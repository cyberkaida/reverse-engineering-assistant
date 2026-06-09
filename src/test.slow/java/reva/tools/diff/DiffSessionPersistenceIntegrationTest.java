package reva.tools.diff;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.List;

import org.junit.After;
import org.junit.Test;

import ghidra.feature.vt.api.db.VTSessionContentHandler;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

import reva.RevaIntegrationTestBase;
import reva.util.VersionTrackingUtil;

/**
 * Integration tests for DomainFile-backed persistent diff sessions.
 *
 * NOTE: For the reopen-from-disk tests, programs must be explicitly persisted to the active
 * project before creating the diff session, so that VTSessionDB can store and retrieve the
 * programs' file IDs. ProgramBuilder programs are in-memory (no real file ID) and VTSessionDB
 * cannot reopen them from disk. We persist them via root.createFile() before diffing.
 */
public class DiffSessionPersistenceIntegrationTest extends RevaIntegrationTestBase {

    @After
    public void tearDownDiffSessions() {
        DiffSessionManager.clearAll();
    }

    /**
     * Persist source and destination programs into the active project, giving them real file IDs
     * that VTSessionDB can store and retrieve. Returns the persisted DomainFile for each.
     * Caller is responsible for releasing the programs.
     */
    private Program[] buildAndPersistPair() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);

        DomainFolder root = AppInfo.getActiveProject().getProjectData().getRootFolder();
        // Save each program to the project root to assign a real file ID.
        // createFile may throw DuplicateFileException if a prior test left a file —
        // clearAll() should delete DiffSession files but not program files. Use unique
        // names (ProgramBuilder already appends a sequence number) to avoid conflicts.
        root.createFile(src.getName(), src, TaskMonitor.DUMMY);
        root.createFile(dst.getName(), dst, TaskMonitor.DUMMY);

        return new Program[]{src, dst};
    }

    /**
     * createStaged with an empty correlator list should create a VTSessionDB, persist it as a
     * DomainFile under the ReVaDiffSessions folder, and store the DomainFile reference in the
     * returned DiffSession. The persisted file's content type must be "VersionTracking" and the
     * session must record the correlators that ran.
     */
    @Test
    public void testCreatePersistsDomainFile() throws Exception {
        Program[] pair = buildAndPersistPair();
        Program src = pair[0];
        Program dst = pair[1];
        try {
            DiffSession ds = DiffSessionManager.createStaged(src, dst,
                VersionTrackingUtil.defaultCorrelatorSequence(), null, null, false,
                TaskMonitor.DUMMY);

            // Session must have a domainFile reference.
            assertNotNull("domainFile must be set after createStaged", ds.domainFile);

            // The ReVaDiffSessions folder must exist under the active project root.
            DomainFolder folder = AppInfo.getActiveProject().getProjectData()
                .getRootFolder().getFolder(DiffSessionManager.FOLDER);
            assertNotNull("ReVaDiffSessions folder must exist", folder);

            // The folder must contain a file with VersionTracking content type.
            boolean found = false;
            for (DomainFile f : folder.getFiles()) {
                if (VTSessionContentHandler.CONTENT_TYPE.equals(f.getContentType())) {
                    found = true;
                    break;
                }
            }
            assertTrue("At least one VersionTracking file must exist in " + DiffSessionManager.FOLDER,
                found);

            // The session's domainFile must have VersionTracking content type.
            assertEquals("domainFile content type must be VersionTracking",
                VTSessionContentHandler.CONTENT_TYPE, ds.domainFile.getContentType());

            // The session must have run correlators.
            assertFalse("correlatorsRun must not be empty", ds.correlatorsRun.isEmpty());
        } finally {
            src.release(this);
            dst.release(this);
        }
    }

    /**
     * After evicting the in-memory cache, get() must reopen the session from the persisted
     * DomainFile. The reopened session must contain the same number of function matches as the
     * original, proving the correlation data survived the round-trip to disk.
     */
    @Test
    public void testReopenAfterCacheEvict() throws Exception {
        Program[] pair = buildAndPersistPair();
        Program src = pair[0];
        Program dst = pair[1];
        String srcPath;
        String dstPath;
        int expectedMatchCount;
        try {
            DiffSession ds = DiffSessionManager.createStaged(src, dst,
                VersionTrackingUtil.defaultCorrelatorSequence(), null, null, false,
                TaskMonitor.DUMMY);
            srcPath = ds.sourcePath;
            dstPath = ds.destinationPath;
            expectedMatchCount = VersionTrackingUtil.collectFunctionMatches(ds.vtSession).size();
            assertTrue("Expected at least one function match", expectedMatchCount > 0);
        } finally {
            // Release the programs; VTSessionDB holds its own consumer reference on the persisted
            // programs, so they survive being released by us here.
            src.release(this);
            dst.release(this);
        }

        // Evict the cache so the next get() must reopen from disk.
        DiffSessionManager.evictCacheForTest();

        // Reopen from the persisted DomainFile.
        DiffSession reopened = DiffSessionManager.get(srcPath, dstPath);
        assertNotNull("Reopened session must be non-null", reopened);
        assertEquals("Match count must survive round-trip to disk",
            expectedMatchCount,
            VersionTrackingUtil.collectFunctionMatches(reopened.vtSession).size());
    }

    /**
     * delete(srcPath, dstPath) must release the session and remove the DomainFile from the
     * project, returning true. After deletion the file must no longer exist.
     */
    @Test
    public void testDeleteRemovesFile() throws Exception {
        Program[] pair = buildAndPersistPair();
        Program src = pair[0];
        Program dst = pair[1];
        try {
            DiffSession ds = DiffSessionManager.createStaged(src, dst,
                VersionTrackingUtil.defaultCorrelatorSequence(), null, null, false,
                TaskMonitor.DUMMY);
            assertNotNull("domainFile must be set", ds.domainFile);
            String fileName = ds.domainFile.getName();

            boolean deleted = DiffSessionManager.delete(ds.sourcePath, ds.destinationPath);
            assertTrue("delete must return true", deleted);

            // The file must no longer exist in the folder.
            DomainFolder folder = AppInfo.getActiveProject().getProjectData()
                .getRootFolder().getFolder(DiffSessionManager.FOLDER);
            if (folder != null) {
                DomainFile after = folder.getFile(fileName);
                assertNull("DomainFile must be removed after delete", after);
            }
            // If the folder itself was removed that is also fine — the session is gone.
        } finally {
            src.release(this);
            dst.release(this);
        }
    }

    /**
     * After creating a session, list() must return at least one session whose source and
     * destination paths match the programs we used to create the session.
     */
    @Test
    public void testListIncludesPersistedSession() throws Exception {
        Program[] pair = buildAndPersistPair();
        Program src = pair[0];
        Program dst = pair[1];
        try {
            DiffSession ds = DiffSessionManager.createStaged(src, dst,
                VersionTrackingUtil.defaultCorrelatorSequence(), null, null, false,
                TaskMonitor.DUMMY);
            String srcPath = ds.sourcePath;
            String dstPath = ds.destinationPath;

            List<DiffSessionManager.SessionSummary> sessions = DiffSessionManager.list();
            boolean found = false;
            for (DiffSessionManager.SessionSummary s : sessions) {
                if (srcPath.equals(s.sourcePath()) && dstPath.equals(s.destinationPath())) {
                    found = true;
                    break;
                }
            }
            assertTrue("list() must include the newly-created session", found);
        } finally {
            src.release(this);
            dst.release(this);
        }
    }

    /**
     * Regression: program-close must NOT auto-delete a persisted diff session.
     *
     * <p>Sessions are durable until explicitly removed via {@link DiffSessionManager#delete}.
     * Closing a program (simulated here via {@code serverManager.programClosed}) only cancels
     * in-flight diff jobs; it must never evict or delete the persisted DomainFile. This test
     * proves that invariant: after creating a session and then simulating program-close on both
     * the source and destination programs (without calling delete), the session is still
     * retrievable from disk and its DomainFile still exists.
     */
    @Test
    public void testSurvivesProgramCloseNoAutoDelete() throws Exception {
        Program[] pair = buildAndPersistPair();
        Program src = pair[0];
        Program dst = pair[1];
        try {
            DiffSession ds = DiffSessionManager.createStaged(src, dst,
                VersionTrackingUtil.defaultCorrelatorSequence(), null, null, false,
                TaskMonitor.DUMMY);
            String srcPath = ds.sourcePath;
            String dstPath = ds.destinationPath;
            assertNotNull("domainFile must be set after createStaged", ds.domainFile);
            String fileName = ds.domainFile.getName();

            // Simulate program close for both programs — must NOT delete the session.
            if (serverManager != null) {
                serverManager.programClosed(src, tool);
                serverManager.programClosed(dst, tool);
            }

            // The DomainFile must still exist in the ReVaDiffSessions folder.
            DomainFolder folder = AppInfo.getActiveProject().getProjectData()
                .getRootFolder().getFolder(DiffSessionManager.FOLDER);
            assertNotNull("ReVaDiffSessions folder must still exist after program close", folder);
            DomainFile fileAfterClose = folder.getFile(fileName);
            assertNotNull("DomainFile must NOT be deleted by program-close", fileAfterClose);
            assertEquals("DomainFile content type must still be VersionTracking",
                ghidra.feature.vt.api.db.VTSessionContentHandler.CONTENT_TYPE,
                fileAfterClose.getContentType());

            // Evict the in-memory cache so get() must reopen from the persisted DomainFile on disk,
            // proving true on-disk survival (not just cache survival) after program-close.
            DiffSessionManager.evictCacheForTest();
            DiffSession afterClose = DiffSessionManager.get(srcPath, dstPath);
            assertNotNull("Session must still be reopenable from disk after program-close (not auto-deleted)",
                afterClose);
        } finally {
            src.release(this);
            dst.release(this);
        }
    }

    /**
     * Regression for the mid-loop leak: if createStaged throws partway through the staged loop
     * (e.g. a diff-cancel raising CancelledException), the open VTSessionDB must be released so the
     * pair self-heals. Before the fix, the orphaned open file made the next createStaged throw
     * FileInUseException, permanently wedging the pair.
     *
     * <p>The monitor here lets {@code folder().createFile(...)} complete (so the throw lands inside
     * the staged loop, exercising the new loop catch — not the pre-existing createFile catch), then
     * cancels itself the moment the loop's first {@code checkCancelled()} runs. It does this by
     * arming on the first non-empty {@code setMessage(...)}, which the VT correlator emits once the
     * loop begins, and throwing on the subsequent {@code checkCancelled()}. We then assert a SECOND
     * createStaged (fresh monitor) succeeds and persists — proving the pair is not wedged.
     */
    @Test
    public void testCancelMidCreateDoesNotWedgePair() throws Exception {
        Program[] pair = buildAndPersistPair();
        Program src = pair[0];
        Program dst = pair[1];
        try {
            // Arms after createFile completes (on the first loop-phase setMessage), then trips the
            // next checkCancelled() — so the throw unwinds through the staged loop, not createFile.
            TaskMonitor loopCanceller = new TaskMonitorAdapter(true) {
                private volatile boolean armed = false;
                @Override
                public void setMessage(String message) {
                    if (message != null && !message.isEmpty()) armed = true;
                }
                @Override
                public void checkCancelled() throws CancelledException {
                    if (armed) throw new CancelledException();
                }
                @Override
                public boolean isCancelled() {
                    return armed;
                }
            };

            boolean threw = false;
            try {
                DiffSessionManager.createStaged(src, dst,
                    VersionTrackingUtil.defaultCorrelatorSequence(), null, null, false, loopCanceller);
            } catch (CancelledException | IOException e) {
                // Either path proves the no-wedge contract: CancelledException from the loop catch,
                // or IOException("Could not persist...") if the cancel landed during createFile.
                threw = true;
            }
            assertTrue("createStaged must throw when the monitor cancels mid-run", threw);

            // The pair must NOT be wedged: a second createStaged with a fresh monitor must succeed
            // (no FileInUseException from an orphaned open handle) and persist a real session.
            DiffSession ds = DiffSessionManager.createStaged(src, dst,
                VersionTrackingUtil.defaultCorrelatorSequence(), null, null, false,
                TaskMonitor.DUMMY);
            assertNotNull("retry after cancel must produce a session", ds);
            assertNotNull("retry session must be persisted", ds.domainFile);
            assertEquals("retry session file must be VersionTracking",
                VTSessionContentHandler.CONTENT_TYPE, ds.domainFile.getContentType());
            assertFalse("retry session must have run correlators", ds.correlatorsRun.isEmpty());
        } finally {
            src.release(this);
            dst.release(this);
        }
    }
}
