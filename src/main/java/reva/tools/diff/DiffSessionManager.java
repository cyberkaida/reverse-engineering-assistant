package reva.tools.diff;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.feature.vt.api.db.VTSessionContentHandler;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.task.TaskMonitor;

import reva.util.VersionTrackingUtil;

/**
 * DomainFile-backed store of {@link DiffSession}s, keyed by (sourcePath, destinationPath). Each
 * session is a persisted {@code VTSessionDB} DomainFile under {@link #FOLDER}; an in-memory map
 * caches the open session over the durable file. Correlation is staged: each correlator runs only
 * over the still-unmatched residual (within an optional agent scope) and the file is saved after
 * each stage.
 * <p>
 * Sessions are reused if the same correlator selection is requested again; a different correlator
 * selection (or {@code force=true}) deletes the existing session and re-correlates. Explicit
 * removal via {@link #delete} is the only other removal path.
 */
public final class DiffSessionManager {
    public static final String FOLDER = "ReVaDiffSessions";
    private static final Object CONSUMER = DiffSessionManager.class;
    private static final Map<String, DiffSession> CACHE = new ConcurrentHashMap<>();

    private DiffSessionManager() {}

    private static String key(String s, String d) { return s + "\0" + d; }

    private static String fileName(String srcPath, String dstPath) {
        String s = srcPath.substring(srcPath.lastIndexOf('/') + 1);
        String d = dstPath.substring(dstPath.lastIndexOf('/') + 1);
        int h = key(srcPath, dstPath).hashCode();
        return s + "__" + d + "__" + Integer.toHexString(h);
    }

    private static DomainFolder folder() throws IOException {
        Project project = AppInfo.getActiveProject();
        if (project == null) throw new IOException("No active Ghidra project for diff sessions.");
        DomainFolder root = project.getProjectData().getRootFolder();
        DomainFolder f = root.getFolder(FOLDER);
        if (f == null) {
            try {
                f = root.createFolder(FOLDER);
            } catch (Exception e) {
                throw new IOException("Could not create diff-session folder: " + e.getMessage(), e);
            }
        }
        return f;
    }

    /** Cached open session, or reopen from its DomainFile (auto-opens the programs), or null. */
    public static synchronized DiffSession get(String srcPath, String dstPath) {
        DiffSession cached = CACHE.get(key(srcPath, dstPath));
        if (cached != null) return cached;
        try {
            DomainFile file = folder().getFile(fileName(srcPath, dstPath));
            if (file == null || !VTSessionContentHandler.CONTENT_TYPE.equals(file.getContentType())) {
                return null;
            }
            VTSessionDB vt = (VTSessionDB) file.getDomainObject(CONSUMER, true, false, TaskMonitor.DUMMY);
            boolean handed = false;
            try {
                Program src = vt.getSourceProgram();
                Program dst = vt.getDestinationProgram();
                // fileName() folds the pair into a 32-bit hash, so a collision could map a different
                // pair onto this file. Verify the reopened session's REAL programs match the request;
                // on mismatch return a clean miss (finally releases) rather than serving wrong programs.
                if (!srcPath.equals(src.getDomainFile().getPathname())
                        || !dstPath.equals(dst.getDomainFile().getPathname())) {
                    return null;
                }
                DiffSession ds = new DiffSession(src, dst, srcPath, dstPath, vt, correlatorsRun(vt), file);
                CACHE.put(key(srcPath, dstPath), ds);
                handed = true;
                return ds;
            } finally {
                if (!handed) {
                    try { vt.release(CONSUMER); } catch (Exception ignore) { }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Could not reopen diff session for " + srcPath + " -> "
                + dstPath + ": " + e.getMessage(), e);
        }
    }

    /** Reconstruct the ordered correlator names from the session's match sets,
     *  excluding the VTSessionDB-internal "Manual Match" and "Implied Match" sets. */
    private static List<String> correlatorsRun(VTSession vt) {
        List<String> ran = new ArrayList<>();
        for (var ms : vt.getMatchSets()) {
            String n = ms.getProgramCorrelatorInfo().getName();
            // Skip the internal match sets that VTSessionDB always creates.
            if ("Manual Match".equals(n) || "Implied Match".equals(n)) continue;
            if (!ran.contains(n)) ran.add(n);
        }
        return ran;
    }

    /**
     * Create (or idempotently reuse) the persisted session and run the scoped-staged correlator
     * sequence, saving after each stage. {@code force} re-creates from scratch. Optional initial
     * scopes restrict the FIRST stage; later stages scope to the residual within that.
     * <p>
     * If an existing session has a different correlator selection than {@code factories}, the
     * session is deleted and re-correlated — this preserves the agent's ability to change
     * correlator sets and see fresh results (same behaviour as the old {@code getOrCreate}).
     */
    public static synchronized DiffSession createStaged(Program source, Program dest,
            List<VTProgramCorrelatorFactory> factories, AddressSetView initialSrc,
            AddressSetView initialDst, boolean force, TaskMonitor monitor)
            throws IOException, CancelledException {
        String srcPath = source.getDomainFile().getPathname();
        String dstPath = dest.getDomainFile().getPathname();
        if (force) delete(srcPath, dstPath);
        DiffSession existing = get(srcPath, dstPath);
        // Reuse the existing session only when the correlator selection is unchanged.
        // A different selection means the agent wants a fresh diff — delete and re-correlate.
        if (existing != null && !force) {
            List<String> requestedNames = new ArrayList<>();
            for (VTProgramCorrelatorFactory f : factories) requestedNames.add(f.getName());
            if (existing.correlatorsRun.equals(requestedNames)) return existing;
            delete(srcPath, dstPath); // different selection: release old session
        }

        VTSession vt = new VTSessionDB("ReVa diff: " + source.getName() + " -> " + dest.getName(),
            source, dest, CONSUMER);
        DomainFile file;
        try {
            file = folder().createFile(fileName(srcPath, dstPath), (VTSessionDB) vt, monitor);
        } catch (DuplicateFileException dup) {
            ((VTSessionDB) vt).release(CONSUMER);
            throw new IOException("Diff session filename collision for " + srcPath + " -> " + dstPath
                + " (another session's file maps to the same name). Delete the conflicting session with"
                + " diff-delete-session, then retry.", dup);
        } catch (Exception e) {
            ((VTSessionDB) vt).release(CONSUMER);
            throw new IOException("Could not persist diff session: " + e.getMessage(), e);
        }
        try {
            AddressSetView fullSrc = source.getMemory().getLoadedAndInitializedAddressSet();
            AddressSetView fullDst = dest.getMemory().getLoadedAndInitializedAddressSet();
            AddressSetView scopeSrc = (initialSrc != null) ? initialSrc : fullSrc;
            AddressSetView scopeDst = (initialDst != null) ? initialDst : fullDst;

            for (VTProgramCorrelatorFactory f : factories) {
                monitor.checkCancelled();
                AddressSetView srcSet = residual(scopeSrc, VersionTrackingUtil.matchedSourceEntries(vt), source);
                AddressSetView dstSet = residual(scopeDst, VersionTrackingUtil.matchedDestEntries(vt), dest);
                VersionTrackingUtil.runOneCorrelator(vt, source, srcSet, dest, dstSet, f, monitor);
                ((VTSessionDB) vt).save("ReVa diff stage: " + f.getName(), monitor);
            }

            DiffSession ds = new DiffSession(source, dest, srcPath, dstPath, vt, correlatorsRun(vt), file);
            CACHE.put(key(srcPath, dstPath), ds);
            return ds;
        } catch (RuntimeException | CancelledException | IOException e) {
            // A throw mid-loop (cancel, correlate, or save) must release the open handle so the
            // (partially-saved) file is CLOSED and the pair self-heals: the next get() reopens it
            // cleanly and a delete/force then works. Leaving the handle open would orphan the file
            // (never cached, never released) and wedge the pair with FileInUseException. The
            // persisted stages survive on disk.
            ((VTSessionDB) vt).release(CONSUMER);
            throw e;
        }
    }

    /** Run ONE more correlator over the given scope (default residual) on an existing session; save. */
    public static synchronized DiffSession addCorrelator(DiffSession ds, VTProgramCorrelatorFactory factory,
            AddressSetView scopeSrc, AddressSetView scopeDst, TaskMonitor monitor)
            throws IOException, CancelledException {
        AddressSetView srcSet = (scopeSrc != null) ? scopeSrc
            : residual(ds.sourceProgram.getMemory().getLoadedAndInitializedAddressSet(),
                VersionTrackingUtil.matchedSourceEntries(ds.vtSession), ds.sourceProgram);
        AddressSetView dstSet = (scopeDst != null) ? scopeDst
            : residual(ds.destinationProgram.getMemory().getLoadedAndInitializedAddressSet(),
                VersionTrackingUtil.matchedDestEntries(ds.vtSession), ds.destinationProgram);
        VersionTrackingUtil.runOneCorrelator(ds.vtSession, ds.sourceProgram, srcSet,
            ds.destinationProgram, dstSet, factory, monitor);
        ((VTSessionDB) ds.vtSession).save("ReVa diff add-correlator: " + factory.getName(), monitor);
        DiffSession refreshed = new DiffSession(ds.sourceProgram, ds.destinationProgram,
            ds.sourcePath, ds.destinationPath, ds.vtSession, correlatorsRun(ds.vtSession), ds.domainFile);
        CACHE.put(key(ds.sourcePath, ds.destinationPath), refreshed);
        return refreshed;
    }

    /** Intersection of {@code scope} with the unmatched function bodies in {@code program}. */
    private static AddressSetView residual(AddressSetView scope, Set<Address> matchedEntries, Program program) {
        AddressSet unmatched = VersionTrackingUtil.unmatchedFunctionBodies(program, matchedEntries);
        return unmatched.intersect(scope);
    }

    /** Lightweight summary of a persisted diff session — does NOT pin the VT session or programs. */
    public record SessionSummary(String sourcePath, String destinationPath, List<String> correlatorsRun) {}

    /**
     * Summaries for every cached AND on-disk persisted session. Cached sessions are summarized
     * from the live handle; uncached files are opened only long enough to read their fields, then
     * released — listing never pins (and never leaks) a VT session or its programs.
     */
    public static synchronized List<SessionSummary> list() {
        List<SessionSummary> out = new ArrayList<>();
        Set<String> seenFiles = new HashSet<>();
        for (DiffSession ds : CACHE.values()) {
            out.add(new SessionSummary(ds.sourcePath, ds.destinationPath, ds.correlatorsRun));
            if (ds.domainFile != null) seenFiles.add(ds.domainFile.getName());
        }
        try {
            for (DomainFile f : folder().getFiles()) {
                if (!VTSessionContentHandler.CONTENT_TYPE.equals(f.getContentType())) continue;
                if (seenFiles.contains(f.getName())) continue;
                VTSessionDB vt = null;
                try {
                    vt = (VTSessionDB) f.getDomainObject(CONSUMER, true, false, TaskMonitor.DUMMY);
                    Program src = vt.getSourceProgram();
                    Program dst = vt.getDestinationProgram();
                    out.add(new SessionSummary(src.getDomainFile().getPathname(),
                        dst.getDomainFile().getPathname(), correlatorsRun(vt)));
                } finally {
                    // Never cache/pin a listed-only session: release the handle (which also
                    // releases its source/dest programs) so listing N files leaks nothing.
                    if (vt != null) vt.release(CONSUMER);
                }
            }
        } catch (Exception e) {
            // Best-effort listing; return what we have.
        }
        return out;
    }

    /** Explicit removal: release + delete the DomainFile. The ONLY removal path. */
    public static synchronized boolean delete(String srcPath, String dstPath) {
        DiffSession ds = CACHE.remove(key(srcPath, dstPath));
        try {
            DomainFile file = (ds != null && ds.domainFile != null) ? ds.domainFile
                : folder().getFile(fileName(srcPath, dstPath));
            if (ds != null) ((VTSessionDB) ds.vtSession).release(CONSUMER);
            if (file != null) { file.delete(); return true; }
        } catch (Exception e) {
            throw new RuntimeException("Could not delete diff session: " + e.getMessage(), e);
        }
        return false;
    }

    /** Test/teardown hook: release all cached sessions AND delete their files. */
    public static synchronized void clearAll() {
        for (String k : new ArrayList<>(CACHE.keySet())) {
            DiffSession ds = CACHE.remove(k);
            if (ds == null) continue;
            try {
                ((VTSessionDB) ds.vtSession).release(CONSUMER);
                if (ds.domainFile != null) ds.domainFile.delete();
            } catch (Exception ignore) { }
        }
    }

    /** Test-only: drop the in-memory cache WITHOUT deleting files, so get() reopens from disk. */
    static synchronized void evictCacheForTest() {
        for (DiffSession ds : new ArrayList<>(CACHE.values())) {
            try { ((VTSessionDB) ds.vtSession).release(CONSUMER); } catch (Exception ignore) { }
        }
        CACHE.clear();
    }
}
