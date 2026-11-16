/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.tools.project;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.base.project.GhidraProject;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.local.IndexedV1LocalFileSystem;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;
import reva.RevaIntegrationTestBase;
import reva.plugin.RevaProgramManager;
import reva.util.ProgramPersistenceUtil;
import utilities.util.FileUtilities;

/**
 * Integration tests for version control operations in ProjectToolProvider.
 * Tests fix for issue #154 (save before checkin) and save fallback for unversioned files.
 */
public class ProjectToolProviderVersionControlIntegrationTest extends RevaIntegrationTestBase {

    private ObjectMapper objectMapper;

    @Before
    public void setUp() {
        objectMapper = new ObjectMapper();
    }

    /**
     * Test checkin-program works correctly.
     * This test verifies the fix for issue #154 - the tool should handle saves properly.
     */
    @Test
    public void testCheckinProgram() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            Program testProgram = null;
            try {
                client.initialize();

                // Create a test program
                testProgram = createDefaultProgram("test-checkin", "x86:LE:64:default", this);
                String programPath = testProgram.getDomainFile().getPathname();

                // Register the program so it can be found by tools
                RevaProgramManager.registerProgram(testProgram);
                if (serverManager != null) {
                    serverManager.programOpened(testProgram, tool);
                }

                // Make changes to the program (add a label)
                int transactionID = testProgram.startTransaction("Add test label");
                try {
                    SymbolTable symbolTable = testProgram.getSymbolTable();
                    symbolTable.createLabel(testProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000),
                        "test_label", SourceType.USER_DEFINED);
                    testProgram.endTransaction(transactionID, true);
                } catch (Exception e) {
                    testProgram.endTransaction(transactionID, false);
                    throw e;
                }

                // Try to checkin - this should save first, then add to version control or save
                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "checkin-program",
                    Map.of(
                        "programPath", programPath,
                        "message", "Test commit"
                    )
                ));

                // Verify the response
                assertNotNull("Result should not be null", result);
                if (result.isError()) {
                    // Print error for debugging
                    String errorMsg = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                    System.err.println("Tool error: " + errorMsg);
                }
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertTrue("Checkin should be successful", Boolean.TRUE.equals(response.get("success")));

                // Should either be added_to_version_control (new file) or saved (if not versioned)
                String action = (String) response.get("action");
                assertTrue("Action should be added_to_version_control or saved",
                    "added_to_version_control".equals(action) || "saved".equals(action));

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            } finally {
                // Clean up the test program
                if (testProgram != null) {
                    RevaProgramManager.unregisterProgram(testProgram);
                    if (serverManager != null) {
                        serverManager.programClosed(testProgram, tool);
                    }
                    testProgram.release(this);
                }
            }
        });
    }

    /**
     * Test checkin-program returns appropriate action based on version control support.
     * This test verifies that the tool handles both versioned and unversioned files correctly.
     */
    @Test
    public void testCheckinHandlesVersionControlStatus() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            Program testProgram = null;
            try {
                client.initialize();

                // Create a test program
                testProgram = createDefaultProgram("test-unversioned", "x86:LE:64:default", this);
                String programPath = testProgram.getDomainFile().getPathname();
                DomainFile domainFile = testProgram.getDomainFile();

                // Register the program so it can be found by tools
                RevaProgramManager.registerProgram(testProgram);
                if (serverManager != null) {
                    serverManager.programOpened(testProgram, tool);
                }

                // Make changes to the program
                int transactionID = testProgram.startTransaction("Add test label");
                try {
                    SymbolTable symbolTable = testProgram.getSymbolTable();
                    symbolTable.createLabel(testProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000),
                        "test_label_unversioned", SourceType.USER_DEFINED);
                    testProgram.endTransaction(transactionID, true);
                } catch (Exception e) {
                    testProgram.endTransaction(transactionID, false);
                    throw e;
                }

                // Check if file can be added to version control
                boolean canAddToVCS = domainFile.canAddToRepository();

                // Try to checkin - should work regardless of version control support
                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "checkin-program",
                    Map.of(
                        "programPath", programPath,
                        "message", "Test commit"
                    )
                ));

                // Verify the response
                assertNotNull("Result should not be null", result);
                if (result.isError()) {
                    // Print error for debugging
                    String errorMsg = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                    System.err.println("Tool error: " + errorMsg);
                }
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertTrue("Operation should be successful", Boolean.TRUE.equals(response.get("success")));

                // Action should depend on version control support
                String action = (String) response.get("action");
                assertNotNull("Action should be present", action);

                if (canAddToVCS) {
                    assertEquals("Action should be added_to_version_control when supported", "added_to_version_control", action);
                } else {
                    assertEquals("Action should be saved when version control not supported", "saved", action);
                    assertFalse("Response should indicate file is not versioned", Boolean.TRUE.equals(response.get("isVersioned")));
                }

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            } finally {
                // Clean up the test program
                if (testProgram != null) {
                    RevaProgramManager.unregisterProgram(testProgram);
                    if (serverManager != null) {
                        serverManager.programClosed(testProgram, tool);
                    }
                    testProgram.release(this);
                }
            }
        });
    }

    /**
     * Test that checkin-program accepts commit message parameter.
     */
    @Test
    public void testCheckinWithCommitMessage() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            Program testProgram = null;
            try {
                client.initialize();

                // Create a test program
                testProgram = createDefaultProgram("test-message", "x86:LE:64:default", this);
                String programPath = testProgram.getDomainFile().getPathname();

                // Register the program so it can be found by tools
                RevaProgramManager.registerProgram(testProgram);
                if (serverManager != null) {
                    serverManager.programOpened(testProgram, tool);
                }

                // Make changes to the program
                int transactionID = testProgram.startTransaction("Add test label");
                try {
                    SymbolTable symbolTable = testProgram.getSymbolTable();
                    symbolTable.createLabel(testProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x3000),
                        "test_label_message", SourceType.USER_DEFINED);
                    testProgram.endTransaction(transactionID, true);
                } catch (Exception e) {
                    testProgram.endTransaction(transactionID, false);
                    throw e;
                }

                String commitMessage = "Test commit message for version control";

                // Try to checkin with specific message
                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "checkin-program",
                    Map.of(
                        "programPath", programPath,
                        "message", commitMessage
                    )
                ));

                // Verify the response
                assertNotNull("Result should not be null", result);
                if (result.isError()) {
                    // Print error for debugging
                    String errorMsg = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                    System.err.println("Tool error: " + errorMsg);
                }
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertTrue("Operation should be successful", Boolean.TRUE.equals(response.get("success")));
                assertEquals("Response should include the commit message", commitMessage, response.get("message"));

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            } finally {
                // Clean up the test program
                if (testProgram != null) {
                    RevaProgramManager.unregisterProgram(testProgram);
                    if (serverManager != null) {
                        serverManager.programClosed(testProgram, tool);
                    }
                    testProgram.release(this);
                }
            }
        });
    }

    /**
     * A blocked checkin must not release the cached program. Releasing the last
     * consumer closes the in-memory program, so committed-but-unsaved bookmarks
     * would be discarded and a later retry would save the stale on-disk state.
     * <p>
     * The program is opened by normal tool lookup (not {@code registeredPrograms}),
     * so RevaProgramManager's cache is its only consumer. This test is headed,
     * though, and a headed Ghidra tool may hold another consumer: the headless e2e
     * test supplies the decisive data-loss proof.
     */
    @Test
    public void testBlockedCheckinRetainsCachedProgram() throws Exception {
        // Save a real program to the project and release it, as import-file leaves it.
        // The tool lookup below then opens and caches it, making the cache its only
        // consumer; registering it instead would bypass the cache and hide the defect.
        DomainFolder root = env.getProject().getProjectData().getRootFolder();
        String fileName = "blocked-checkin-" + System.nanoTime();
        Program source = createDefaultProgram(fileName + "-source", "x86:LE:64:default", this);
        DomainFile file;
        try {
            int memoryTx = source.startTransaction("add memory");
            try {
                source.getMemory().createInitializedBlock("test",
                    source.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000),
                    0x1000, (byte) 0, TaskMonitor.DUMMY, false);
            } finally {
                source.endTransaction(memoryTx, true);
            }
            file = root.createFile(fileName, source, TaskMonitor.DUMMY);
        } finally {
            source.release(this);
        }
        String programPath = file.getPathname();

        try {
            withMcpClient(createMcpTransport(), (McpClientFunction<Void>) client -> {
                client.initialize();

                // Normal tool lookup opens the project file and caches it.
                McpSchema.CallToolResult lookup = client.callTool(new McpSchema.CallToolRequest(
                    "get-function-count", Map.of("programPath", programPath)));
                assertFalse("Lookup should succeed: " + text(lookup), lookup.isError());

                Program p = RevaProgramManager.getProgramByPath(programPath);
                assertNotNull("Lookup should have opened the program", p);
                assertTrue("Normal lookup should cache the program",
                    RevaProgramManager.isProgramCached(p));

                // Three bookmarks, each committed in its own transaction.
                Address address = p.getMinAddress();
                for (int i = 1; i <= 3; i++) {
                    int tx = p.startTransaction("bookmark " + i);
                    try {
                        p.getBookmarkManager().setBookmark(address, "Note", "note-" + i,
                            "bookmark " + i);
                    } finally {
                        p.endTransaction(tx, true);
                    }
                }

                // A concurrent writer blocks the save. The checkin must fail without
                // releasing the cached program, or the unsaved bookmarks would be lost.
                int held = p.startTransaction("concurrent writer");
                try {
                    McpSchema.CallToolResult blocked = client.callTool(new McpSchema.CallToolRequest(
                        "checkin-program", Map.of("programPath", programPath, "message", "blocked")));
                    assertTrue("Blocked checkin should report an error: " + text(blocked),
                        blocked.isError());
                    assertTrue("Error should name the open transaction: " + text(blocked),
                        text(blocked).contains("concurrent writer"));
                    assertTrue("an unsaved checkin must retain the cached program",
                        RevaProgramManager.isProgramCached(p));
                } finally {
                    if (!p.isClosed()) {
                        p.endTransaction(held, true);
                    }
                }

                // Retry after the blocker ends: the save must include every bookmark.
                McpSchema.CallToolResult retried = client.callTool(new McpSchema.CallToolRequest(
                    "checkin-program", Map.of("programPath", programPath, "message", "after blocker")));
                assertFalse("Retry should succeed: " + text(retried), retried.isError());
                assertTrue("Retry should report success: " + text(retried),
                    text(retried).contains("\"success\":true"));

                // Read the saved database back from disk, not the released live program.
                DomainObject saved = null;
                try {
                    saved = file.getReadOnlyDomainObject(this, DomainFile.DEFAULT_VERSION,
                        TaskMonitor.DUMMY);
                    assertTrue("Saved domain object should be a program", saved instanceof Program);
                    Program savedProgram = (Program) saved;
                    BookmarkManager savedBookmarks = savedProgram.getBookmarkManager();
                    Address savedAddress = savedProgram.getMinAddress();
                    for (int i = 1; i <= 3; i++) {
                        assertNotNull("bookmark note-" + i + " should be in the saved database",
                            savedBookmarks.getBookmark(savedAddress, "Note", "note-" + i));
                    }
                } finally {
                    if (saved != null) {
                        saved.release(this);
                    }
                }
                return null;
            });
        } finally {
            // Release any cache entry the test left behind, then delete the file.
            for (Program known : RevaProgramManager.getAllKnownPrograms()) {
                if (programPath.equals(RevaProgramManager.getCanonicalProgramPath(known))
                        && RevaProgramManager.isProgramCached(known)) {
                    RevaProgramManager.releaseProgramFromCache(known);
                }
            }
            try {
                file.delete();
            } catch (Exception ignore) {
                // best-effort cleanup of the temporary project file
            }
        }
    }

    /**
     * A successful checkin must retain the cached program. Releasing the cache after the
     * save/checkin closes the last headless consumer, so a later mutation committed on the
     * same program would be lost when that consumer goes away.
     * <p>
     * This test uses a real repository-backed project, because the shared TestEnv project is
     * private and cannot exercise a {@code checked_in} action: a private project only reaches
     * the local-save fallback.
     */
    @Test
    public void testSuccessfulCheckinRetainsProgramForSubsequentWrites() throws Exception {
        // GhidraProject.createProject makes the new project the AppInfo active project, so
        // capture the real one before constructing the fixture and restore it even when
        // construction itself fails.
        Project originalProject = AppInfo.getActiveProject();
        TestRepositoryProject repo = null;
        String programPath = null;
        try {
            repo = new TestRepositoryProject(originalProject);
            AppInfo.setActiveProject(repo.getProject());

            DomainFolder root = repo.getProjectData().getRootFolder();
            String fileName = "checkin-program-" + System.nanoTime();
            Program source = createDefaultProgram(fileName + "-source", "x86:LE:64:default", this);
            DomainFile file;
            try {
                int memoryTx = source.startTransaction("add memory");
                try {
                    source.getMemory().createInitializedBlock("test",
                        source.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000),
                        0x1000, (byte) 0, TaskMonitor.DUMMY, false);
                } finally {
                    source.endTransaction(memoryTx, true);
                }
                file = root.createFile(fileName, source, TaskMonitor.DUMMY);
            } finally {
                source.release(this);
            }
            programPath = file.getPathname();
            final String path = programPath;

            assertTrue("fixture must be repository-backed", file.canAddToRepository());
            file.addToVersionControl("initial", true, TaskMonitor.DUMMY);
            assertTrue("fixture must start from a real checked-out file",
                file.isVersioned() && file.isCheckedOut());

            withMcpClient(createMcpTransport(), (McpClientFunction<Void>) client -> {
                client.initialize();

                // Normal tool lookup opens the project file and caches it.
                McpSchema.CallToolResult lookup = client.callTool(new McpSchema.CallToolRequest(
                    "get-function-count", Map.of("programPath", path)));
                assertFalse("Lookup should succeed: " + text(lookup), lookup.isError());

                Program p = RevaProgramManager.getProgramByPath(path);
                assertNotNull("Lookup should have opened the program", p);
                assertTrue("Normal lookup should cache the program",
                    RevaProgramManager.isProgramCached(p));

                Address address = p.getMinAddress();
                int firstWrite = p.startTransaction("first bookmark");
                try {
                    p.getBookmarkManager().setBookmark(address, "Note", "first", "before checkin");
                } finally {
                    p.endTransaction(firstWrite, true);
                }
                McpSchema.CallToolResult first = client.callTool(new McpSchema.CallToolRequest(
                    "checkin-program",
                    Map.of("programPath", path, "message", "first", "keepCheckedOut", false)));
                assertFalse(text(first), first.isError());
                assertTrue("fixture must exercise a real checkin, not a local save",
                    text(first).contains("\"action\":\"checked_in\""));
                assertTrue("a successful checkin must retain the cached program",
                    RevaProgramManager.isProgramCached(p));
                assertFalse("the retained program must stay open", p.isClosed());

                int secondWrite = p.startTransaction("second bookmark");
                try {
                    p.getBookmarkManager().setBookmark(address, "Note", "second", "after checkin");
                } finally {
                    p.endTransaction(secondWrite, true);
                }
                McpSchema.CallToolResult second = client.callTool(new McpSchema.CallToolRequest(
                    "checkin-program",
                    Map.of("programPath", path, "message", "second", "keepCheckedOut", false)));
                assertFalse(text(second), second.isError());

                // Read the saved database back, not the retained live program. With the file
                // still checked out, DEFAULT_VERSION is the checked-out database that
                // checkin-program just saved, which is the local persistence record.
                DomainObject saved = file.getReadOnlyDomainObject(this,
                    DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
                try {
                    assertTrue("Saved domain object should be a program", saved instanceof Program);
                    Program savedProgram = (Program) saved;
                    BookmarkManager bookmarks = savedProgram.getBookmarkManager();
                    assertNotNull("the first bookmark should be in the saved database",
                        bookmarks.getBookmark(savedProgram.getMinAddress(), "Note", "first"));
                    assertNotNull("the mutation after checkin must reach the saved database",
                        bookmarks.getBookmark(savedProgram.getMinAddress(), "Note", "second"));
                } finally {
                    saved.release(this);
                }
                return null;
            });
        } finally {
            releaseCachedProgram(programPath);
            AppInfo.setActiveProject(originalProject);
            if (repo != null) {
                repo.dispose();
            }
        }
    }

    /**
     * A failed checkin after a save must retain the cached program so a retry can
     * save the post-save mutation. This forces the exact save→checkin→mutation
     * interleaving: a bookmark is removed in a committed transaction between the
     * save and the checkin step. Without retention, the failed checkin releases the
     * only consumer and the retry reopens the pre-removal state.
     */
    @Test
    public void testPostSaveCheckinFailureRetainsRemoval() throws Exception {
        Project originalProject = AppInfo.getActiveProject();
        TestRepositoryProject repo = null;
        String programPath = null;
        try {
            repo = new TestRepositoryProject(originalProject);
            AppInfo.setActiveProject(repo.getProject());

            DomainFolder root = repo.getProjectData().getRootFolder();
            String fileName = "post-save-checkin-" + System.nanoTime();
            Program source = createDefaultProgram(fileName + "-source", "x86:LE:64:default", this);
            DomainFile file;
            try {
                int memoryTx = source.startTransaction("add memory");
                try {
                    source.getMemory().createInitializedBlock("test",
                        source.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000),
                        0x1000, (byte) 0, TaskMonitor.DUMMY, false);
                } finally {
                    source.endTransaction(memoryTx, true);
                }
                file = root.createFile(fileName, source, TaskMonitor.DUMMY);
            } finally {
                source.release(this);
            }
            programPath = file.getPathname();
            final String path = programPath;

            assertTrue("fixture must be repository-backed", file.canAddToRepository());
            file.addToVersionControl("initial", true, TaskMonitor.DUMMY);
            assertTrue("fixture must start from a real checked-out file",
                file.isVersioned() && file.isCheckedOut());

            withMcpClient(createMcpTransport(), (McpClientFunction<Void>) client -> {
                client.initialize();

                McpSchema.CallToolResult lookup = client.callTool(new McpSchema.CallToolRequest(
                    "get-function-count", Map.of("programPath", path)));
                assertFalse("Lookup should succeed: " + text(lookup), lookup.isError());

                Program p = RevaProgramManager.getProgramByPath(path);
                assertNotNull("Lookup should have opened the program", p);
                assertTrue("Normal lookup should cache the program",
                    RevaProgramManager.isProgramCached(p));

                Address address = p.getMinAddress();
                int tx = p.startTransaction("bookmarks");
                try {
                    p.getBookmarkManager().setBookmark(address, "Note", "race", "race bookmark");
                    p.getBookmarkManager().setBookmark(address, "Note", "keep1", "keep bookmark 1");
                    p.getBookmarkManager().setBookmark(address, "Note", "keep2", "keep bookmark 2");
                } finally {
                    p.endTransaction(tx, true);
                }

                // Force the exact post-save interleaving: remove the race bookmark in a
                // committed transaction immediately after save and before checkin.
                ProgramPersistenceUtil.setPostSaveHookForTesting(program -> {
                    int tx2 = program.startTransaction("post-save removal");
                    try {
                        Bookmark bookmark = program.getBookmarkManager().getBookmark(
                            program.getMinAddress(), "Note", "race");
                        program.getBookmarkManager().removeBookmark(bookmark);
                    } finally {
                        program.endTransaction(tx2, true);
                    }
                });
                try {
                    McpSchema.CallToolResult blocked = client.callTool(new McpSchema.CallToolRequest(
                        "checkin-program", Map.of("programPath", path, "message", "race")));
                    assertTrue("Blocked checkin should report an error: " + text(blocked),
                        blocked.isError());
                    assertTrue("Error should name unsaved changes: " + text(blocked),
                        text(blocked).contains("unsaved changes"));
                    assertTrue("an unsaved checkin must retain the cached program",
                        RevaProgramManager.isProgramCached(p));
                } finally {
                    ProgramPersistenceUtil.setPostSaveHookForTesting(null);
                }

                // Retry after resetting the hook: the save must include the removal.
                McpSchema.CallToolResult retried = client.callTool(new McpSchema.CallToolRequest(
                    "checkin-program", Map.of("programPath", path, "message", "after removal")));
                assertFalse("Retry should succeed: " + text(retried), retried.isError());
                assertTrue("Retry should report success: " + text(retried),
                    text(retried).contains("\"success\":true"));

                // Read the saved database back from disk.
                DomainObject saved = null;
                try {
                    saved = file.getReadOnlyDomainObject(this, DomainFile.DEFAULT_VERSION,
                        TaskMonitor.DUMMY);
                    assertTrue("Saved domain object should be a program", saved instanceof Program);
                    Program savedProgram = (Program) saved;
                    BookmarkManager savedBookmarks = savedProgram.getBookmarkManager();
                    Address savedAddress = savedProgram.getMinAddress();
                    assertNull("removed bookmark should be absent from the saved database",
                        savedBookmarks.getBookmark(savedAddress, "Note", "race"));
                    assertNotNull("bookmark keep1 should survive",
                        savedBookmarks.getBookmark(savedAddress, "Note", "keep1"));
                    assertNotNull("bookmark keep2 should survive",
                        savedBookmarks.getBookmark(savedAddress, "Note", "keep2"));
                } finally {
                    if (saved != null) {
                        saved.release(this);
                    }
                }
                return null;
            });
        } finally {
            releaseCachedProgram(programPath);
            AppInfo.setActiveProject(originalProject);
            if (repo != null) {
                repo.dispose();
            }
        }
    }

    /**
     * A fixture construction failure must not strand the active project on the half-built
     * fixture: {@code GhidraProject.createProject} switches {@link AppInfo} before the
     * repository attach step, and every later test depends on the original project.
     */
    @Test
    public void testFixtureConstructionFailureRestoresActiveProject() throws IOException {
        Project originalProject = AppInfo.getActiveProject();
        assertNotNull("the shared TestEnv project must be active", originalProject);
        try {
            new TestRepositoryProject(originalProject, false);
            fail("a non-versioned file system must fail the repository fixture");
        } catch (IOException expected) {
            assertTrue("fixture failure should name the repository attach step: "
                + expected.getMessage(), expected.getMessage().contains("Failed to attach"));
        }
        assertSame("a failed fixture must restore the caller's active project",
            originalProject, AppInfo.getActiveProject());
    }

    /** Release any cache entry for {@code programPath}, then forget it. */
    private static void releaseCachedProgram(String programPath) {
        if (programPath == null) {
            return;
        }
        for (Program known : RevaProgramManager.getAllKnownPrograms()) {
            if (programPath.equals(RevaProgramManager.getCanonicalProgramPath(known))
                    && RevaProgramManager.isProgramCached(known)) {
                RevaProgramManager.releaseProgramFromCache(known);
            }
        }
    }

    /**
     * Minimal repository-backed project fixture for version-control tests.
     * <p>
     * Ghidra's test-only {@code ghidra.base.project.FakeRepository} / {@code FakeSharedProject}
     * are not shipped in the release installation this extension builds against, so this
     * reproduces their essential wiring: an isolated private project whose versioned file
     * system is a local shared (versioned) file system. Tests set this project as the active
     * project via {@link AppInfo} and restore the original one before {@link #dispose()};
     * construction failure also restores it, because {@code GhidraProject.createProject} has
     * already switched the active project by the time the repository attach can fail.
     */
    private static final class TestRepositoryProject {

        private final File rootDir;
        private final LocalFileSystem repoFileSystem;
        private final GhidraProject ghidraProject;

        TestRepositoryProject(Project originalProject) throws IOException {
            this(originalProject, true);
        }

        /**
         * @param versioned false creates a non-versioned local file system, so the repository
         *        attach fails after {@code createProject} has switched the active project
         */
        private TestRepositoryProject(Project originalProject, boolean versioned)
                throws IOException {
            rootDir = Files.createTempDirectory("reva-checkin-project-").toFile();
            // Validation is required when a fake shared project and the regular TestEnv
            // private file system are both used in the same JVM (see FakeRepository).
            LocalFileSystem.setValidationRequired();
            File repoDir = new File(rootDir, "TestRepo.rep");
            if (!FileUtilities.createDir(repoDir)) {
                FileUtilities.deleteDir(rootDir);
                throw new IOException("Could not create shared repository directory: " + repoDir);
            }
            LocalFileSystem fs = null;
            GhidraProject project = null;
            try {
                fs = new TestLocalFileSystem(repoDir.getPath(), versioned);
                project = GhidraProject.createProject(rootDir.getPath(),
                    "TestProject_" + System.nanoTime(), true);
                setVersionedFileSystem((DefaultProjectData) project.getProjectData(), fs);
            } catch (Exception e) {
                if (project != null) {
                    project.close();
                }
                if (fs != null) {
                    fs.dispose();
                }
                FileUtilities.deleteDir(rootDir);
                // createProject made the fixture project the active project. Restore the
                // caller's project before propagating: a half-built fixture must not leave
                // later tests without the real active project.
                AppInfo.setActiveProject(originalProject);
                if (e instanceof IOException io) {
                    throw io;
                }
                throw new IOException("Failed to attach the test repository", e);
            }
            repoFileSystem = fs;
            ghidraProject = project;
        }

        Project getProject() {
            return ghidraProject.getProject();
        }

        DefaultProjectData getProjectData() {
            return (DefaultProjectData) ghidraProject.getProjectData();
        }

        void dispose() {
            try {
                ghidraProject.close();
            } finally {
                repoFileSystem.dispose();
                FileUtilities.deleteDir(rootDir);
            }
        }

        private static void setVersionedFileSystem(DefaultProjectData projectData, FileSystem fs)
                throws Exception {
            Method setter = DefaultProjectData.class.getDeclaredMethod(
                "setVersionedFileSystem", FileSystem.class);
            setter.setAccessible(true);
            try {
                setter.invoke(projectData, fs);
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause();
                if (cause instanceof Exception) {
                    throw (Exception) cause;
                }
                throw e;
            }
        }

        /** Match FakeRepository: a shared file system dispatches file-system events async. */
        private static final class TestLocalFileSystem extends IndexedV1LocalFileSystem {
            TestLocalFileSystem(String rootPath, boolean versioned) throws IOException {
                super(rootPath, versioned, false, true, true);
            }

            @Override
            public boolean isShared() {
                return true;
            }
        }
    }

    /** Extract the text payload of a single-content tool result. */
    private static String text(McpSchema.CallToolResult result) {
        return ((McpSchema.TextContent) result.content().get(0)).text();
    }
}
