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
package reva.tools.bookmarks;

import static org.junit.Assert.*;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import reva.RevaIntegrationTestBase;
import reva.plugin.RevaProgramManager;

/**
 * Integration tests for BookmarkToolProvider using MCP client.
 * Tests the full end-to-end flow from MCP client through the server to Ghidra.
 */
public class BookmarkToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();
        
        // Open the program in the tool's ProgramManager so it can be found by RevaProgramManager
        env.open(program);

        // Also open it directly in the tool's ProgramManager service to ensure it's available
        ghidra.app.services.ProgramManager programManager = tool.getService(ghidra.app.services.ProgramManager.class);
        if (programManager != null) {
            programManager.openProgram(program);
        }

        // Register the program with the server manager so it can be found by the tools
        if (serverManager != null) {
            serverManager.programOpened(program, tool);
        }
    }

    @Test
    public void testSetAndGetBookmark() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Use the minimum address in the program which should be valid
                Address testAddress = program.getMinAddress();
                String addressStr = testAddress.toString();

                // Set a bookmark
                Map<String, Object> setArgs = new HashMap<>();
                setArgs.put("programPath", programPath);
                setArgs.put("addressOrSymbol", addressStr);
                setArgs.put("type", "Note");
                setArgs.put("category", "Analysis");
                setArgs.put("comment", "Test bookmark");

                CallToolRequest setRequest = new CallToolRequest("set-bookmark", setArgs);
                CallToolResult setResult = client.callTool(setRequest);
                assertFalse("Set bookmark should succeed", setResult.isError());

                // Verify the bookmark was set in the program
                BookmarkManager bookmarkMgr = program.getBookmarkManager();
                Bookmark bookmark = bookmarkMgr.getBookmark(testAddress, "Note", "Analysis");
                assertNotNull("Bookmark should exist", bookmark);
                assertEquals("Bookmark comment should match", "Test bookmark", bookmark.getComment());

                // Get the bookmark using the tool
                Map<String, Object> getArgs = new HashMap<>();
                getArgs.put("programPath", programPath);
                getArgs.put("addressOrSymbol", addressStr);

                CallToolRequest getRequest = new CallToolRequest("get-bookmarks", getArgs);
                CallToolResult getResult = client.callTool(getRequest);
                assertFalse("Get bookmarks should succeed", getResult.isError());

                // Parse the result
                String jsonResponse = ((TextContent) getResult.content().get(0)).text();
                JsonNode responseNode = objectMapper.readTree(jsonResponse);
                JsonNode bookmarksNode = responseNode.get("bookmarks");
                
                assertEquals("Should have one bookmark", 1, bookmarksNode.size());
                assertEquals("Bookmark comment should match", "Test bookmark", bookmarksNode.get(0).get("comment").asText());
                assertEquals("Bookmark type should match", "Note", bookmarksNode.get(0).get("type").asText());
                assertEquals("Bookmark category should match", "Analysis", bookmarksNode.get(0).get("category").asText());
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    /**
     * A missing removal must roll back its transaction: the next bookmark write
     * commits normally, and the checkin that follows leaves both bookmarks in the
     * saved database and exports a non-empty packed GZF.
     */
    @Test
    public void testMissingRemovalRollsBackAndNextWritePersists() throws Exception {
        // A temporary program's domain file is read-only, so the save behind
        // checkin would be skipped and nothing would reach disk. Publish a
        // project-backed copy instead; registering it also keeps the checkin
        // path from caching a program it did not open as a consumer.
        DomainFolder root = env.getProject().getProjectData().getRootFolder();
        DomainFile file = root.createFile("bookmark-rollback-" + System.nanoTime(), program,
            TaskMonitor.DUMMY);
        Program saveable = (Program) file.getDomainObject(this, false, false, TaskMonitor.DUMMY);
        saveable.setTemporary(false);
        String saveablePath = file.getPathname();
        RevaProgramManager.registerProgram(saveable);
        try {
            withMcpClient(createMcpTransport(), (McpClientFunction<Void>) client -> {
                client.initialize();

                Address testAddress = saveable.getMinAddress();
                String addressStr = testAddress.toString();

                // A bookmark in another category: the removal below must not match it.
                CallToolResult first =
                    setBookmark(client, saveablePath, addressStr, "Analysis", "original");
                assertFalse("Initial set-bookmark should succeed", first.isError());

                // Removal with a non-matching category fails and must roll back.
                Map<String, Object> removeArgs = new HashMap<>();
                removeArgs.put("programPath", saveablePath);
                removeArgs.put("addressOrSymbol", addressStr);
                removeArgs.put("type", "Note");
                removeArgs.put("category", "Evidence");
                CallToolResult removeResult =
                    client.callTool(new CallToolRequest("remove-bookmark", removeArgs));
                assertTrue("Missing removal should report an error", removeResult.isError());
                assertTrue("Missing removal should report no bookmark was found",
                    text(removeResult).contains("No bookmark found"));
                assertNull("Missing removal must not leave a transaction open",
                    saveable.getCurrentTransactionInfo());

                // The next write opens and commits a transaction of its own.
                CallToolResult second =
                    setBookmark(client, saveablePath, addressStr, "Evidence", "after");
                assertFalse("Set-bookmark after the rollback should succeed", second.isError());
                assertTrue(text(second).contains("\"success\":true"));
                assertNull("Set-bookmark should have ended its transaction",
                    saveable.getCurrentTransactionInfo());

                // Check in and read the saved database back from disk.
                CallToolResult checkinResult = client.callTool(new CallToolRequest(
                    "checkin-program",
                    Map.of("programPath", saveablePath, "message", "after missing removal")));
                assertFalse("Checkin should succeed: " + text(checkinResult),
                    checkinResult.isError());
                assertTrue(text(checkinResult).contains("\"success\":true"));

                // The read-back below must be the saved database, not this live
                // program: commit a bookmark in memory without saving it and
                // require it to be absent from the saved copy.
                int unsavedTx = saveable.startTransaction("unsaved bookmark");
                try {
                    saveable.getBookmarkManager().setBookmark(testAddress, "Note", "Unsaved",
                        "memory only");
                } finally {
                    saveable.endTransaction(unsavedTx, true);
                }

                DomainObject saved = null;
                try {
                    saved = file.getReadOnlyDomainObject(this, DomainFile.DEFAULT_VERSION,
                        TaskMonitor.DUMMY);
                    assertTrue("Saved domain object should be a program", saved instanceof Program);
                    BookmarkManager savedBookmarks = ((Program) saved).getBookmarkManager();

                    assertNull("The read-back must not see committed-but-unsaved work",
                        savedBookmarks.getBookmark(testAddress, "Note", "Unsaved"));

                    Bookmark analysis =
                        savedBookmarks.getBookmark(testAddress, "Note", "Analysis");
                    assertNotNull("The pre-existing bookmark should survive in the saved database",
                        analysis);
                    assertEquals("original", analysis.getComment());

                    Bookmark evidence =
                        savedBookmarks.getBookmark(testAddress, "Note", "Evidence");
                    assertNotNull("The write after the rollback should be in the saved database",
                        evidence);
                    assertEquals("after", evidence.getComment());

                    File gzf = new File(System.getProperty("java.io.tmpdir"),
                        "bookmark-rollback-" + System.nanoTime() + ".gzf");
                    try {
                        saved.saveToPackedFile(gzf, TaskMonitor.DUMMY);
                        assertTrue("Packed GZF should be non-empty", gzf.length() > 0);
                    } finally {
                        gzf.delete();
                    }
                } finally {
                    if (saved != null) {
                        saved.release(this);
                    }
                }
                return null;
            });
        } finally {
            RevaProgramManager.unregisterProgram(saveable);
            saveable.release(this);
            try {
                file.delete();
            } catch (Exception ignore) {
                // best-effort cleanup of the temporary project file
            }
        }
    }

    private CallToolResult setBookmark(McpSyncClient client, String path, String addressStr,
            String category, String comment) {
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", path);
        args.put("addressOrSymbol", addressStr);
        args.put("type", "Note");
        args.put("category", category);
        args.put("comment", comment);
        return client.callTool(new CallToolRequest("set-bookmark", args));
    }

    private static String text(CallToolResult result) {
        return ((TextContent) result.content().get(0)).text();
    }
}