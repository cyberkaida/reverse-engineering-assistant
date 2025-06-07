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

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import reva.RevaIntegrationTestBase;

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
            serverManager.programOpened(program);
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
                setArgs.put("address", addressStr);
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
                getArgs.put("address", addressStr);

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
}