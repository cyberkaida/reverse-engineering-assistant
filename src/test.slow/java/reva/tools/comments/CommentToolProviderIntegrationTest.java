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
package reva.tools.comments;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import reva.RevaIntegrationTestBase;

/**
 * Integration tests for CommentToolProvider using MCP client.
 * Tests the full end-to-end flow from MCP client through the server to Ghidra.
 */
public class CommentToolProviderIntegrationTest extends RevaIntegrationTestBase {

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
    public void testSetAndGetComment() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Use the minimum address in the program which should be valid
                Address testAddress = program.getMinAddress();
                String addressStr = testAddress.toString();

                // Set a comment
                Map<String, Object> setArgs = new HashMap<>();
                setArgs.put("programPath", programPath);
                setArgs.put("address", addressStr);
                setArgs.put("commentType", "eol");
                setArgs.put("comment", "Test comment");

                CallToolRequest setRequest = new CallToolRequest("set-comment", setArgs);
                CallToolResult setResult = client.callTool(setRequest);
                assertFalse("Set comment should succeed", setResult.isError());

                // Verify the comment was set in the program
                Listing listing = program.getListing();
                String actualComment = listing.getComment(CodeUnit.EOL_COMMENT, testAddress);
                assertEquals("Comment should be set correctly", "Test comment", actualComment);

                // Get the comment using the tool
                Map<String, Object> getArgs = new HashMap<>();
                getArgs.put("programPath", programPath);
                getArgs.put("address", addressStr);

                CallToolRequest getRequest = new CallToolRequest("get-comments", getArgs);
                CallToolResult getResult = client.callTool(getRequest);
                assertFalse("Get comments should succeed", getResult.isError());

                // Parse the result
                String jsonResponse = ((TextContent) getResult.content().get(0)).text();
                JsonNode responseNode = objectMapper.readTree(jsonResponse);
                JsonNode commentsNode = responseNode.get("comments");
                
                assertEquals("Should have one comment", 1, commentsNode.size());
                assertEquals("Comment text should match", "Test comment", commentsNode.get(0).get("comment").asText());
                assertEquals("Comment type should match", "eol", commentsNode.get(0).get("commentType").asText());
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }
}