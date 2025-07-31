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
package reva.plugin;

import static org.junit.Assert.*;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import org.junit.Test;
import org.junit.Before;
import org.junit.After;

import io.modelcontextprotocol.spec.McpClientTransport;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import reva.RevaIntegrationTestBase;

/**
 * Integration tests for MCP client timeout functionality
 */
public class McpTimeoutIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;

    @Before
    public void setUpTimeoutTest() throws Exception {
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

    @After
    public void tearDownTimeoutTest() throws Exception {
        // No need to reset timeouts since we don't modify server config
    }

    @Test
    public void testMcpClientTimeoutTriggers() throws Exception {
        // Create a custom MCP client with a short timeout (don't change server config)
        McpClientTransport transport = createMcpTransport();

        withMcpClient(transport,
            spec -> spec.requestTimeout(Duration.ofSeconds(1))
                       .initializationTimeout(Duration.ofSeconds(10)),
            client -> {
                client.initialize();

                // Call a tool that will take longer than 1 second
                // Use search-decompilation with overrideMaxFunctionsLimit which should take time
                Map<String, Object> args = new HashMap<>();
                args.put("programPath", programPath);
                args.put("pattern", ".*");  // Search for everything - should take time
                args.put("overrideMaxFunctionsLimit", true);  // Force processing all functions

                try {
                    CallToolResult result = client.callTool(new CallToolRequest("search-decompilation", args));
                    
                    // If we get a result, check if it indicates a timeout
                    if (result != null && result.content() != null && !result.content().isEmpty()) {
                        Object contentObj = result.content().get(0);
                        if (contentObj instanceof TextContent) {
                            String content = ((TextContent) contentObj).text();
                            if (content.toLowerCase().contains("timeout") || content.toLowerCase().contains("timed out")) {
                                // Success - timeout was handled gracefully by the tool
                                return;
                            }
                        }
                    }
                    
                    fail("Expected timeout but search call succeeded without timeout indication");
                } catch (Exception e) {
                    // Check if the exception is related to timeout
                    Throwable cause = e;
                    while (cause != null) {
                        if (cause instanceof TimeoutException ||
                            (cause.getMessage() != null && cause.getMessage().toLowerCase().contains("timeout"))) {
                            // Success - timeout was triggered
                            return;
                        }
                        cause = cause.getCause();
                    }
                    // The tool might return an error result rather than throwing - check the message
                    if (e.getMessage() != null && e.getMessage().toLowerCase().contains("timeout")) {
                        return;
                    }
                    throw new AssertionError("Expected timeout exception but got: " + e.getClass().getName() + " - " + e.getMessage(), e);
                }
            });
    }

    @Test
    public void testMcpClientSucceedsWithinTimeout() throws Exception {
        // Create a custom MCP client with adequate timeout (don't change server config)
        McpClientTransport transport = createMcpTransport();

        withMcpClient(transport,
            spec -> spec.requestTimeout(Duration.ofSeconds(10))
                       .initializationTimeout(Duration.ofSeconds(10)),
            client -> {
                client.initialize();

                // Call a simple tool that should complete quickly
                Map<String, Object> args = new HashMap<>();
                args.put("programPath", programPath);

                CallToolResult result = client.callTool(new CallToolRequest("get-strings-count", args));
                assertNotNull("Tool result should not be null", result);
                assertFalse("Tool should succeed (not error)", result.isError());

                // Verify the response
                Object contentObj = result.content().get(0);
                assertTrue("Content should be TextContent", contentObj instanceof TextContent);
                String content = ((TextContent) contentObj).text();
                assertTrue("Response should contain count", content.contains("count"));
            });
    }

}