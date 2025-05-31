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

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;

import org.junit.Test;
import org.junit.Before;
import org.junit.After;

import io.modelcontextprotocol.spec.McpSchema.ListToolsResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import reva.RevaHeadlessIntegrationTestBase;
import reva.RevaIntegrationTestBase;
import reva.util.ConfigManager;

/**
 * Integration tests for the MCP server functionality in RevaPlugin
 */
public class RevaPluginMcpIntegrationTest extends RevaIntegrationTestBase {

    private ConfigManager configManager;

    @Before
    public void setUpMcpTest() throws Exception {
        // Get the config manager from the plugin's server manager
        // The plugin already has its own ConfigManager instance
        configManager = reva.util.RevaInternalServiceRegistry.getService(ConfigManager.class);
        assertNotNull("ConfigManager should be registered", configManager);
    }

    @After
    public void tearDownMcpTest() throws Exception {
        // No need to disable server - let the plugin manage its own lifecycle
    }

    @Test
    public void testMcpServerStarts() throws Exception {
        // The server starts asynchronously, so we need to give it more time
        // and retry a few times
        int port = configManager.getServerPort();
        URL url = new URL("http://localhost:" + port + "/");

        boolean connected = false;
        Exception lastException = null;

        // Try to connect up to 10 times with 500ms delay between attempts
        for (int i = 0; i < 10; i++) {
            try {
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("GET");
                connection.setConnectTimeout(1000);
                connection.setReadTimeout(1000);

                int responseCode = connection.getResponseCode();

                // The MCP server should respond with something (even if it's an error for GET)
                // We're just checking that it's listening
                if (responseCode > 0) {
                    connected = true;
                    break;
                }
            } catch (Exception e) {
                lastException = e;
                Thread.sleep(500); // Wait before retrying
            }
        }

        assertTrue("Should be able to connect to MCP server" +
                   (lastException != null ? ": " + lastException.getMessage() : ""),
                   connected);
    }

    @Test
    public void testServerConfiguration() {
        assertTrue("Server should be enabled", configManager.isServerEnabled());
        // Check that the server is using the default port (8080)
        assertEquals("Server port should be default", 8080, configManager.getServerPort());
    }

    @Test
    public void testToolsAreRegistered() throws Exception {
        System.out.println("[DEADLOCK-DEBUG] testToolsAreRegistered() starting - Thread: " + Thread.currentThread().getName());
        // Wait a bit for server to fully initialize
        Thread.sleep(1000);

        try {
            System.out.println("[DEADLOCK-DEBUG] Calling getAvailableTools()...");
            ListToolsResult toolsResult = getAvailableTools();
            System.out.println("[DEADLOCK-DEBUG] getAvailableTools() returned");
            assertNotNull("Tools result should not be null", toolsResult);

            List<Tool> tools = toolsResult.tools();
            assertNotNull("Tools list should not be null", tools);
            assertFalse("Should have at least one tool registered", tools.isEmpty());

            // Print tool names for debugging
            System.out.println("Found " + tools.size() + " tools:");
            for (Tool tool : tools) {
                System.out.println("  - " + tool.name());
            }

            // Verify that tools have required properties
            for (Tool tool : tools) {
                assertNotNull("Tool name should not be null", tool.name());
                assertFalse("Tool name should not be empty", tool.name().trim().isEmpty());
                assertNotNull("Tool description should not be null", tool.description());
            }
        } catch (Exception e) {
            System.err.println("Error connecting to MCP server: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    @Test
    public void testExpectedToolsArePresent() throws Exception {
        ListToolsResult toolsResult = getAvailableTools();
        List<Tool> tools = toolsResult.tools();

        // Convert to a list of tool names for easier checking
        List<String> toolNames = tools.stream()
            .map(Tool::name)
            .collect(java.util.stream.Collectors.toList());

        // Check for some expected tool categories - these should be present based on the tool providers
        assertTrue("Should have memory-related tools",
            toolNames.stream().anyMatch(name -> name.contains("memory")));
        assertTrue("Should have function-related tools",
            toolNames.stream().anyMatch(name -> name.contains("function")));
        assertTrue("Should have string-related tools",
            toolNames.stream().anyMatch(name -> name.contains("string")));
        assertTrue("Should have symbol-related tools",
            toolNames.stream().anyMatch(name -> name.contains("symbol")));
    }
}