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
package reva;

import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.program.model.listing.Program;
import ghidra.framework.plugintool.PluginTool;

import org.junit.Before;
import org.apache.commons.compress.harmony.pack200.NewAttributeBands.Call;
import org.junit.After;

import static org.junit.Assert.fail;

import java.time.Duration;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.transport.HttpClientSseClientTransport;
import io.modelcontextprotocol.spec.McpClientTransport;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.ClientCapabilities;
import io.modelcontextprotocol.spec.McpSchema.ListToolsResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import reva.plugin.RevaPlugin;
import reva.util.ConfigManager;
import reva.server.McpServerManager;

/**
 * Base class for ReVa integration tests that provides common test setup
 * and utility methods for testing with Ghidra programs and MCP clients.
 * This follows the same pattern as AbstractMcpSyncClientTests from the MCP Java SDK.
 */
public abstract class RevaIntegrationTestBase extends AbstractGhidraHeadedIntegrationTest {

    public TestEnv env;
    protected PluginTool tool;
    protected Program program;
    protected RevaPlugin plugin;
    protected ConfigManager configManager;
    protected McpServerManager serverManager;
    protected ObjectMapper objectMapper;


    /**
     * Create the MCP transport - provides a default HTTP SSE implementation.
     * Subclasses can override this to use different transport types (WebSocket, etc.)
     */
    protected McpClientTransport createMcpTransport() {
        // Create HTTP SSE transport to connect to our MCP server
        int serverPort = configManager != null ? configManager.getServerPort() : 8080;
        String serverUrl = "http://localhost:" + serverPort;

        HttpClientSseClientTransport transport = HttpClientSseClientTransport.builder(serverUrl)
            .sseEndpoint("/mcp/sse")
            .build();
        return transport;
    }

    /**
     * Hook for subclasses to perform additional setup after the Ghidra environment is ready
     */
    protected void onGhidraStart() {
    }

    /**
     * Hook for subclasses to perform additional cleanup
     */
    protected void onGhidraClose() {
    }

    /**
     * Get request timeout for MCP operations
     */
    protected Duration getRequestTimeout() {
        return Duration.ofSeconds(14);
    }

    /**
     * Get initialization timeout for MCP client
     */
    protected Duration getInitializationTimeout() {
        return Duration.ofSeconds(10);
    }

    /**
     * Create an MCP client with default settings
     */
    protected McpSyncClient createMcpClient(McpClientTransport transport) {
        return createMcpClient(transport, Function.identity());
    }

    /**
     * Create an MCP client with custom configuration
     */
    protected McpSyncClient createMcpClient(McpClientTransport transport,
            Function<McpClient.SyncSpec, McpClient.SyncSpec> customizer) {
        McpClient.SyncSpec builder = McpClient.sync(transport)
                .requestTimeout(getRequestTimeout())
                .initializationTimeout(getInitializationTimeout())
                .capabilities(ClientCapabilities.builder().roots(true).build());

        builder = customizer.apply(builder);
        return builder.build();
    }

    /**
     * Utility method to execute operations with an MCP client
     */
    protected void withMcpClient(McpClientTransport transport, Consumer<McpSyncClient> operation) {
        withMcpClient(transport, Function.identity(), operation);
    }

    /**
     * Utility method to execute operations with a customized MCP client
     */
    protected void withMcpClient(McpClientTransport transport,
            Function<McpClient.SyncSpec, McpClient.SyncSpec> customizer,
            Consumer<McpSyncClient> operation) {

        McpSyncClient client = createMcpClient(transport, customizer);

        try {
            operation.accept(client);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("MCP client operation failed", e);
        } finally {
            try {
                if (!client.closeGracefully()) {
                    System.err.println("Failed to close MCP client gracefully");
                    throw new RuntimeException("Failed to close MCP client gracefully");
                } else {
                }
            } catch (Exception e) {
                System.err.println("Exception while closing client: " + e.getMessage());
                throw new RuntimeException("Exception while closing MCP client", e);
            }
        }
    }

    @Before
    public void setUpRevaPlugin() throws Exception {
        // Initialize object mapper for JSON parsing
        objectMapper = new ObjectMapper();

        // Create test environment - this will work if test resources are available
        if (env == null) {
            env = new TestEnv();
        }

        // Get the tool from the environment
        tool = env.getTool();

        // Create a program using the helper method from parent class
        program = createDefaultProgram(getName(), "x86:LE:32:default", this);

        // Add a memory block to the program for tests that expect it
        if (program.getMemory().getBlocks().length == 0) {
            int txId = program.startTransaction("Add test memory");
            try {
                program.getMemory().createInitializedBlock("test",
                    program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000),
                    0x1000, (byte) 0, ghidra.util.task.TaskMonitor.DUMMY, false);
            } finally {
                program.endTransaction(txId, true);
            }
        }

        // Add the ReVa plugin to the tool
        tool.addPlugin(RevaPlugin.class.getName());

        // Get the plugin instance
        for (ghidra.framework.plugintool.Plugin p : tool.getManagedPlugins()) {
            if (p instanceof RevaPlugin) {
                plugin = (RevaPlugin) p;
                break;
            }
        }

        if (plugin == null) {
            throw new RuntimeException("Failed to load RevaPlugin");
        }

        // Initialize MCP utilities
        configManager = reva.util.RevaInternalServiceRegistry.getService(ConfigManager.class);
        serverManager = reva.util.RevaInternalServiceRegistry.getService(McpServerManager.class);

        if (configManager != null) {
        }

        // Wait for the server to be ready
        int maxWait = 15000; // 15 seconds
        int waitTime = 0;
        int interval = 100;

        while (waitTime < maxWait) {
            if (serverManager != null && serverManager.isServerReady()) {
                break;
            }
            Thread.sleep(interval);
            waitTime += interval;
        }

        if (waitTime >= maxWait) {
            System.err.println("Server failed to become ready within " + maxWait + "ms");
            throw new RuntimeException("Server failed to start within timeout");
        }


        onGhidraStart();
    }

    @After
    public void tearDownRevaPlugin() throws Exception {
        onGhidraClose();

        // Clean up the test environment to prevent interference between tests
        if (env != null) {
            try {
                env.dispose();
            } catch (IllegalAccessError e) {
                // Ignore the module access error during cleanup
                // This is a known issue with Ghidra's test framework in Java 11+
            }
            env = null;
        }
        tool = null;
        program = null;
        plugin = null;
        configManager = null;
        serverManager = null;
        objectMapper = null;
    }

    /**
     * Helper method to parse JSON content from MCP tool results
     * @param content The text content to parse
     * @return JsonNode representation of the content
     * @throws RuntimeException if JSON parsing fails
     */
    protected JsonNode parseJsonContent(String content) {
        try {
            return objectMapper.readTree(content);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse JSON content: " + content, e);
        }
    }

    /**
     * Helper method to call an MCP tool using the MCP client
     * @param toolName The name of the tool to call
     * @param arguments The arguments for the tool
     * @return The tool result content as string
     * @throws Exception if the tool call fails
     */
    protected String callMcpTool(String toolName, Map<String, Object> arguments) throws Exception {
        return withMcpClient(createMcpTransport(), (McpClientFunction<String>) client -> {
            client.initialize();
            CallToolResult result = client.callTool(new CallToolRequest(toolName, arguments));

            if (result.isError() != null && result.isError()) {
                throw new RuntimeException("Tool call failed: " + result);
            }

            if (result.content() != null && !result.content().isEmpty()) {
                Object content = result.content().get(0);
                if (content instanceof TextContent) {
                    return ((TextContent) content).text();
                }
            }

            throw new RuntimeException("No content in tool result");
        });
    }

    /**
     * Helper method to get available tools from the MCP server
     * @return List of available tools
     * @throws Exception if the request fails
     */
    protected ListToolsResult getAvailableTools() throws Exception {

        // First, let's verify server is accessible via simple HTTP check
        int serverPort = configManager.getServerPort();
        String baseServerUrl = "http://localhost:" + serverPort;

        try {
            java.net.URL url = new java.net.URL(baseServerUrl + "/");
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            int responseCode = conn.getResponseCode();
            conn.disconnect();
        } catch (Exception e) {
        }

        // Try the MCP message endpoint
        try {
            java.net.URL url = new java.net.URL(baseServerUrl + "/mcp/message");
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            int responseCode = conn.getResponseCode();
            conn.disconnect();
        } catch (Exception e) {
        }

        // Try the MCP SSE endpoint
        try {
            java.net.URL url = new java.net.URL(baseServerUrl + "/mcp/sse");
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            int responseCode = conn.getResponseCode();
            conn.disconnect();
        } catch (Exception e) {
        }

        return withMcpClient(createMcpTransport(), (McpClientFunction<ListToolsResult>) client -> {
            try {
                client.initialize();
            } catch (Exception e) {
                e.printStackTrace();
                throw e;
            }

            try {
                ListToolsResult result = client.listTools(null);
                return result;
            } catch (Exception e) {
                e.printStackTrace();
                throw e;
            }
        });
    }

    /**
     * Helper method to verify that an MCP tool call fails with an expected error
     * @param toolName The name of the tool to call
     * @param arguments The arguments for the tool
     * @param expectedErrorSubstring A substring that should be contained in the error message
     * @throws Exception if the test setup fails
     */
    protected void verifyMcpToolFailsWithError(String toolName, Map<String, Object> arguments,
            String expectedErrorSubstring) throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            try {
                CallToolResult result = client.callTool(new CallToolRequest(toolName, arguments));
                if (result.isError() == null || !result.isError()) {
                    throw new AssertionError("Expected tool call to fail but it succeeded");
                }

                String errorMessage = result.toString();
                if (!errorMessage.contains(expectedErrorSubstring)) {
                    throw new AssertionError("Expected error message to contain '" + expectedErrorSubstring +
                        "' but got: " + errorMessage);
                }
            } catch (Exception e) {
                if (!e.getMessage().contains(expectedErrorSubstring)) {
                    throw new AssertionError("Expected error message to contain '" + expectedErrorSubstring +
                        "' but got: " + e.getMessage());
                }
                // Test passed - error message contains expected substring
            }
        });
    }

    /**
     * Functional interface for operations that return a value
     */
    @FunctionalInterface
    protected interface McpClientFunction<T> {
        T apply(McpSyncClient client) throws Exception;
    }

    /**
     * Utility method to execute operations with an MCP client that return a value
     */
    protected <T> T withMcpClient(McpClientTransport transport, McpClientFunction<T> operation) throws Exception {
        McpSyncClient client = createMcpClient(transport);
        try {
            return operation.apply(client);
        } finally {
            if (!client.closeGracefully()) {
                throw new RuntimeException("Failed to close MCP client gracefully");
            }
        }
    }

    public void assertMcpResultNotError(CallToolResult result, String message) {
        if (result.isError()) {
            String fullMessage = message + ": " + result.toString();
            fail(fullMessage);
        }
    }

}