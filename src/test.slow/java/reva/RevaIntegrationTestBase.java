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
import ghidra.test.TestEnv;
import ghidra.program.model.listing.Program;
import ghidra.framework.plugintool.PluginTool;

import org.junit.Before;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.AfterClass;

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

    // Shared test environment across all tests
    private static TestEnv sharedEnv;
    private static PluginTool sharedTool;
    private static RevaPlugin sharedPlugin;
    private static ConfigManager sharedConfigManager;
    private static McpServerManager sharedServerManager;
    private static ObjectMapper sharedObjectMapper;
    
    // Per-test instances
    public TestEnv env;
    protected PluginTool tool;
    protected Program program;
    protected RevaPlugin plugin;
    protected ConfigManager configManager;
    protected McpServerManager serverManager;
    protected ObjectMapper objectMapper;


    /**
     * Set up shared test environment once for all tests in the class.
     * This significantly speeds up test execution by reusing the Ghidra instance.
     * 
     * Note: TestEnv, MCP server, and plugin initialization must be done lazily in @Before 
     * method due to Ghidra system initialization requirements, but we can prepare 
     * non-Ghidra dependent shared resources here to reduce per-test overhead.
     */
    @BeforeClass
    public static void setUpSharedTestEnvironment() throws Exception {
        // Initialize shared object mapper for JSON parsing across all tests
        sharedObjectMapper = new ObjectMapper();
        
        // Pre-configure any other non-Ghidra dependent shared resources here
        // This reduces per-test initialization overhead even though the main 
        // Ghidra/MCP setup must still be done lazily in @Before
    }

    /**
     * Set up shared MCP server services for the entire test class.
     */
    private static void setupSharedMcpServices() {
        // Create and register shared ConfigManager
        sharedConfigManager = new ConfigManager(sharedTool);
        reva.util.RevaInternalServiceRegistry.registerService(ConfigManager.class, sharedConfigManager);
        
        // Create and register shared McpServerManager
        sharedServerManager = new McpServerManager(sharedTool);
        reva.util.RevaInternalServiceRegistry.registerService(McpServerManager.class, sharedServerManager);
        reva.util.RevaInternalServiceRegistry.registerService(reva.services.RevaMcpService.class, sharedServerManager);
        
        // Start the shared MCP server
        sharedServerManager.startServer();
    }

    /**
     * Clean up shared test environment after all tests complete.
     */
    @AfterClass
    public static void tearDownSharedTestEnvironment() throws Exception {
        if (sharedEnv != null) {
            // Shutdown the shared MCP server
            if (sharedServerManager != null) {
                sharedServerManager.shutdown();
                sharedServerManager = null;
            }

            // Clear the shared service registry
            reva.util.RevaInternalServiceRegistry.clearAllServices();

            // Clean up the shared test environment
            try {
                sharedEnv.dispose();
            } catch (IllegalAccessError e) {
                // Ignore the module access error during cleanup
            }
            sharedEnv = null;
            sharedTool = null;
            sharedPlugin = null;
            sharedConfigManager = null;
            sharedObjectMapper = null;
        }
    }

    /**
     * Create the MCP transport - provides a default HTTP SSE implementation.
     * Subclasses can override this to use different transport types (WebSocket, etc.)
     */
    protected McpClientTransport createMcpTransport() {
        // Use shared config manager for server port
        int serverPort = sharedConfigManager != null ? sharedConfigManager.getServerPort() : 8080;
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
        // Initialize shared environment lazily on first test to ensure Ghidra system is ready
        if (sharedEnv == null) {
            synchronized (RevaIntegrationTestBase.class) {
                if (sharedEnv == null) {
                    // Create shared test environment
                    sharedEnv = new TestEnv();
                    sharedTool = sharedEnv.getTool();

                    // Set up MCP services for testing
                    setupSharedMcpServices();

                    // Add the ReVa plugin to the shared tool
                    sharedTool.addPlugin(RevaPlugin.class.getName());

                    // Get the shared plugin instance
                    for (ghidra.framework.plugintool.Plugin p : sharedTool.getManagedPlugins()) {
                        if (p instanceof RevaPlugin) {
                            sharedPlugin = (RevaPlugin) p;
                            break;
                        }
                    }

                    if (sharedPlugin == null) {
                        throw new RuntimeException("Failed to load RevaPlugin in shared environment");
                    }

                    // Wait for the shared server to be ready
                    int maxWait = 15000; // 15 seconds
                    int waitTime = 0;
                    int interval = 100;

                    while (waitTime < maxWait) {
                        if (sharedServerManager != null && sharedServerManager.isServerReady()) {
                            break;
                        }
                        Thread.sleep(interval);
                        waitTime += interval;
                    }

                    if (waitTime >= maxWait) {
                        throw new RuntimeException("Shared server failed to start within timeout");
                    }
                }
            }
        }

        // Use shared instances to avoid re-initialization
        env = sharedEnv;
        tool = sharedTool;
        plugin = sharedPlugin;
        configManager = sharedConfigManager;
        serverManager = sharedServerManager;
        objectMapper = sharedObjectMapper;

        // Create a fresh program for each test
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

        // Register this program with the shared server (simulates program opening in tool)
        if (serverManager != null) {
            serverManager.programOpened(program, tool);
        }

        onGhidraStart();
    }

    @After
    public void tearDownRevaPlugin() throws Exception {
        onGhidraClose();

        // Unregister the test program from the shared server
        if (serverManager != null && program != null) {
            serverManager.programClosed(program, tool);
        }

        // Clean up the program (but keep shared instances)
        if (program != null) {
            program.release(this);
            program = null;
        }

        // Note: We don't shutdown the server or clear the registry here
        // since they're shared across all tests in the class
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
        int serverPort = sharedConfigManager.getServerPort();
        String baseServerUrl = "http://localhost:" + serverPort;

        try {
            java.net.URL url = java.net.URI.create(baseServerUrl + "/").toURL();
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            conn.getResponseCode(); // Check server availability
            conn.disconnect();
        } catch (Exception e) {
        }

        // Try the MCP message endpoint
        try {
            java.net.URL url = java.net.URI.create(baseServerUrl + "/mcp/message").toURL();
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            conn.getResponseCode(); // Check server availability
            conn.disconnect();
        } catch (Exception e) {
        }

        // Try the MCP SSE endpoint
        try {
            java.net.URL url = java.net.URI.create(baseServerUrl + "/mcp/sse").toURL();
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            conn.getResponseCode(); // Check server availability
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