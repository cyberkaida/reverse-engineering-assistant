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
import java.net.URI;
import java.net.URL;
import java.util.List;

import org.junit.Test;
import org.junit.Before;
import org.junit.After;

import io.modelcontextprotocol.client.transport.HttpClientSseClientTransport;
import io.modelcontextprotocol.spec.McpClientTransport;
import io.modelcontextprotocol.spec.McpSchema.ListToolsResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import reva.RevaIntegrationTestBase;

/**
 * Integration test for MCP server port change functionality.
 * Tests that the server automatically restarts when the port configuration changes,
 * addressing issue #131.
 */
public class McpServerPortChangeIntegrationTest extends RevaIntegrationTestBase {

    private static final int ORIGINAL_PORT = 8080;
    private static final int NEW_PORT = 8955;
    private static final int CONNECTION_TIMEOUT = 2000;
    private static final int SERVER_RESTART_TIMEOUT = 8000;
    private static final int SERVER_STARTUP_TIMEOUT = 5000;
    
    private ConfigManager configManager;
    private int originalPort;

    @Before
    public void setUpPortChangeTest() throws Exception {
        configManager = reva.util.RevaInternalServiceRegistry.getService(ConfigManager.class);
        assertNotNull("ConfigManager should be registered", configManager);
        
        // Store original port for cleanup
        originalPort = configManager.getServerPort();
        
        // Ensure server is started on original port
        assertTrue("Server should be running initially", serverManager.isServerRunning());
        assertTrue("Server should be ready initially", serverManager.isServerReady());
    }

    @After
    public void tearDownPortChangeTest() throws Exception {
        // Restore original port configuration
        if (configManager != null && configManager.getServerPort() != originalPort) {
            configManager.setServerPort(originalPort);
            waitForServerRestart();
        }
    }

    /**
     * Main integration test: Verifies complete port change workflow
     * 1. Verify server is running on original port (8080)
     * 2. Change port to 8955 via ConfigManager
     * 3. Verify server restarts automatically
     * 4. Verify server is running on new port
     */
    @Test
    public void testMcpServerPortChange() throws Exception {
        // Step 1: Verify server is initially running
        assertTrue("Server should be running initially", serverManager.isServerRunning());
        assertTrue("Server should be ready initially", serverManager.isServerReady());
        assertEquals("Should be on original port", ORIGINAL_PORT, configManager.getServerPort());
        
        // Step 2: Change port configuration - this should trigger automatic restart
        configManager.setServerPort(NEW_PORT);
        
        // Step 3: Wait for server restart to complete
        waitForServerRestart();
        
        // Step 4: Verify server is running on new port
        assertTrue("Server should be running after port change", serverManager.isServerRunning());
        assertTrue("Server should be ready after port change", serverManager.isServerReady());
        assertEquals("Should be on new port", NEW_PORT, configManager.getServerPort());
        
        // Step 5: Verify port accessibility via simple HTTP check
        assertTrue("New port should be accessible", isPortAccessible(NEW_PORT));
    }

    /**
     * Test the server restart process in detail
     */
    @Test
    public void testServerRestartProcess() throws Exception {
        assertTrue("Server should be running initially", serverManager.isServerRunning());
        assertTrue("Server should be ready initially", serverManager.isServerReady());
        
        // Change port to trigger restart
        configManager.setServerPort(NEW_PORT + 1); // Use different port to avoid conflicts
        
        // Wait for restart to complete
        waitForServerRestart();
        
        // Verify restart completed successfully
        assertTrue("Server should be running after restart", serverManager.isServerRunning());
        assertTrue("Server should be ready after restart", serverManager.isServerReady());
        assertEquals("Port should be updated", NEW_PORT + 1, configManager.getServerPort());
    }

    /**
     * Test that tools remain available after port change
     */
    @Test
    public void testToolsAvailableAfterPortChange() throws Exception {
        // Get initial tool count via base class method
        ListToolsResult initialTools = getAvailableTools();
        int initialToolCount = initialTools.tools().size();
        assertTrue("Should have tools initially", initialToolCount > 0);
        
        // Change port
        configManager.setServerPort(NEW_PORT + 2); // Use different port to avoid conflicts
        waitForServerRestart();
        
        // Verify tools are still available (the base class getAvailableTools uses the shared config manager)
        ListToolsResult newTools = getAvailableTools();
        assertNotNull("Tools should be available after port change", newTools);
        assertTrue("Should still have tools after port change", newTools.tools().size() > 0);
        
        // Verify some key tool categories are still present
        List<String> toolNames = newTools.tools().stream()
            .map(Tool::name)
            .collect(java.util.stream.Collectors.toList());
        
        assertTrue("Should still have memory-related tools",
            toolNames.stream().anyMatch(name -> name.contains("memory")));
        assertTrue("Should still have function-related tools",
            toolNames.stream().anyMatch(name -> name.contains("function")));
    }

    /**
     * Verify that an MCP client can successfully connect to the server on the specified port
     */
    private boolean verifyClientConnectivity(int port) {
        try {
            McpClientTransport transport = createMcpTransportForPort(port);
            return withMcpClient(transport, client -> {
                client.initialize();
                ListToolsResult result = client.listTools(null);
                return result != null && result.tools() != null && !result.tools().isEmpty();
            });
        } catch (Exception e) {
            System.err.println("Failed to connect to MCP server on port " + port + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Verify that a port is no longer accessible
     */
    private boolean verifyPortInaccessible(int port) {
        // Try multiple times to ensure port is truly closed
        for (int i = 0; i < 3; i++) {
            if (isPortAccessible(port)) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            } else {
                return true;
            }
        }
        return false;
    }

    /**
     * Wait for server to be accessible on the specified port
     */
    private boolean waitForServerOnPort(int port, int timeoutMs) {
        long startTime = System.currentTimeMillis();
        System.out.println("Waiting for server on port " + port + " (timeout: " + timeoutMs + "ms)");
        
        while (System.currentTimeMillis() - startTime < timeoutMs) {
            boolean portAccessible = isPortAccessible(port);
            boolean clientConnects = portAccessible && verifyClientConnectivity(port);
            
            if (clientConnects) {
                System.out.println("Successfully connected to server on port " + port);
                return true;
            }
            
            if (System.currentTimeMillis() - startTime > timeoutMs / 2) {
                // Log status after half the timeout
                System.out.println("Still waiting for port " + port + " - accessible: " + portAccessible + ", connects: " + clientConnects);
            }
            
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        System.err.println("Timeout waiting for server on port " + port);
        return false;
    }

    /**
     * Wait for server restart to complete
     */
    private void waitForServerRestart() throws InterruptedException {
        long startTime = System.currentTimeMillis();
        
        // Wait for server state to stabilize
        while (System.currentTimeMillis() - startTime < SERVER_RESTART_TIMEOUT) {
            if (serverManager.isServerRunning() && serverManager.isServerReady()) {
                // Give it a bit more time to fully initialize
                Thread.sleep(500);
                return;
            }
            Thread.sleep(100);
        }
        
        throw new RuntimeException("Server restart did not complete within timeout");
    }

    /**
     * Check if a port is accessible via HTTP
     */
    private boolean isPortAccessible(int port) {
        try {
            URL url = URI.create("http://localhost:" + port + "/").toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(CONNECTION_TIMEOUT);
            conn.setReadTimeout(CONNECTION_TIMEOUT);
            
            int responseCode = conn.getResponseCode();
            conn.disconnect();
            
            // Any response code means the port is accessible
            return responseCode > 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Create MCP transport for a specific port
     */
    private McpClientTransport createMcpTransportForPort(int port) {
        String serverUrl = "http://localhost:" + port;
        return HttpClientSseClientTransport.builder(serverUrl)
            .sseEndpoint("/mcp/sse")
            .build();
    }

    /**
     * Get available tools using a specific port
     */
    private ListToolsResult getAvailableToolsByPort(int port) throws Exception {
        McpClientTransport transport = createMcpTransportForPort(port);
        return withMcpClient(transport, client -> {
            client.initialize();
            return client.listTools(null);
        });
    }
}