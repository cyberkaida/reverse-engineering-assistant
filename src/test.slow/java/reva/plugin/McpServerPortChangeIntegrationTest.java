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
    private static final int CONNECTION_TIMEOUT = 5000;
    private static final int SERVER_RESTART_TIMEOUT = 20000;
    private static final int SERVER_STARTUP_TIMEOUT = 15000;
    
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
     * 1. Connect to server on original port (8080)
     * 2. Change port to 8955 via ConfigManager
     * 3. Verify server restarts automatically
     * 4. Verify old port becomes inaccessible  
     * 5. Verify new port becomes accessible
     * 6. Verify tools are still available after restart
     */
    @Test
    public void testMcpServerPortChange() throws Exception {
        // Step 1: Wait for server to be fully ready and verify initial connectivity
        assertTrue("Should be able to wait for server on original port " + ORIGINAL_PORT,
                   waitForServerOnPort(ORIGINAL_PORT, SERVER_STARTUP_TIMEOUT));
        assertTrue("Should be able to connect to server on original port " + ORIGINAL_PORT, 
                   verifyClientConnectivity(ORIGINAL_PORT));
        
        // Get initial tool list for comparison
        ListToolsResult originalTools = getAvailableToolsByPort(ORIGINAL_PORT);
        assertNotNull("Should have tools available on original port", originalTools);
        assertTrue("Should have multiple tools registered", originalTools.tools().size() > 5);
        
        // Step 2: Change port configuration - this should trigger automatic restart
        configManager.setServerPort(NEW_PORT);
        
        // Step 3: Wait for server restart to complete
        waitForServerRestart();
        
        // Step 4: Verify old port is no longer accessible
        assertTrue("Old port " + ORIGINAL_PORT + " should no longer be accessible", 
                   verifyPortInaccessible(ORIGINAL_PORT));
        
        // Step 5: Verify new port is accessible
        assertTrue("Should be able to connect to server on new port " + NEW_PORT,
                   waitForServerOnPort(NEW_PORT, SERVER_STARTUP_TIMEOUT));
        assertTrue("Should be able to establish MCP client connection on new port",
                   verifyClientConnectivity(NEW_PORT));
        
        // Step 6: Verify tools are available after port change
        ListToolsResult newTools = getAvailableToolsByPort(NEW_PORT);
        assertNotNull("Should have tools available on new port", newTools);
        assertEquals("Should have same number of tools after port change", 
                     originalTools.tools().size(), newTools.tools().size());
        
        // Verify tool names are preserved
        List<String> originalToolNames = originalTools.tools().stream()
            .map(Tool::name)
            .sorted()
            .collect(java.util.stream.Collectors.toList());
        List<String> newToolNames = newTools.tools().stream()
            .map(Tool::name)
            .sorted()
            .collect(java.util.stream.Collectors.toList());
        
        assertEquals("Tool names should be preserved after port change", 
                     originalToolNames, newToolNames);
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
        
        // Monitor server state during restart
        long startTime = System.currentTimeMillis();
        boolean sawServerDown = false;
        boolean restartCompleted = false;
        
        while (System.currentTimeMillis() - startTime < SERVER_RESTART_TIMEOUT) {
            boolean isRunning = serverManager.isServerRunning();
            boolean isReady = serverManager.isServerReady();
            
            if (!isRunning || !isReady) {
                sawServerDown = true;
            }
            
            if (sawServerDown && isRunning && isReady) {
                restartCompleted = true;
                break;
            }
            
            Thread.sleep(100);
        }
        
        assertTrue("Should have seen server go down during restart", sawServerDown);
        assertTrue("Server restart should complete within timeout", restartCompleted);
        assertTrue("Server should be running after restart", serverManager.isServerRunning());
        assertTrue("Server should be ready after restart", serverManager.isServerReady());
    }

    /**
     * Test that tools remain available after port change
     */
    @Test
    public void testToolsAvailableAfterPortChange() throws Exception {
        // Get initial tool count
        ListToolsResult initialTools = getAvailableTools();
        int initialToolCount = initialTools.tools().size();
        assertTrue("Should have tools initially", initialToolCount > 0);
        
        // Change port
        configManager.setServerPort(NEW_PORT + 2); // Use different port to avoid conflicts
        waitForServerRestart();
        
        // Verify tools are still available
        ListToolsResult newTools = getAvailableToolsByPort(NEW_PORT + 2);
        assertNotNull("Tools should be available after port change", newTools);
        assertEquals("Tool count should be preserved", initialToolCount, newTools.tools().size());
        
        // Verify specific tool categories are still present
        List<String> toolNames = newTools.tools().stream()
            .map(Tool::name)
            .collect(java.util.stream.Collectors.toList());
        
        assertTrue("Should still have memory-related tools",
            toolNames.stream().anyMatch(name -> name.contains("memory")));
        assertTrue("Should still have function-related tools",
            toolNames.stream().anyMatch(name -> name.contains("function")));
        assertTrue("Should still have string-related tools",
            toolNames.stream().anyMatch(name -> name.contains("string")));
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
                    Thread.sleep(500);
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
                Thread.sleep(500);
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
                Thread.sleep(1000);
                return;
            }
            Thread.sleep(200);
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