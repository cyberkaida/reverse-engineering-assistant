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

import org.junit.Test;
import org.junit.Before;
import org.junit.After;

import reva.RevaIntegrationTestBase;
import reva.util.ConfigManager;

/**
 * Integration tests for the MCP server functionality in RevaPlugin
 */
public class RevaPluginMcpIntegrationTest extends RevaIntegrationTestBase {
    
    private ConfigManager configManager;
    
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        
        if (tool != null) {
            // Get the config manager from the tool
            configManager = new ConfigManager(tool);
            configManager.setServerEnabled(true);
            configManager.setServerPort(8085); // Use a different port to avoid conflicts
        }
    }
    
    @After
    @Override  
    public void tearDown() throws Exception {
        // Disable server before cleanup
        if (configManager != null) {
            configManager.setServerEnabled(false);
        }
        super.tearDown();
    }
    
    @Test
    public void testMcpServerStarts() throws Exception {
        if (configManager == null) {
            System.out.println("Skipping testMcpServerStarts - tool environment not available");
            return;
        }
        
        // Give the server time to start
        Thread.sleep(2000);
        
        // Check if we can connect to the server
        int port = configManager.getServerPort();
        URL url = new URL("http://localhost:" + port + "/");
        
        try {
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            
            int responseCode = connection.getResponseCode();
            
            // The MCP server should respond with something (even if it's an error for GET)
            // We're just checking that it's listening
            assertTrue("Server should be responding", responseCode > 0);
            
        } catch (Exception e) {
            fail("Should be able to connect to MCP server: " + e.getMessage());
        }
    }
    
    @Test
    public void testServerConfiguration() {
        if (configManager == null) {
            System.out.println("Skipping testServerConfiguration - tool environment not available");
            return;
        }
        
        assertTrue("Server should be enabled", configManager.isServerEnabled());
        assertEquals("Server port should match", 8085, configManager.getServerPort());
    }
}