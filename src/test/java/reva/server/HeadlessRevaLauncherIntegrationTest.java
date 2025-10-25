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
package reva.server;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import reva.RevaHeadlessIntegrationTestBase;
import reva.plugin.RevaProgramManager;

/**
 * Integration tests for HeadlessRevaLauncher.
 * Tests the full lifecycle of the headless MCP server including startup, program management, and shutdown.
 */
public class HeadlessRevaLauncherIntegrationTest extends RevaHeadlessIntegrationTestBase {

    private HeadlessRevaLauncher launcher;
    private static final int TEST_PORT = 18080; // Use non-standard port to avoid conflicts
    private static final String TEST_HOST = "127.0.0.1";

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        // Clean up any existing services
        RevaProgramManager.cleanup();

        // Create launcher with test port
        launcher = new HeadlessRevaLauncher(TEST_HOST, TEST_PORT);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        // Shutdown launcher if still running
        if (launcher != null) {
            try {
                launcher.shutdown();
            } catch (Exception e) {
                Msg.error(this, "Error shutting down launcher in tearDown", e);
            }
            launcher = null;
        }

        // Clean up program manager
        RevaProgramManager.cleanup();

        super.tearDown();
    }

    @Test
    public void testLauncherCreation() {
        assertNotNull("Launcher should be created", launcher);
        assertNull("Server manager should not be initialized before launch", launcher.getServerManager());
    }

    @Test
    public void testServerLaunch() {
        // Launch the server
        launcher.launch();

        // Verify server is ready
        assertTrue("Server should be ready after launch", launcher.isServerReady());
        assertNotNull("Server manager should be initialized", launcher.getServerManager());

        HeadlessMcpServerManager serverManager = launcher.getServerManager();
        assertTrue("Server manager should be ready", serverManager.isServerReady());
        assertEquals("Server should be on test port", TEST_PORT, serverManager.getServerPort());
        assertEquals("Server should be on test host", TEST_HOST, serverManager.getServerHost());
    }

    @Test
    public void testServerHttpEndpoint() throws Exception {
        // Launch the server
        launcher.launch();
        assertTrue("Server should be ready", launcher.isServerReady());

        // Try to connect to the HTTP endpoint
        String baseUrl = "http://" + TEST_HOST + ":" + TEST_PORT;
        URL url = new URI(baseUrl + "/mcp/message").toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);

        try {
            int responseCode = connection.getResponseCode();
            // We expect 405 (Method Not Allowed) because GET is not supported for MCP endpoint
            // The important thing is that the server is listening
            assertTrue("Server should respond (even if with error)",
                responseCode == HttpURLConnection.HTTP_BAD_METHOD ||
                responseCode == HttpURLConnection.HTTP_OK ||
                responseCode == HttpURLConnection.HTTP_NOT_FOUND);
        } finally {
            connection.disconnect();
        }
    }

    @Test
    public void testProgramRegistration() {
        // Launch server
        launcher.launch();
        assertTrue("Server should be ready", launcher.isServerReady());

        // Register our test program
        launcher.getServerManager().registerProgram(program);

        // Verify program is in the program manager
        List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
        assertTrue("Should have at least one open program", openPrograms.size() > 0);

        boolean found = false;
        for (Program p : openPrograms) {
            if (p.getName().equals(program.getName())) {
                found = true;
                break;
            }
        }
        assertTrue("Test program should be registered", found);
    }

    @Test
    public void testProgramUnregistration() {
        // Launch server
        launcher.launch();
        assertTrue("Server should be ready", launcher.isServerReady());

        // Register program
        launcher.getServerManager().registerProgram(program);
        List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
        assertTrue("Should have open program after registration", openPrograms.size() > 0);

        // Unregister program
        launcher.getServerManager().unregisterProgram(program);

        // Verify program is removed (in headless mode, it should be fully removed)
        // Note: In GUI mode it might still be cached, but headless mode should clean up
        openPrograms = RevaProgramManager.getOpenPrograms();
        boolean stillFound = false;
        for (Program p : openPrograms) {
            if (p == program) { // Use identity comparison
                stillFound = true;
                break;
            }
        }
        assertFalse("Test program should be unregistered", stillFound);
    }

    @Test
    public void testMultipleProgramRegistration() {
        // Launch server
        launcher.launch();
        assertTrue("Server should be ready", launcher.isServerReady());

        // Create additional test programs
        Program program2 = null;
        Program program3 = null;

        try {
            program2 = createDefaultProgram();
            program3 = createDefaultProgram();

            // Register all programs
            launcher.getServerManager().registerProgram(program);
            launcher.getServerManager().registerProgram(program2);
            launcher.getServerManager().registerProgram(program3);

            // Verify all are registered
            List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
            assertTrue("Should have at least 3 programs", openPrograms.size() >= 3);

        } catch (Exception e) {
            fail("Failed to create additional test programs: " + e.getMessage());
        } finally {
            // Clean up additional programs
            if (program2 != null) {
                launcher.getServerManager().unregisterProgram(program2);
                program2.release(this);
            }
            if (program3 != null) {
                launcher.getServerManager().unregisterProgram(program3);
                program3.release(this);
            }
        }
    }

    @Test
    public void testServerShutdown() {
        // Launch server
        launcher.launch();
        assertTrue("Server should be ready after launch", launcher.isServerReady());

        // Shutdown
        launcher.shutdown();

        // Verify shutdown
        assertFalse("Server should not be ready after shutdown", launcher.isServerReady());

        // Verify we can't connect anymore
        try {
            String baseUrl = "http://" + TEST_HOST + ":" + TEST_PORT;
            URL url = new URI(baseUrl + "/mcp/message").toURL();
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(1000);
            connection.setReadTimeout(1000);

            // This should throw IOException because server is down
            connection.getResponseCode();
            fail("Should not be able to connect to shutdown server");
        } catch (IOException e) {
            // Expected - server is down
        } catch (Exception e) {
            // Also acceptable - server is down
        }
    }

    @Test
    public void testServerRestartability() {
        // Launch server
        launcher.launch();
        assertTrue("Server should be ready after first launch", launcher.isServerReady());

        // Shutdown
        launcher.shutdown();
        assertFalse("Server should not be ready after shutdown", launcher.isServerReady());

        // Create new launcher and launch again
        launcher = new HeadlessRevaLauncher(TEST_HOST, TEST_PORT);
        launcher.launch();

        assertTrue("Server should be ready after relaunch", launcher.isServerReady());
    }

    @Test
    public void testGetOpenProgramsEmpty() {
        // Launch server without registering any programs
        launcher.launch();
        assertTrue("Server should be ready", launcher.isServerReady());

        List<Program> openPrograms = launcher.getOpenPrograms();
        assertNotNull("Open programs list should not be null", openPrograms);
        assertEquals("Should have no open programs initially", 0, openPrograms.size());
    }

    @Test
    public void testGetOpenProgramsWithPrograms() {
        // Launch server
        launcher.launch();
        assertTrue("Server should be ready", launcher.isServerReady());

        // Register program
        launcher.getServerManager().registerProgram(program);

        List<Program> openPrograms = launcher.getOpenPrograms();
        assertNotNull("Open programs list should not be null", openPrograms);
        assertTrue("Should have at least one program", openPrograms.size() > 0);
    }

    @Test(timeout = 10000) // 10 second timeout
    public void testServerStartupPerformance() {
        long startTime = System.currentTimeMillis();

        launcher.launch();
        assertTrue("Server should be ready", launcher.isServerReady());

        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;

        // Server should start within 10 seconds (usually much faster)
        assertTrue("Server startup should be reasonably fast (< 10s), took " + duration + "ms",
            duration < 10000);

        Msg.info(this, "Server startup took " + duration + "ms");
    }

    @Test
    public void testPortConflictHandling() {
        // Launch first server
        launcher.launch();
        assertTrue("First server should be ready", launcher.isServerReady());

        // Try to launch second server on same port
        HeadlessRevaLauncher launcher2 = new HeadlessRevaLauncher(TEST_HOST, TEST_PORT);

        try {
            launcher2.launch();

            // If we get here, check if second server actually started
            // It should fail or the first server should still be the one running
            // This behavior depends on the OS and how Jetty handles port conflicts

            // At minimum, the first server should still be running
            assertTrue("First server should still be running", launcher.isServerReady());

        } catch (Exception e) {
            // This is acceptable - port conflict should cause an error
            Msg.info(this, "Port conflict handled correctly: " + e.getMessage());
        } finally {
            if (launcher2 != null) {
                try {
                    launcher2.shutdown();
                } catch (Exception e) {
                    // Ignore cleanup errors
                }
            }
        }
    }
}
