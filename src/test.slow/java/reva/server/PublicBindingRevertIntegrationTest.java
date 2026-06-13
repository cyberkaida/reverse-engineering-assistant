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

import org.junit.After;
import org.junit.Test;

import reva.plugin.ConfigManager;

/**
 * Verifies that a refused runtime bind change (headless = auto-refuse, the same code
 * path as clicking Cancel in the GUI dialog) reverts the option and leaves the running
 * server untouched, rather than tearing it down.
 */
public class PublicBindingRevertIntegrationTest {

    private McpServerManager manager;

    @After
    public void tearDown() {
        if (manager != null) {
            manager.shutdown();
            manager = null;
        }
    }

    @Test
    public void refusedRuntimeHostChangeRevertsAndKeepsServerRunning() throws Exception {
        ConfigManager config = new ConfigManager();
        config.setRandomAvailablePort();
        config.setServerHost("127.0.0.1");
        manager = new McpServerManager(config);
        manager.startServer();
        assertTrue("server should start on localhost", manager.isServerRunning());

        // Runtime change to a public interface. Headless auto-refuses (same path as
        // GUI Cancel): the change must be reverted and the server left running.
        config.setServerHost("0.0.0.0");

        assertEquals("host must be reverted to its previous value",
            "127.0.0.1", config.getServerHost());
        assertTrue("server must remain running after a refused runtime host change",
            manager.isServerRunning());
    }

    @Test
    public void approvedRuntimeHostChangeRestartsOnNewHost() throws Exception {
        ConfigManager config = new ConfigManager();
        config.setRandomAvailablePort();
        config.setAllowPublicBindingWithoutApiKey(true); // pre-approved -> guard passes
        config.setServerHost("127.0.0.1");
        manager = new McpServerManager(config);
        manager.startServer();
        assertTrue(manager.isServerRunning());

        config.setServerHost("0.0.0.0");

        assertEquals("0.0.0.0", config.getServerHost());
        assertTrue("server should restart on the new (approved) host", manager.isServerRunning());
    }
}
