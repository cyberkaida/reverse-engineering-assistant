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
 * Verifies the public-binding consent guard in headless mode: refuse to start
 * when bound to a non-localhost interface without API key auth, unless the
 * allow-public-binding option is set. Uses random ports to avoid conflicts.
 */
public class PublicBindingGuardIntegrationTest {

    private McpServerManager manager;

    @After
    public void tearDown() {
        if (manager != null) {
            manager.shutdown();
            manager = null;
        }
    }

    @Test
    public void headlessRefusesPublicBindWithoutApiKey() throws Exception {
        ConfigManager config = new ConfigManager();
        config.setRandomAvailablePort();
        config.setServerHost("0.0.0.0");
        // API key disabled (default), allow-public-binding false (default)
        manager = new McpServerManager(config);
        manager.startServer();
        assertFalse("Server must NOT start on public bind without API key in headless",
            manager.isServerRunning());
    }

    @Test
    public void headlessProceedsWhenAllowPublicBindingSet() throws Exception {
        ConfigManager config = new ConfigManager();
        config.setRandomAvailablePort();
        config.setServerHost("0.0.0.0");
        config.setAllowPublicBindingWithoutApiKey(true);
        manager = new McpServerManager(config);
        manager.startServer();
        assertTrue("Server should start when public binding is explicitly allowed",
            manager.isServerRunning());
    }

    @Test
    public void headlessProceedsOnLocalhostWithoutApiKey() throws Exception {
        ConfigManager config = new ConfigManager();
        config.setRandomAvailablePort();
        config.setServerHost("127.0.0.1");
        manager = new McpServerManager(config);
        manager.startServer();
        assertTrue("Localhost bind without API key is fine", manager.isServerRunning());
    }

    @Test
    public void headlessProceedsOnPublicBindWithApiKey() throws Exception {
        ConfigManager config = new ConfigManager();
        config.setRandomAvailablePort();
        config.setServerHost("0.0.0.0");
        config.setApiKey("ReVa-test-key");
        config.setApiKeyEnabled(true);
        manager = new McpServerManager(config);
        manager.startServer();
        assertTrue("Public bind with API key auth is allowed", manager.isServerRunning());
    }
}
