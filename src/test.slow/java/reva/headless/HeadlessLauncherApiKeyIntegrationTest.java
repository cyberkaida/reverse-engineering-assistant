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
package reva.headless;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Test;

import reva.plugin.ConfigManager;

/**
 * Verifies that an API key supplied to the launcher enables authentication with
 * that exact key before the server starts.
 *
 * <p>Unlike the tool-provider integration tests, this class does not extend
 * {@code RevaIntegrationTestBase}: it drives {@link RevaHeadlessLauncher} directly,
 * which self-initializes Ghidra headlessly via {@code autoInitializeGhidra=true} and
 * needs no test {@code Program}. {@code forkEvery 1} gives each test class a fresh JVM,
 * so {@code Application.isInitialized()} is false at start and the launcher owns init.
 */
public class HeadlessLauncherApiKeyIntegrationTest {

    private RevaHeadlessLauncher launcher;

    @After
    public void tearDown() {
        if (launcher != null) {
            launcher.stop();
            launcher = null;
        }
    }

    @Test
    public void suppliedApiKeyEnablesAuth() throws Exception {
        launcher = new RevaHeadlessLauncher(null, true, true, null, null, "ReVa-unit-test-key");
        launcher.start();
        assertTrue(launcher.waitForServer(60000));

        ConfigManager config = launcher.getConfigManager();
        assertTrue("API key auth should be enabled", config.isApiKeyEnabled());
        assertEquals("ReVa-unit-test-key", config.getApiKey());
    }

    @Test
    public void nullApiKeyLeavesAuthDisabled() throws Exception {
        launcher = new RevaHeadlessLauncher(null, true, true, null, null, null);
        launcher.start();
        assertTrue(launcher.waitForServer(60000));
        assertFalse("API key auth stays disabled when no key supplied",
            launcher.getConfigManager().isApiKeyEnabled());
    }

    @Test
    public void emptyApiKeyLeavesAuthDisabled() throws Exception {
        launcher = new RevaHeadlessLauncher(null, true, true, null, null, "");
        launcher.start();
        assertTrue(launcher.waitForServer(60000));
        assertFalse("API key auth stays disabled when an empty key is supplied",
            launcher.getConfigManager().isApiKeyEnabled());
    }
}
