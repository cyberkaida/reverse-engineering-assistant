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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;

/**
 * Unit coverage for {@link ConfigManager#setRandomAvailablePort()}, the mechanism the
 * integration test base uses so tests don't collide with a dev/dogfooding server on 8080.
 */
public class ConfigManagerPortTest {

    @Test
    public void defaultServerPortIs8080() {
        ConfigManager cm = new ConfigManager(); // in-memory backend, no Ghidra env
        assertEquals(8080, cm.getServerPort());
    }

    @Test
    public void setRandomAvailablePortPicksAFreePortAndUpdatesGetter() throws IOException {
        ConfigManager cm = new ConfigManager();
        int port = cm.setRandomAvailablePort();
        assertEquals("getServerPort() must reflect the randomized port", port, cm.getServerPort());
        assertTrue("port must be in the valid TCP range, was " + port, port > 0 && port <= 65535);
        // ServerSocket(0) draws from the ephemeral range and never returns the default 8080,
        // so a random port is always distinct from the default the tests must avoid.
        assertNotEquals("random port must differ from the default 8080", 8080, port);
    }
}
