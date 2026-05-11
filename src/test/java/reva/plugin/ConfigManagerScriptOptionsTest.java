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

import org.junit.Test;

/**
 * Tests for the script-execution-related options added to {@link ConfigManager}
 * to back the {@code run-script} tool: per-call timeout default and output
 * truncation cap.
 */
public class ConfigManagerScriptOptionsTest {

    @Test
    public void scriptTimeoutDefaultsTo60Seconds() {
        ConfigManager config = new ConfigManager();
        assertEquals(60, config.getScriptTimeoutSeconds());
    }

    @Test
    public void scriptOutputCharLimitDefaultsTo65536() {
        ConfigManager config = new ConfigManager();
        assertEquals(65536, config.getScriptOutputCharLimit());
    }

    @Test
    public void scriptTimeoutIsConfigurable() {
        ConfigManager config = new ConfigManager();
        config.setScriptTimeoutSeconds(120);
        assertEquals(120, config.getScriptTimeoutSeconds());
    }

    @Test
    public void scriptOutputCharLimitIsConfigurable() {
        ConfigManager config = new ConfigManager();
        config.setScriptOutputCharLimit(131072);
        assertEquals(131072, config.getScriptOutputCharLimit());
    }
}
