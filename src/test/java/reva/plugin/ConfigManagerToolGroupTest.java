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

public class ConfigManagerToolGroupTest {

    @Test
    public void allToolGroupsEnabledByDefault() {
        ConfigManager config = new ConfigManager();
        for (ToolGroup group : ToolGroup.values()) {
            assertTrue("Expected " + group + " enabled by default",
                config.isToolGroupEnabled(group));
        }
    }

    @Test
    public void toolGroupCanBeDisabledAndReEnabled() {
        ConfigManager config = new ConfigManager();
        config.setToolGroupEnabled(ToolGroup.SCRIPTING, false);
        assertFalse(config.isToolGroupEnabled(ToolGroup.SCRIPTING));
        assertTrue(config.isToolGroupEnabled(ToolGroup.CORE_ANALYSIS));
        config.setToolGroupEnabled(ToolGroup.SCRIPTING, true);
        assertTrue(config.isToolGroupEnabled(ToolGroup.SCRIPTING));
    }

    @Test
    public void allowPublicBindingDefaultsToFalse() {
        ConfigManager config = new ConfigManager();
        assertFalse(config.isAllowPublicBindingWithoutApiKey());
    }

    @Test
    public void allowPublicBindingIsConfigurable() {
        ConfigManager config = new ConfigManager();
        config.setAllowPublicBindingWithoutApiKey(true);
        assertTrue(config.isAllowPublicBindingWithoutApiKey());
    }
}
