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

import java.util.List;
import java.util.stream.Collectors;

import org.junit.After;
import org.junit.Test;

import io.modelcontextprotocol.spec.McpSchema.Tool;
import reva.plugin.ConfigManager;
import reva.plugin.ToolGroup;
import reva.tools.AbstractToolProvider;

/**
 * Verifies that the launcher's tool-group configuration (disable-list / enable-list)
 * is applied before the server registers tools.
 */
public class HeadlessLauncherToolGroupIntegrationTest {

    private RevaHeadlessLauncher launcher;

    @After
    public void tearDown() {
        if (launcher != null) {
            launcher.stop();
            launcher = null;
        }
    }

    private List<String> registeredToolNames() {
        return launcher.getServerManager().getToolProviders().stream()
            .flatMap(p -> ((AbstractToolProvider) p).getRegisteredTools().stream())
            .map(Tool::name)
            .collect(Collectors.toList());
    }

    @Test
    public void disabledListTurnsOffOnlyThoseGroups() throws Exception {
        launcher = new RevaHeadlessLauncher(null, true, true, null, null, null);
        launcher.setDisabledToolGroups("scripting");
        launcher.start();
        assertTrue(launcher.waitForServer(60000));

        ConfigManager config = launcher.getConfigManager();
        assertFalse(config.isToolGroupEnabled(ToolGroup.SCRIPTING));
        assertTrue(config.isToolGroupEnabled(ToolGroup.CORE_ANALYSIS));
        assertFalse("run-script must not be registered", registeredToolNames().contains("run-script"));
    }

    @Test
    public void enabledListIsAnAllowlist() throws Exception {
        launcher = new RevaHeadlessLauncher(null, true, true, null, null, null);
        launcher.setEnabledToolGroups("core-analysis");
        launcher.start();
        assertTrue(launcher.waitForServer(60000));

        ConfigManager config = launcher.getConfigManager();
        assertTrue(config.isToolGroupEnabled(ToolGroup.CORE_ANALYSIS));
        assertFalse(config.isToolGroupEnabled(ToolGroup.SCRIPTING));
        assertFalse(config.isToolGroupEnabled(ToolGroup.DIFF));
        assertFalse("run-script must not be registered", registeredToolNames().contains("run-script"));
    }

    @Test
    public void unknownGroupNameFailsLoudly() throws Exception {
        launcher = new RevaHeadlessLauncher(null, true, true, null, null, null);
        launcher.setDisabledToolGroups("scripting,bogus-group");
        try {
            launcher.start();
            fail("Expected start() to throw for an unknown tool group id");
        } catch (java.io.IOException e) {
            assertTrue("message should name the bad id: " + e.getMessage(),
                e.getMessage().toLowerCase().contains("bogus-group"));
        }
    }

    @Test
    public void specifyingBothListsIsAnError() throws Exception {
        launcher = new RevaHeadlessLauncher(null, true, true, null, null, null);
        launcher.setEnabledToolGroups("core-analysis");
        launcher.setDisabledToolGroups("scripting");
        try {
            launcher.start();
            fail("Expected start() to throw when both lists are specified");
        } catch (java.io.IOException e) {
            // expected
        }
    }
}
