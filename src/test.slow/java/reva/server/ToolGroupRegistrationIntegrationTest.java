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

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.junit.After;
import org.junit.Test;

import io.modelcontextprotocol.spec.McpSchema.Tool;
import reva.plugin.ConfigManager;
import reva.plugin.ToolGroup;
import reva.tools.ToolProvider;

/**
 * Verifies that disabled tool groups are not registered, and that toggling a
 * group at runtime adds/removes its tools live.
 */
public class ToolGroupRegistrationIntegrationTest {

    private McpServerManager manager;

    @After
    public void tearDown() {
        if (manager != null) {
            manager.shutdown();
            manager = null;
        }
    }

    private List<String> registeredToolNames(McpServerManager m) {
        return m.getToolProviders().stream()
            .flatMap(p -> ((reva.tools.AbstractToolProvider) p).getRegisteredTools().stream())
            .map(Tool::name)
            .collect(Collectors.toList());
    }

    @Test
    public void disabledScriptingGroupOmitsRunScript() {
        ConfigManager config = new ConfigManager();
        config.setToolGroupEnabled(ToolGroup.SCRIPTING, false);
        manager = new McpServerManager(config);

        List<String> names = registeredToolNames(manager);
        assertFalse("run-script should be absent when Scripting disabled", names.contains("run-script"));
        assertFalse("some tools should still be registered", names.isEmpty());
    }

    @Test
    public void allGroupsEnabledRegistersRunScript() {
        ConfigManager config = new ConfigManager();
        manager = new McpServerManager(config);
        assertTrue(registeredToolNames(manager).contains("run-script"));
    }

    @Test
    public void togglingScriptingGroupLiveAddsAndRemovesRunScript() {
        ConfigManager config = new ConfigManager();
        manager = new McpServerManager(config);
        assertTrue(registeredToolNames(manager).contains("run-script"));

        config.setToolGroupEnabled(ToolGroup.SCRIPTING, false);
        assertFalse("run-script removed after disabling group live",
            registeredToolNames(manager).contains("run-script"));

        config.setToolGroupEnabled(ToolGroup.SCRIPTING, true);
        assertTrue("run-script restored after re-enabling group live",
            registeredToolNames(manager).contains("run-script"));
    }

    /**
     * Stresses the CopyOnWriteArrayList iteration safety and final-state consistency:
     * one thread rapidly toggles the Scripting group while another continuously
     * snapshots and iterates the provider list. Asserts no exception escapes and that
     * the registered tools match the final group state. (The programOpened/programClosed
     * interleaving is closed separately by synchronizing those methods on the same
     * monitor as enableGroup/disableGroup, so it is not re-exercised here.)
     */
    @Test
    public void concurrentToggleAndIterationIsSafe() throws Exception {
        ConfigManager config = new ConfigManager();
        manager = new McpServerManager(config);

        final int iterations = 300;
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        final CountDownLatch done = new CountDownLatch(2);

        Thread reader = new Thread(() -> {
            try {
                for (int i = 0; i < iterations * 4; i++) {
                    for (ToolProvider p : manager.getToolProviders()) {
                        ((reva.tools.AbstractToolProvider) p).getRegisteredTools().size();
                    }
                }
            } catch (Throwable t) {
                failure.compareAndSet(null, t);
            } finally {
                done.countDown();
            }
        });

        Thread toggler = new Thread(() -> {
            try {
                for (int i = 0; i < iterations; i++) {
                    config.setToolGroupEnabled(ToolGroup.SCRIPTING, i % 2 == 0);
                }
            } catch (Throwable t) {
                failure.compareAndSet(null, t);
            } finally {
                done.countDown();
            }
        });

        reader.start();
        toggler.start();
        assertTrue("threads should finish", done.await(60, TimeUnit.SECONDS));
        assertNull("no exception under concurrent toggle/iterate: " + failure.get(), failure.get());

        boolean scriptingEnabled = config.isToolGroupEnabled(ToolGroup.SCRIPTING);
        boolean runScriptPresent = registeredToolNames(manager).contains("run-script");
        assertEquals("registered tools must match final group state",
            scriptingEnabled, runScriptPresent);
    }
}
