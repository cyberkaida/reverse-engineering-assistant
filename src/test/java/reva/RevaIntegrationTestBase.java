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
package reva;

import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.test.TestEnv;
import ghidra.program.model.listing.Program;
import ghidra.framework.plugintool.PluginTool;

import org.junit.Before;
import org.junit.After;

import reva.plugin.RevaPlugin;

/**
 * Base class for ReVa integration tests that provides common test setup
 * and utility methods for testing with Ghidra programs and plugins.
 * This follows the same pattern as Ghidra's own plugin tests.
 */
public abstract class RevaIntegrationTestBase extends AbstractGhidraHeadedIntegrationTest {

    public TestEnv env;
    protected PluginTool tool;
    protected Program program;
    protected RevaPlugin plugin;

    @Before
    public void setUpRevaPlugin() throws Exception {
        // Create test environment - this will work if test resources are available
        if (env == null) {
            env = new TestEnv();
        }

        // Get the tool from the environment
        tool = env.getTool();

        // Create a program using the helper method from parent class
        program = createDefaultProgram(getName(), "x86:LE:32:default", this);

        // Add a memory block to the program for tests that expect it
        if (program.getMemory().getBlocks().length == 0) {
            int txId = program.startTransaction("Add test memory");
            try {
                program.getMemory().createInitializedBlock("test",
                    program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000),
                    0x1000, (byte) 0, ghidra.util.task.TaskMonitor.DUMMY, false);
            } finally {
                program.endTransaction(txId, true);
            }
        }

        // Add the ReVa plugin to the tool
        tool.addPlugin(RevaPlugin.class.getName());

        // Get the plugin instance
        for (ghidra.framework.plugintool.Plugin p : tool.getManagedPlugins()) {
            if (p instanceof RevaPlugin) {
                plugin = (RevaPlugin) p;
                break;
            }
        }

        if (plugin == null) {
            throw new RuntimeException("Failed to load RevaPlugin");
        }
    }

    @After
    public void tearDownRevaPlugin() throws Exception {
        // Clean up the test environment to prevent interference between tests
        if (env != null) {
            try {
                env.dispose();
            } catch (IllegalAccessError e) {
                // Ignore the module access error during cleanup
                // This is a known issue with Ghidra's test framework in Java 11+
            }
            env = null;
        }
        tool = null;
        program = null;
        plugin = null;
    }

}