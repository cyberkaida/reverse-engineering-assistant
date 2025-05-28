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

import ghidra.test.AbstractProgramBasedTest;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import ghidra.program.model.listing.Program;

import org.junit.Before;

import reva.plugin.RevaPlugin;

/**
 * Base class for ReVa integration tests that provides common test setup
 * and utility methods for testing with Ghidra programs and plugins.
 * This uses the AbstractProgramBasedTest framework.
 */
public abstract class RevaIntegrationTestBase extends AbstractProgramBasedTest {
    
    protected RevaPlugin plugin;
    
    @Override
    protected Program getProgram() throws Exception {
        ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
        return builder.getProgram();
    }
    
    @Before
    public void setUpRevaPlugin() throws Exception {
        // Initialize the base test (creates env, tool, program)
        initialize();
        
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
    
}