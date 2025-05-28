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

import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;

import org.junit.After;
import org.junit.Before;

import reva.plugin.RevaPlugin;

/**
 * Base class for ReVa integration tests that provides common test setup
 * and utility methods for testing with Ghidra programs and plugins.
 * This uses the headless test framework for faster test execution.
 */
public abstract class RevaIntegrationTestBase extends AbstractGhidraHeadlessIntegrationTest {
    
    protected TestEnv env;
    protected PluginTool tool;
    protected RevaPlugin plugin;
    protected Program program;
    
    @Before
    public void setUp() throws Exception {
        // Try to create a minimal test environment
        try {
            env = new TestEnv();
            
            // Get the default tool or create a minimal one
            tool = env.getTool();
            if (tool == null) {
                tool = env.launchDefaultTool();
            }
            
            // Add the ReVa plugin
            tool.addPlugin(RevaPlugin.class.getName());
            
            // Get the plugin instance
            for (ghidra.framework.plugintool.Plugin p : tool.getManagedPlugins()) {
                if (p instanceof RevaPlugin) {
                    plugin = (RevaPlugin) p;
                    break;
                }
            }
            
            // Create a test program
            program = createDefaultProgram();
            
            // Open the program in the tool
            if (program != null) {
                env.open(program);
            }
        } catch (Exception e) {
            // If TestEnv fails, try a simpler approach
            // This might happen in extension testing environments
            program = createDefaultProgram();
            // We'll test what we can without a full tool environment
        }
    }
    
    @After
    public void tearDown() throws Exception {
        if (env != null) {
            env.dispose();
        }
        
        if (program != null && program instanceof ProgramDB) {
            ((ProgramDB) program).release(this);
        }
        
        program = null;
        plugin = null;
        tool = null;
    }
    
    /**
     * Creates a default program for testing.
     * Subclasses can override this to customize the test program.
     * 
     * @return A new Program instance
     * @throws Exception if program creation fails
     */
    protected Program createDefaultProgram() throws Exception {
        Language language = getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        CompilerSpec compilerSpec = language.getDefaultCompilerSpec();
        ProgramDB testProgram = new ProgramDB("TestProgram", language, compilerSpec, this);
        
        // Add a memory block
        Memory memory = testProgram.getMemory();
        int txId = testProgram.startTransaction("Create Memory");
        try {
            memory.createInitializedBlock("test", 
                testProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000), 
                0x1000, (byte) 0, TaskMonitor.DUMMY, false);
        } finally {
            testProgram.endTransaction(txId, true);
        }
        
        return testProgram;
    }
}