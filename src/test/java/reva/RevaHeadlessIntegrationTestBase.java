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

/**
 * Base class for ReVa headless integration tests that don't require a GUI tool.
 * This is a simpler alternative that just tests with programs directly.
 */
public abstract class RevaHeadlessIntegrationTestBase extends AbstractGhidraHeadlessIntegrationTest {
    
    protected Program program;
    
    @Before
    public void setUp() throws Exception {
        // Create a test program
        program = createDefaultProgram();
    }
    
    @After
    public void tearDown() throws Exception {
        if (program != null && program instanceof ProgramDB) {
            ((ProgramDB) program).release(this);
        }
        program = null;
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