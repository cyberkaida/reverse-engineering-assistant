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

import ghidra.program.model.mem.Memory;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import reva.RevaHeadlessIntegrationTestBase;
import reva.util.RevaInternalServiceRegistry;

import java.util.List;

/**
 * Headless integration tests for RevaPlugin that test core functionality
 * without requiring a GUI tool environment.
 */
public class RevaPluginHeadlessIntegrationTest extends RevaHeadlessIntegrationTestBase {
    
    @Test
    public void testProgramManagement() throws Exception {
        assertNotNull("Program should be created", program);
        assertEquals("TestProgram", program.getName());
        
        // Verify program has memory
        Memory memory = program.getMemory();
        assertNotNull("Memory should exist", memory);
        assertTrue("Memory should have blocks", memory.getNumAddressRanges() > 0);
    }
    
    @Test
    public void testProgramManagerFunctionality() throws Exception {
        // RevaProgramManager uses static methods, so we'll test the static functionality
        // Since we're in a headless test, we won't have an active project, so just verify
        // that the methods don't throw exceptions
        
        List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
        assertNotNull("Open programs list should not be null", openPrograms);
        
        // In headless mode without a project, the list should be empty
        assertEquals("Should have no open programs in headless test", 0, openPrograms.size());
        
        // Test getting a program by path (should return null without a project)
        Program retrievedProgram = RevaProgramManager.getProgramByPath("/test/path");
        assertNull("Should return null for non-existent program in headless test", retrievedProgram);
    }
    
    @Test
    public void testSymbolCreation() throws Exception {
        SymbolTable symbolTable = program.getSymbolTable();
        Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
        
        int txId = program.startTransaction("Create Symbol");
        try {
            Symbol symbol = symbolTable.createLabel(addr, "test_function", SourceType.USER_DEFINED);
            assertNotNull("Symbol should be created", symbol);
            assertEquals("test_function", symbol.getName());
        } finally {
            program.endTransaction(txId, true);
        }
        
        // Verify symbol persists
        Symbol[] symbols = symbolTable.getSymbols(addr);
        assertTrue("Should have symbols at address", symbols.length > 0);
        
        boolean found = false;
        for (Symbol s : symbols) {
            if ("test_function".equals(s.getName())) {
                found = true;
                break;
            }
        }
        assertTrue("Should find our symbol", found);
    }
    
    @Test
    public void testFunctionCreation() throws Exception {
        FunctionManager functionManager = program.getFunctionManager();
        Address entryPoint = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000200);
        
        int txId = program.startTransaction("Create Function");
        try {
            // Create a simple function at the entry point
            // First add some bytes at the function location
            Memory memory = program.getMemory();
            byte[] retInstruction = new byte[] { (byte)0xc3 }; // x86 RET instruction
            memory.setBytes(entryPoint, retInstruction);
            
            // Create function with a simple body
            Function function = functionManager.createFunction(
                null, // Let Ghidra assign a default name first
                entryPoint, 
                functionManager.getFunctionContaining(entryPoint) == null ? 
                    new ghidra.program.model.address.AddressSet(entryPoint, entryPoint) : null,
                SourceType.USER_DEFINED
            );
            
            if (function != null) {
                // Now rename it
                function.setName("test_func", SourceType.USER_DEFINED);
            }
            
            assertNotNull("Function should be created", function);
            assertEquals("test_func", function.getName());
            assertEquals(entryPoint, function.getEntryPoint());
        } finally {
            program.endTransaction(txId, true);
        }
        
        // Verify function exists
        Function func = functionManager.getFunctionAt(entryPoint);
        assertNotNull("Function should exist at entry point", func);
        assertEquals("test_func", func.getName());
    }
    
    @Test
    public void testServiceRegistry() throws Exception {
        // Create a mock service implementation
        class TestService {
            public String getName() {
                return "TestService";
            }
        }
        
        TestService service = new TestService();
        
        // Register the service using the class as key
        RevaInternalServiceRegistry.registerService(TestService.class, service);
        
        // Retrieve the service
        TestService retrieved = RevaInternalServiceRegistry.getService(TestService.class);
        assertNotNull("Service should be retrievable", retrieved);
        assertEquals("TestService", retrieved.getName());
        
        // Clean up
        RevaInternalServiceRegistry.unregisterService(TestService.class);
        assertNull("Service should be removed", RevaInternalServiceRegistry.getService(TestService.class));
    }
}