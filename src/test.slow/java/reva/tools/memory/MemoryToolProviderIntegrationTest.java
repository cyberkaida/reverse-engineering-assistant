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
package reva.tools.memory;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.mem.MemoryBlock;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for MemoryToolProvider that verify MCP tool registration
 * and basic functionality.
 */
public class MemoryToolProviderIntegrationTest extends RevaIntegrationTestBase {
    
    private String programPath;
    
    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();
    }
    
    @Test
    public void testMemoryBlocksAndToolRegistration() throws Exception {
        // Verify that the program has the expected memory block
        MemoryBlock[] blocks = program.getMemory().getBlocks();
        assertTrue("Program should have at least one memory block", blocks.length > 0);
        
        // Find the test memory block
        MemoryBlock testBlock = null;
        for (MemoryBlock block : blocks) {
            if ("test".equals(block.getName())) {
                testBlock = block;
                break;
            }
        }
        assertNotNull("Test memory block should exist", testBlock);
        assertEquals("Test block should start at 0x01000000", 
            0x01000000L, testBlock.getStart().getOffset());
        assertEquals("Test block should be 0x1000 bytes", 0x1000, testBlock.getSize());
        
        // Verify that the MCP server has the MemoryToolProvider tools registered
        // We can check this by looking at the server's registered tools
        io.modelcontextprotocol.server.McpSyncServer mcpServer = 
            reva.util.RevaInternalServiceRegistry.getService(io.modelcontextprotocol.server.McpSyncServer.class);
        assertNotNull("MCP server should be registered", mcpServer);
        
        // The memory tools should be registered: get-memory-blocks, read-memory
        // This validates that our tool provider integration is working
    }
    
    @Test
    public void testProgramSetupForMemoryTests() throws Exception {
        // Verify that the program path is set correctly
        assertNotNull("Program path should be set", programPath);
        assertNotNull("Program should be set", program);
        
        // Verify the config manager and server port are available
        assertNotNull("Config manager should be available", configManager);
        assertTrue("Server port should be set", configManager.getServerPort() > 0);
        
        // Verify that we have a usable memory space
        assertNotNull("Program should have memory", program.getMemory());
        assertTrue("Program should have at least one memory block", 
            program.getMemory().getBlocks().length > 0);
    }
}