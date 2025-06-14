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
package reva.tools.decompiler;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import reva.RevaIntegrationTestBase;

/**
 * Test that the decompiler tool properly limits incoming references
 */
public class DecompilerIncomingReferencesLimitTest extends RevaIntegrationTestBase {

    private String programPath;
    private Address targetFunctionAddr;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();
        
        // Create a target function that will have many incoming references
        targetFunctionAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01001000);
        
        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager refManager = program.getReferenceManager();
        
        int txId = program.startTransaction("Create Test Functions");
        try {
            // Create the target function
            functionManager.createFunction("popularFunction", targetFunctionAddr,
                new AddressSet(targetFunctionAddr, targetFunctionAddr.add(50)), SourceType.USER_DEFINED);
            
            // Create 15 calling functions (more than the limit of 10)
            for (int i = 0; i < 15; i++) {
                Address callerAddr = program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(0x01002000 + i * 0x100);
                
                // Create calling function
                functionManager.createFunction("caller_" + i, callerAddr,
                    new AddressSet(callerAddr, callerAddr.add(20)), SourceType.USER_DEFINED);
                
                // Add reference to the popular function
                refManager.addMemoryReference(callerAddr.add(0x10), targetFunctionAddr, 
                    RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
            }
        } finally {
            program.endTransaction(txId, true);
        }
        
        // Open the program in the tool's ProgramManager
        env.open(program);
    }

    @Test
    public void testIncomingReferencesLimit() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                // Get decompilation with incoming references
                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-decompilation",
                    Map.of(
                        "programPath", programPath,
                        "functionNameOrAddress", "popularFunction",
                        "includeIncomingReferences", true
                    )
                ));
                
                assertFalse("Tool should not have errors", result.isError());
                
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());
                
                // Check that incoming references are limited
                JsonNode incomingRefs = jsonResult.get("incomingReferences");
                assertNotNull("Should have incoming references", incomingRefs);
                
                // Should have exactly 10 references (the limit)
                assertEquals(10, incomingRefs.size());
                
                // Check the metadata
                assertEquals(true, jsonResult.get("incomingReferencesLimited").asBoolean());
                assertEquals(15, jsonResult.get("totalIncomingReferences").asInt());
                
                // Check the message
                String message = jsonResult.get("incomingReferencesMessage").asText();
                assertNotNull("Should have a message about limited references", message);
                assertTrue(message.contains("Showing first 10 of 15 references"));
                assertTrue(message.contains("find-cross-references"));
                assertTrue(message.contains("popularFunction"));
                
                // Verify all 10 are actual references
                for (int i = 0; i < 10; i++) {
                    JsonNode ref = incomingRefs.get(i);
                    assertTrue(ref.get("fromAddress").asText().startsWith("0x"));
                    assertEquals("UNCONDITIONAL_CALL", ref.get("referenceType").asText());
                }
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testIncomingReferencesNotLimited() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                // Create a function with fewer incoming references
                int txId = program.startTransaction("Create Small Function");
                Address smallFuncAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01003000);
                try {
                    FunctionManager functionManager = program.getFunctionManager();
                    ReferenceManager refManager = program.getReferenceManager();
                    
                    functionManager.createFunction("smallFunction", smallFuncAddr,
                        new AddressSet(smallFuncAddr, smallFuncAddr.add(30)), SourceType.USER_DEFINED);
                    
                    // Add only 3 references (under the limit)
                    for (int i = 0; i < 3; i++) {
                        Address refAddr = program.getAddressFactory().getDefaultAddressSpace()
                            .getAddress(0x01002000 + i * 0x100);
                        refManager.addMemoryReference(refAddr.add(0x15), smallFuncAddr, 
                            RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
                    }
                } finally {
                    program.endTransaction(txId, true);
                }
                
                // Get decompilation with incoming references
                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-decompilation",
                    Map.of(
                        "programPath", programPath,
                        "functionNameOrAddress", "smallFunction",
                        "includeIncomingReferences", true
                    )
                ));
                
                assertFalse("Tool should not have errors", result.isError());
                
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());
                
                // Check that incoming references are NOT limited
                JsonNode incomingRefs = jsonResult.get("incomingReferences");
                assertNotNull("Should have incoming references", incomingRefs);
                assertEquals(3, incomingRefs.size());
                
                // Should not have the limited flag when under the limit
                assertNull("Should not have incomingReferencesLimited flag", jsonResult.get("incomingReferencesLimited"));
                assertNull("Should not have limitation message", jsonResult.get("incomingReferencesMessage"));
                assertEquals(3, jsonResult.get("totalIncomingReferences").asInt());
                
                // All should be actual references
                for (JsonNode ref : incomingRefs) {
                    assertTrue(ref.get("fromAddress").asText().startsWith("0x"));
                    assertEquals("UNCONDITIONAL_CALL", ref.get("referenceType").asText());
                }
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }
}