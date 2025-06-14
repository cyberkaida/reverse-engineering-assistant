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
package reva.tools.xrefs;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import reva.RevaIntegrationTestBase;

/**
 * Integration tests for CrossReferencesToolProvider
 */
public class CrossReferencesToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;
    private Address mainAddr;
    private Address helperAddr;
    private Address utilityAddr;
    private Address stringAddr;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();
        
        // Use addresses within the existing memory block (base class creates block at 0x01000000)
        mainAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01001000);
        helperAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01002000);
        utilityAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01003000);
        stringAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01004000);
        
        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager refManager = program.getReferenceManager();
        
        int txId = program.startTransaction("Create Test Functions and References");
        try {
            // Create functions
            functionManager.createFunction("main", mainAddr,
                new AddressSet(mainAddr, mainAddr.add(100)), SourceType.USER_DEFINED);
            functionManager.createFunction("helper", helperAddr,
                new AddressSet(helperAddr, helperAddr.add(50)), SourceType.USER_DEFINED);
            functionManager.createFunction("utility", utilityAddr,
                new AddressSet(utilityAddr, utilityAddr.add(30)), SourceType.USER_DEFINED);
            
            // Create string data
            try {
                program.getMemory().setBytes(stringAddr, "Hello World\0".getBytes());
                program.getListing().createData(stringAddr, 
                    ghidra.program.model.data.StringDataType.dataType);
            } catch (Exception e) {
                // If we can't create string data, just continue without it
                // Some test environments may not support this
            }
            
            // Create references
            // main calls helper
            refManager.addMemoryReference(mainAddr.add(0x10), helperAddr, 
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
            // main calls utility
            refManager.addMemoryReference(mainAddr.add(0x20), utilityAddr, 
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
            // helper calls utility
            refManager.addMemoryReference(helperAddr.add(0x10), utilityAddr, 
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
            // main references string
            refManager.addMemoryReference(mainAddr.add(0x30), stringAddr, 
                RefType.DATA, SourceType.USER_DEFINED, 0);
            // helper references string
            refManager.addMemoryReference(helperAddr.add(0x20), stringAddr, 
                RefType.DATA, SourceType.USER_DEFINED, 0);
        } finally {
            program.endTransaction(txId, true);
        }
        
        // Open the program in the tool's ProgramManager so it can be found by RevaProgramManager
        env.open(program);
    }

    @Test
    public void testFindCrossReferencesToFunction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                CallToolResult result = client.callTool(new CallToolRequest(
                    "find-cross-references",
                    Map.of(
                        "programPath", programPath,
                        "location", "utility",
                        "direction", "to"
                    )
                ));
                
                assertFalse("Tool should not have errors", result.isError());
                assertEquals(1, result.content().size());
                
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());
                
                // Check location info
                JsonNode location = jsonResult.get("location");
                assertEquals("0x01003000", location.get("address").asText());
                assertEquals("utility", location.get("symbol").asText());
                assertEquals("utility", location.get("function").asText());
                assertEquals(true, location.get("isFunctionEntry").asBoolean());
                
                // Check references to utility (should be from main and helper)
                JsonNode refsTo = jsonResult.get("referencesTo");
                assertEquals(2, refsTo.size());
                
                // Verify references are from main and helper
                boolean foundFromMain = false;
                boolean foundFromHelper = false;
                
                for (JsonNode ref : refsTo) {
                    assertEquals("0x01003000", ref.get("toAddress").asText());
                    assertEquals("UNCONDITIONAL_CALL", ref.get("referenceType").asText());
                    assertEquals(true, ref.get("isCall").asBoolean());
                    
                    JsonNode fromFunc = ref.get("fromFunction");
                    if ("main".equals(fromFunc.get("name").asText())) {
                        foundFromMain = true;
                        assertEquals("0x01001020", ref.get("fromAddress").asText());
                    } else if ("helper".equals(fromFunc.get("name").asText())) {
                        foundFromHelper = true;
                        assertEquals("0x01002010", ref.get("fromAddress").asText());
                    }
                }
                
                assertTrue("Should find reference from main", foundFromMain);
                assertTrue("Should find reference from helper", foundFromHelper);
                
                // Check that references from is empty (direction was "to")
                JsonNode refsFrom = jsonResult.get("referencesFrom");
                assertEquals(0, refsFrom.size());
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testFindCrossReferencesFromFunction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                CallToolResult result = client.callTool(new CallToolRequest(
                    "find-cross-references",
                    Map.of(
                        "programPath", programPath,
                        "location", mainAddr.toString(),
                        "direction", "from"
                    )
                ));
                
                assertFalse("Tool should not have errors", result.isError());
                
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());
                
                // Check references from main
                JsonNode refsFrom = jsonResult.get("referencesFrom");
                assertEquals(3, refsFrom.size()); // Calls to helper, utility, and data ref to string
                
                // Count reference types
                int callCount = 0;
                int dataCount = 0;
                
                for (JsonNode ref : refsFrom) {
                    String fromAddr = ref.get("fromAddress").asText();
                    // Check that it's from the main function range
                    assertTrue("Address should be from main function", 
                        fromAddr.startsWith("0x0100100") || fromAddr.startsWith("0x0100101") || 
                        fromAddr.startsWith("0x0100102") || fromAddr.startsWith("0x0100103"));
                    
                    if ("UNCONDITIONAL_CALL".equals(ref.get("referenceType").asText())) {
                        callCount++;
                        JsonNode toSymbol = ref.get("toSymbol");
                        String toName = toSymbol.get("name").asText();
                        assertTrue("helper".equals(toName) || "utility".equals(toName));
                    } else if ("DATA".equals(ref.get("referenceType").asText())) {
                        dataCount++;
                        assertEquals("0x01004000", ref.get("toAddress").asText());
                    }
                }
                
                assertEquals(2, callCount);
                assertEquals(1, dataCount);
                
                // Check that references to is empty (direction was "from")
                JsonNode refsTo = jsonResult.get("referencesTo");
                assertEquals(0, refsTo.size());
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testFindCrossReferencesBothDirections() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                CallToolResult result = client.callTool(new CallToolRequest(
                    "find-cross-references",
                    Map.of(
                        "programPath", programPath,
                        "location", stringAddr.toString(), // String address
                        "direction", "both"
                    )
                ));
                
                assertFalse("Tool should not have errors", result.isError());
                
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());
                
                // Check references to string (from main and helper)
                JsonNode refsTo = jsonResult.get("referencesTo");
                assertEquals(2, refsTo.size());
                
                for (JsonNode ref : refsTo) {
                    assertEquals("0x01004000", ref.get("toAddress").asText());
                    assertEquals("DATA", ref.get("referenceType").asText());
                    assertEquals(true, ref.get("isData").asBoolean());
                    
                    JsonNode fromFunc = ref.get("fromFunction");
                    String funcName = fromFunc.get("name").asText();
                    assertTrue("main".equals(funcName) || "helper".equals(funcName));
                }
                
                // String has no outgoing references
                JsonNode refsFrom = jsonResult.get("referencesFrom");
                assertEquals(0, refsFrom.size());
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testFilterByReferenceType() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                // Test with only flow references
                CallToolResult result = client.callTool(new CallToolRequest(
                    "find-cross-references",
                    Map.of(
                        "programPath", programPath,
                        "location", mainAddr.toString(),
                        "direction", "from",
                        "includeFlow", true,
                        "includeData", false
                    )
                ));
                
                assertFalse("Tool should not have errors", result.isError());
                
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());
                
                JsonNode refsFrom = jsonResult.get("referencesFrom");
                assertEquals(2, refsFrom.size()); // Only calls, no data refs
                
                for (JsonNode ref : refsFrom) {
                    assertEquals("UNCONDITIONAL_CALL", ref.get("referenceType").asText());
                }
                
                // Test with only data references
                result = client.callTool(new CallToolRequest(
                    "find-cross-references",
                    Map.of(
                        "programPath", programPath,
                        "location", mainAddr.toString(),
                        "direction", "from",
                        "includeFlow", false,
                        "includeData", true
                    )
                ));
                
                assertFalse("Tool should not have errors", result.isError());
                
                content = (TextContent) result.content().get(0);
                jsonResult = objectMapper.readTree(content.text());
                
                refsFrom = jsonResult.get("referencesFrom");
                assertEquals(1, refsFrom.size()); // Only data ref
                
                assertEquals("DATA", refsFrom.get(0).get("referenceType").asText());
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testPagination() throws Exception {
        // Create many references to test pagination
        int txId = program.startTransaction("Create More References");
        try {
            ReferenceManager refManager = program.getReferenceManager();
            FunctionManager functionManager = program.getFunctionManager();
            
            for (int i = 0; i < 20; i++) {
                Address fromAddr = program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(0x01005000 + i * 0x100);
                functionManager.createFunction("func_" + i, fromAddr,
                    new AddressSet(fromAddr, fromAddr.add(10)), SourceType.USER_DEFINED);
                refManager.addMemoryReference(fromAddr, utilityAddr, 
                    RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
            }
        } finally {
            program.endTransaction(txId, true);
        }
        
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                // Test first page
                CallToolResult result = client.callTool(new CallToolRequest(
                    "find-cross-references",
                    Map.of(
                        "programPath", programPath,
                        "location", "utility",
                        "direction", "to",
                        "offset", 0,
                        "limit", 10
                    )
                ));
                
                assertFalse("Tool should not have errors", result.isError());
                
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());
                
                JsonNode refsTo = jsonResult.get("referencesTo");
                assertEquals(10, refsTo.size());
                
                JsonNode pagination = jsonResult.get("pagination");
                assertEquals(0, pagination.get("offset").asInt());
                assertEquals(10, pagination.get("limit").asInt());
                assertEquals(22, pagination.get("totalToCount").asInt()); // 2 original + 20 new
                assertEquals(true, pagination.get("hasMoreTo").asBoolean());
                
                // Test last page
                result = client.callTool(new CallToolRequest(
                    "find-cross-references",
                    Map.of(
                        "programPath", programPath,
                        "location", "utility",
                        "direction", "to",
                        "offset", 20,
                        "limit", 10
                    )
                ));
                
                assertFalse("Tool should not have errors", result.isError());
                
                content = (TextContent) result.content().get(0);
                jsonResult = objectMapper.readTree(content.text());
                
                refsTo = jsonResult.get("referencesTo");
                assertEquals(2, refsTo.size()); // Only 2 remaining
                
                pagination = jsonResult.get("pagination");
                assertEquals(20, pagination.get("offset").asInt());
                assertEquals(false, pagination.get("hasMoreTo").asBoolean());
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testInvalidLocation() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                CallToolResult result = client.callTool(new CallToolRequest(
                    "find-cross-references",
                    Map.of(
                        "programPath", programPath,
                        "location", "nonexistent_function"
                    )
                ));
                
                assertTrue("Tool should have error", result.isError());
                TextContent content = (TextContent) result.content().get(0);
                assertTrue(content.text().contains("Invalid address or symbol"));
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }
}