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
package reva.tools.functions;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import reva.RevaIntegrationTestBase;

/**
 * Integration tests for function prototype tool
 */
public class FunctionPrototypeToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;
    private Address testAddr;
    private Address existingFuncAddr;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();
        
        // Use addresses within the existing memory block
        testAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01001000);
        existingFuncAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01002000);
        
        FunctionManager functionManager = program.getFunctionManager();
        
        int txId = program.startTransaction("Create Test Function");
        try {
            // Create an existing function to test updates
            Function existingFunc = functionManager.createFunction("oldFunction", existingFuncAddr,
                new AddressSet(existingFuncAddr, existingFuncAddr.add(50)), SourceType.USER_DEFINED);
            
            // Give it a simple signature to start with
            existingFunc.setReturnType(new IntegerDataType(), SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(txId, true);
        }
        
        // Open the program in the tool's ProgramManager
        env.open(program);
    }

    @Test
    public void testCreateFunctionFromSignature() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                CallToolResult result = client.callTool(new CallToolRequest(
                    "set-function-prototype",
                    Map.of(
                        "programPath", programPath,
                        "location", "0x01001000",
                        "signature", "int main(int argc, char** argv)",
                        "createIfNotExists", true
                    )
                ));
                
                assertFalse("Tool should not have errors", result.isError());
                
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());
                
                // Check that function was created
                assertEquals(true, jsonResult.get("success").asBoolean());
                assertEquals(true, jsonResult.get("created").asBoolean());
                assertEquals("0x01001000", jsonResult.get("address").asText());
                
                // Check function info
                JsonNode functionInfo = jsonResult.get("function");
                assertEquals("main", functionInfo.get("name").asText());
                assertEquals("0x01001000", functionInfo.get("address").asText());
                assertEquals("int", functionInfo.get("returnType").asText());
                
                // Check parameters
                JsonNode parameters = functionInfo.get("parameters");
                assertEquals(2, parameters.size());
                assertEquals("argc", parameters.get(0).get("name").asText());
                assertEquals("int", parameters.get(0).get("dataType").asText());
                assertEquals("argv", parameters.get(1).get("name").asText());
                assertTrue(parameters.get(1).get("dataType").asText().contains("char"));
                
                // Verify function was actually created in program
                FunctionManager fm = program.getFunctionManager();
                Function createdFunc = fm.getFunctionAt(testAddr);
                assertNotNull("Function should exist in program", createdFunc);
                assertEquals("main", createdFunc.getName());
                assertEquals(2, createdFunc.getParameterCount());
                
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testUpdateExistingFunction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                CallToolResult result = client.callTool(new CallToolRequest(
                    "set-function-prototype",
                    Map.of(
                        "programPath", programPath,
                        "location", "0x01002000",
                        "signature", "void processData(char* buffer, int size, int* success)"
                    )
                ));
                
                if (result.isError()) {
                    TextContent errorContent = (TextContent) result.content().get(0);
                    fail("Tool should not have errors, but got: " + errorContent.text());
                }
                
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());
                
                // Check that function was updated, not created
                assertEquals(true, jsonResult.get("success").asBoolean());
                assertEquals(false, jsonResult.get("created").asBoolean());
                assertEquals("0x01002000", jsonResult.get("address").asText());
                
                // Check updated function info
                JsonNode functionInfo = jsonResult.get("function");
                assertEquals("processData", functionInfo.get("name").asText());
                assertEquals("void", functionInfo.get("returnType").asText());
                
                // Check parameters
                JsonNode parameters = functionInfo.get("parameters");
                assertEquals(3, parameters.size());
                assertEquals("buffer", parameters.get(0).get("name").asText());
                assertEquals("size", parameters.get(1).get("name").asText());
                assertEquals("success", parameters.get(2).get("name").asText());
                
                // Verify function was actually updated in program
                FunctionManager fm = program.getFunctionManager();
                Function updatedFunc = fm.getFunctionAt(existingFuncAddr);
                assertNotNull("Function should exist in program", updatedFunc);
                assertEquals("processData", updatedFunc.getName());
                assertEquals(3, updatedFunc.getParameterCount());
                assertEquals("buffer", updatedFunc.getParameter(0).getName());
                
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testInvalidSignature() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                CallToolResult result = client.callTool(new CallToolRequest(
                    "set-function-prototype",
                    Map.of(
                        "programPath", programPath,
                        "location", "0x01001000",
                        "signature", "invalid signature without parens"
                    )
                ));
                
                assertTrue("Tool should have error for invalid signature", result.isError());
                TextContent content = (TextContent) result.content().get(0);
                assertTrue("Error message should mention parsing", 
                    content.text().contains("Failed to parse function signature"));
                
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testCreateIfNotExistsFalse() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                CallToolResult result = client.callTool(new CallToolRequest(
                    "set-function-prototype",
                    Map.of(
                        "programPath", programPath,
                        "location", "0x01003000", // Address with no existing function
                        "signature", "void test()",
                        "createIfNotExists", false
                    )
                ));
                
                assertTrue("Tool should have error when function doesn't exist", result.isError());
                TextContent content = (TextContent) result.content().get(0);
                assertTrue("Error message should mention function doesn't exist", 
                    content.text().contains("Function does not exist"));
                
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testComplexSignature() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                CallToolResult result = client.callTool(new CallToolRequest(
                    "set-function-prototype",
                    Map.of(
                        "programPath", programPath,
                        "location", "0x01004000",
                        "signature", "char* strncpy(char* dest, char* src, int n)"
                    )
                ));
                
                assertFalse("Tool should not have errors", result.isError());
                
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());
                
                // Check function info
                JsonNode functionInfo = jsonResult.get("function");
                assertEquals("strncpy", functionInfo.get("name").asText());
                assertTrue("Return type should be char pointer", 
                    functionInfo.get("returnType").asText().contains("char"));
                
                // Check parameters
                JsonNode parameters = functionInfo.get("parameters");
                assertEquals(3, parameters.size());
                assertEquals("dest", parameters.get(0).get("name").asText());
                assertEquals("src", parameters.get(1).get("name").asText());
                assertEquals("n", parameters.get(2).get("name").asText());
                
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }
}