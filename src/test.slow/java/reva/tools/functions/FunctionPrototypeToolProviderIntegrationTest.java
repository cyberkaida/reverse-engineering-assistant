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
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
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

    @Test
    public void testChangeAutoParameterTypeEnablesCustomStorage() throws Exception {
        // Create a function with __thiscall calling convention that has auto 'this' parameter
        Address thiscallAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01005000);

        int txId = program.startTransaction("Create __thiscall function");
        try {
            FunctionManager fm = program.getFunctionManager();
            Function thiscallFunc = fm.createFunction("Graphics_PostProcessPixelData", thiscallAddr,
                new AddressSet(thiscallAddr, thiscallAddr.add(50)), SourceType.USER_DEFINED);

            // Set calling convention to __thiscall (if available)
            CompilerSpec compilerSpec = program.getCompilerSpec();
            PrototypeModel[] callingConventions = compilerSpec.getCallingConventions();
            String thiscallConvention = null;
            for (PrototypeModel model : callingConventions) {
                if (model.getName().toLowerCase().contains("thiscall")) {
                    thiscallConvention = model.getName();
                    break;
                }
            }

            if (thiscallConvention != null) {
                thiscallFunc.setCallingConvention(thiscallConvention);
            }

            // Create a simple structure type for testing
            Structure myStruct = new StructureDataType("Graphics_Renderer", 0);
            myStruct.add(new IntegerDataType(), "field1", null);
            myStruct.add(new IntegerDataType(), "field2", null);
            program.getDataTypeManager().addDataType(myStruct, null);

        } finally {
            program.endTransaction(txId, true);
        }

        env.open(program);

        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Get the function to check initial state
                FunctionManager fm = program.getFunctionManager();
                Function beforeFunc = fm.getFunctionAt(thiscallAddr);
                assertNotNull("Function should exist", beforeFunc);

                // Check if it has auto-parameters before the change
                boolean hadAutoParams = false;
                for (Parameter param : beforeFunc.getParameters()) {
                    if (param.isAutoParameter()) {
                        hadAutoParams = true;
                        break;
                    }
                }

                // Try to change the 'this' parameter type to Graphics_Renderer*
                CallToolResult result = client.callTool(new CallToolRequest(
                    "set-function-prototype",
                    Map.of(
                        "programPath", programPath,
                        "location", "0x01005000",
                        "signature", "int Graphics_PostProcessPixelData(Graphics_Renderer* this, int imageData)"
                    )
                ));

                if (result.isError()) {
                    TextContent errorContent = (TextContent) result.content().get(0);
                    fail("Tool should not have errors, but got: " + errorContent.text());
                }

                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());

                // Check that the tool succeeded
                assertEquals("Tool should succeed", true, jsonResult.get("success").asBoolean());

                // Check that custom storage is now enabled
                assertEquals("Custom storage should be enabled", true,
                    jsonResult.get("usingCustomStorage").asBoolean());

                // If there were auto-params, custom storage should have been enabled
                if (hadAutoParams) {
                    assertEquals("Custom storage should have been enabled automatically", true,
                        jsonResult.get("customStorageEnabled").asBoolean());
                }

                // Verify function was actually updated in program
                Function updatedFunc = fm.getFunctionAt(thiscallAddr);
                assertNotNull("Function should exist in program", updatedFunc);
                assertEquals("Graphics_PostProcessPixelData", updatedFunc.getName());

                // Verify the parameter type was actually changed
                Parameter[] params = updatedFunc.getParameters();
                assertTrue("Should have at least one parameter", params.length >= 1);

                // Check that 'this' parameter now has Graphics_Renderer* type
                Parameter thisParam = params[0];
                assertEquals("this", thisParam.getName());
                assertTrue("Parameter should be a pointer to Graphics_Renderer",
                    thisParam.getDataType().toString().contains("Graphics_Renderer"));

                // Verify custom storage is enabled in the actual function
                assertTrue("Function should have custom storage enabled",
                    updatedFunc.hasCustomVariableStorage());

            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testChangeRegularParameterDoesNotEnableCustomStorage() throws Exception {
        // Create a function with __thiscall calling convention that has auto 'this' parameter
        Address thiscallAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01006000);

        int txId = program.startTransaction("Create __thiscall function for regular param test");
        try {
            FunctionManager fm = program.getFunctionManager();
            Function thiscallFunc = fm.createFunction("processImage", thiscallAddr,
                new AddressSet(thiscallAddr, thiscallAddr.add(50)), SourceType.USER_DEFINED);

            // Set calling convention to __thiscall (if available)
            CompilerSpec compilerSpec = program.getCompilerSpec();
            PrototypeModel[] callingConventions = compilerSpec.getCallingConventions();
            String thiscallConvention = null;
            for (PrototypeModel model : callingConventions) {
                if (model.getName().toLowerCase().contains("thiscall")) {
                    thiscallConvention = model.getName();
                    break;
                }
            }

            if (thiscallConvention != null) {
                thiscallFunc.setCallingConvention(thiscallConvention);
            }

        } finally {
            program.endTransaction(txId, true);
        }

        env.open(program);

        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Get the function to check initial state
                FunctionManager fm = program.getFunctionManager();
                Function beforeFunc = fm.getFunctionAt(thiscallAddr);
                assertNotNull("Function should exist", beforeFunc);

                // Check initial state - should NOT have custom storage
                assertFalse("Function should not have custom storage initially",
                    beforeFunc.hasCustomVariableStorage());

                // Check if it has auto-parameters
                boolean hasAutoParams = false;
                for (Parameter param : beforeFunc.getParameters()) {
                    if (param.isAutoParameter()) {
                        hasAutoParams = true;
                        break;
                    }
                }

                // Only continue test if the function actually has auto-parameters
                if (!hasAutoParams) {
                    // Skip test if no auto-params (calling convention doesn't inject them)
                    return;
                }

                // Change ONLY a regular parameter, NOT the 'this' parameter
                // Keep 'void *this' unchanged, but change int to char*
                CallToolResult result = client.callTool(new CallToolRequest(
                    "set-function-prototype",
                    Map.of(
                        "programPath", programPath,
                        "location", "0x01006000",
                        "signature", "void processImage(void* this, char* imageData)"
                    )
                ));

                if (result.isError()) {
                    TextContent errorContent = (TextContent) result.content().get(0);
                    fail("Tool should not have errors, but got: " + errorContent.text());
                }

                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());

                // Check that the tool succeeded
                assertEquals("Tool should succeed", true, jsonResult.get("success").asBoolean());

                // Custom storage should NOT have been enabled since we didn't change the auto-parameter
                assertEquals("Custom storage should NOT be enabled", false,
                    jsonResult.get("customStorageEnabled").asBoolean());
                assertEquals("Function should NOT be using custom storage", false,
                    jsonResult.get("usingCustomStorage").asBoolean());

                // Verify function was actually updated in program
                Function updatedFunc = fm.getFunctionAt(thiscallAddr);
                assertNotNull("Function should exist in program", updatedFunc);

                // Verify custom storage is NOT enabled
                assertFalse("Function should NOT have custom storage enabled",
                    updatedFunc.hasCustomVariableStorage());

                // Verify the regular parameter type was changed
                Parameter[] params = updatedFunc.getParameters();
                assertTrue("Should have at least two parameters", params.length >= 2);

                // Find the non-auto parameter (should be second one in this case)
                Parameter regularParam = null;
                for (Parameter param : params) {
                    if (!param.isAutoParameter()) {
                        regularParam = param;
                        break;
                    }
                }

                assertNotNull("Should have a regular parameter", regularParam);
                assertTrue("Regular parameter should be char*",
                    regularParam.getDataType().toString().contains("char"));

            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testSignatureWithCallingConvention() throws Exception {
        // Test that calling conventions are stripped and signature still parses
        // This is a workaround for Ghidra Issue #8831
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                Address funcAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01007000);

                // Test with __thiscall (common for C++ member functions on Windows)
                CallToolResult result = client.callTool(new CallToolRequest(
                    "set-function-prototype",
                    Map.of(
                        "programPath", programPath,
                        "location", "0x01007000",
                        "signature", "int __thiscall ProcessData(void* this, char* buffer, int size)",
                        "createIfNotExists", true
                    )
                ));

                assertFalse("Tool should not have errors with __thiscall", result.isError());

                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());

                // Verify function was created successfully
                assertEquals("Tool should succeed", true, jsonResult.get("success").asBoolean());
                assertEquals("Function should be created", true, jsonResult.get("created").asBoolean());

                // Verify function info
                JsonNode functionInfo = jsonResult.get("function");
                assertEquals("Function name should be ProcessData", "ProcessData", functionInfo.get("name").asText());
                assertEquals("Return type should be int", "int", functionInfo.get("returnType").asText());

                // Verify function was actually created in program
                FunctionManager fm = program.getFunctionManager();
                Function createdFunc = fm.getFunctionAt(funcAddr);
                assertNotNull("Function should exist in program", createdFunc);
                assertEquals("Function name should match", "ProcessData", createdFunc.getName());

            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testMultipleCallingConventions() throws Exception {
        // Test that various calling conventions are all stripped correctly
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Test cases: different calling conventions
                String[][] testCases = {
                    {"0x01008000", "void __cdecl cdeclFunc(int x)"},
                    {"0x01008100", "int __stdcall stdcallFunc(char* str)"},
                    {"0x01008200", "void* __fastcall fastcallFunc(int a, int b)"},
                    {"0x01008300", "long __vectorcall vectorFunc(float* vec)"}
                };

                for (String[] testCase : testCases) {
                    String addrStr = testCase[0];
                    String signature = testCase[1];

                    CallToolResult result = client.callTool(new CallToolRequest(
                        "set-function-prototype",
                        Map.of(
                            "programPath", programPath,
                            "location", addrStr,
                            "signature", signature,
                            "createIfNotExists", true
                        )
                    ));

                    assertFalse("Tool should not have errors for: " + signature, result.isError());

                    TextContent content = (TextContent) result.content().get(0);
                    JsonNode jsonResult = objectMapper.readTree(content.text());
                    assertEquals("Tool should succeed for: " + signature, true, jsonResult.get("success").asBoolean());
                }

            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }
}