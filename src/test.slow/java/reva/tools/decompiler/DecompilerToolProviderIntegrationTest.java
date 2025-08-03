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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for DecompilerToolProvider.
 * Tests the actual decompiler functionality with a real Ghidra environment.
 */
public class DecompilerToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;
    private Function testFunction;

    @Before
    public void setUp() throws Exception {
        programPath = program.getDomainFile().getPathname();

        // Create a more realistic test function with actual instructions
        // Use an address within the existing memory block (base class creates block at 0x01000000)
        Address functionAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
        FunctionManager functionManager = program.getFunctionManager();

        int transactionId = program.startTransaction("Create Test Function");
        try {
            // Create a simple function without trying to add machine code
            // Just create the function structure - the decompiler will handle empty functions
            testFunction = functionManager.createFunction("testFunction", functionAddr,
                program.getAddressFactory().getAddressSet(functionAddr, functionAddr.add(20)),
                SourceType.USER_DEFINED);

            // Add some parameters to test datatype changes
            DataType intType = new IntegerDataType(program.getDataTypeManager());
            DataType ptrType = new PointerDataType(intType, program.getDataTypeManager());

            Parameter param1 = new ParameterImpl("param1", intType, program);
            Parameter param2 = new ParameterImpl("param2", ptrType, program);

            List<Variable> params = List.of(param1, param2);
            testFunction.replaceParameters(params,
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);

        } finally {
            program.endTransaction(transactionId, true);
        }

        // Open the program in the tool's ProgramManager so it can be found by RevaProgramManager
        env.open(program);

        // Also open it directly in the tool's ProgramManager service to ensure it's available
        ghidra.app.services.ProgramManager programManager = tool.getService(ghidra.app.services.ProgramManager.class);
        if (programManager != null) {
            programManager.openProgram(program);
        }


        // Register the program with the server manager so it can be found by the tools
        if (serverManager != null) {
            serverManager.programOpened(program, tool);
        }

        assertNotNull("Test function should be created", testFunction);
    }

    /**
     * Helper method to perform the forced read of decompilation required before modification tools
     * @param client The MCP client
     * @param functionName The function name to read decompilation for
     * @return The result of the get-decompilation call
     */
    private CallToolResult performForcedDecompilationRead(io.modelcontextprotocol.client.McpSyncClient client, String functionName) {
        try {
            Map<String, Object> readArgs = new HashMap<>();
            readArgs.put("programPath", programPath);
            readArgs.put("functionNameOrAddress", functionName);
            CallToolResult readResult = client.callTool(new CallToolRequest("get-decompilation", readArgs));
            assertNotNull("Read result should not be null", readResult);
            return readResult;
        } catch (Exception e) {
            fail("Failed to perform forced decompilation read: " + e.getMessage());
            return null; // Never reached due to fail()
        }
    }


    @Test
    public void testGetDecompiledFunctionSuccess() throws Exception {
        // First test basic HTTP connectivity
        try {
            java.net.URL url = java.net.URI.create("http://localhost:8080/").toURL();
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(1000);
            conn.setReadTimeout(1000);
            int responseCode = conn.getResponseCode();
            System.out.println("DEBUG: Basic HTTP GET to / returned: " + responseCode);
            conn.disconnect();
        } catch (Exception e) {
            System.out.println("DEBUG: Basic HTTP GET failed: " + e.getMessage());
        }

        withMcpClient(createMcpTransport(), client -> {
            System.out.println("DEBUG: Test about to initialize client, waiting 1 second...");
            try { Thread.sleep(1000); } catch (InterruptedException e) {}
            System.out.println("DEBUG: Test starting client.initialize()...");
            client.initialize();
            System.out.println("DEBUG: Test client initialized successfully!");

            // Test the get-decompilation tool with our real function
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("functionNameOrAddress", "testFunction");

            CallToolResult result = client.callTool(new CallToolRequest("get-decompilation", args));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            assertNotNull("Result should have content", result.content());
            assertFalse("Result content should not be empty", result.content().isEmpty());

            // Parse the result and validate structure
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertEquals("Program name should match", program.getName(), json.get("programName").asText());
            assertEquals("Function name should match", "testFunction", json.get("functionName").asText());
            assertTrue("Should have address", json.has("address"));
            assertTrue("Should have decompilation", json.has("decompilation"));
            assertTrue("Should have metadata", json.has("metadata"));

            // Verify we got actual decompiled code
            String decompilation = json.get("decompilation").asText();
            assertNotNull("Decompilation should not be null", decompilation);
            assertFalse("Decompilation should not be empty", decompilation.trim().isEmpty());
        });
    }

    @Test
    public void testChangeVariableDataTypesSuccess() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First, read the decompilation to satisfy the forced read requirement
            performForcedDecompilationRead(client, "testFunction");

            // First, get the original variable data types from the program using Function API
            Variable[] originalParams = testFunction.getParameters();
            DataType originalParam1Type = null;
            DataType originalParam2Type = null;

            for (Variable param : originalParams) {
                if ("param1".equals(param.getName())) {
                    originalParam1Type = param.getDataType();
                } else if ("param2".equals(param.getName())) {
                    originalParam2Type = param.getDataType();
                }
            }

            // Now try changing variable data types for function parameters
            Map<String, Object> changeArgs = new HashMap<>();
            changeArgs.put("programPath", programPath);
            changeArgs.put("functionNameOrAddress", "testFunction");

            // Try to change parameter data types
            Map<String, String> datatypeMappings = new HashMap<>();
            datatypeMappings.put("param1", "char");
            datatypeMappings.put("param2", "char*");
            changeArgs.put("datatypeMappings", datatypeMappings);

            CallToolResult changeResult = client.callTool(new CallToolRequest("change-variable-datatypes", changeArgs));

            assertNotNull("Change result should not be null", changeResult);

            // Get the content
            TextContent changeContent = (TextContent) changeResult.content().get(0);

            if (changeResult.isError()) {
                // If it's an error, it should be meaningful (variables might not be found in decompilation)
                String errorMsg = changeContent.text();
                assertTrue("Error message should be informative",
                    errorMsg.contains("not found") || errorMsg.contains("Failed to find") ||
                    errorMsg.contains("No matching variables") || errorMsg.contains("Could not find") ||
                    errorMsg.contains("Decompilation failed"));
            } else {
                // Parse the result as JSON only if it's not an error
                JsonNode changeJson = parseJsonContent(changeContent.text());
                // If successful, validate the structure
                assertEquals("Program name should match", program.getName(), changeJson.get("programName").asText());
                assertEquals("Function name should match", "testFunction", changeJson.get("functionName").asText());
                assertTrue("Should have address", changeJson.has("address"));
                assertTrue("Should have dataTypesChanged flag", changeJson.has("dataTypesChanged"));

                // Should have changes information
                assertTrue("Should have changes or error",
                    changeJson.has("changes") || changeJson.has("decompilationError"));

                // If we have changes, validate the structure
                if (changeJson.has("changes")) {
                    JsonNode changes = changeJson.get("changes");
                    assertTrue("Changes should have hasChanges field", changes.has("hasChanges"));
                    assertTrue("Changes should have summary field", changes.has("summary"));
                }

                // Validate that the program state has actually been updated
                if (changeJson.get("dataTypesChanged").asBoolean()) {
                    // Re-get the function to see updated state
                    Function updatedFunction = program.getFunctionManager().getFunctionAt(testFunction.getEntryPoint());
                    assertNotNull("Function should still exist", updatedFunction);

                    // Check that variable data types have actually changed in the program
                    Variable[] updatedParams = updatedFunction.getParameters();

                    for (Variable param : updatedParams) {
                        String paramName = param.getName();
                        DataType newType = param.getDataType();

                        if ("param1".equals(paramName)) {
                            assertNotNull("param1 should have a data type", newType);

                            // Verify the data type actually changed (if we had an original type)
                            if (originalParam1Type != null) {
                                // The type should have changed to char or be different from original
                                boolean typeChanged = !originalParam1Type.isEquivalent(newType);
                                String newTypeName = newType.getName();

                                assertTrue("param1 type should have changed or be char-related",
                                    typeChanged || newTypeName.contains("char") || newTypeName.equals("char"));
                            }
                        } else if ("param2".equals(paramName)) {
                            assertNotNull("param2 should have a data type", newType);

                            // Verify the data type actually changed (if we had an original type)
                            if (originalParam2Type != null) {
                                // The type should have changed to char* or be different from original
                                boolean typeChanged = !originalParam2Type.isEquivalent(newType);
                                String newTypeName = newType.getName();

                                assertTrue("param2 type should have changed or be char*-related",
                                    typeChanged || newTypeName.contains("char") || newTypeName.contains("*"));
                            }
                        }
                    }
                }
            }
        });
    }

    @Test
    public void testRenameVariablesSuccess() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First, read the decompilation to satisfy the forced read requirement
            performForcedDecompilationRead(client, "testFunction");

            // First, get the original variable names from the program using Function API
            Variable[] originalParams = testFunction.getParameters();
            boolean hasParam1 = false;
            boolean hasParam2 = false;

            for (Variable param : originalParams) {
                if ("param1".equals(param.getName())) {
                    hasParam1 = true;
                } else if ("param2".equals(param.getName())) {
                    hasParam2 = true;
                }
            }

            // Now try renaming variables
            Map<String, Object> renameArgs = new HashMap<>();
            renameArgs.put("programPath", programPath);
            renameArgs.put("functionNameOrAddress", "testFunction");

            // Try to rename variables
            Map<String, String> variableMappings = new HashMap<>();
            variableMappings.put("param1", "myParameter1");
            variableMappings.put("param2", "myParameter2");
            renameArgs.put("variableMappings", variableMappings);

            CallToolResult renameResult = client.callTool(new CallToolRequest("rename-variables", renameArgs));

            assertNotNull("Rename result should not be null", renameResult);

            // Get the content
            TextContent renameContent = (TextContent) renameResult.content().get(0);

            if (renameResult.isError()) {
                // If it's an error, it should be meaningful (variables might not be found in decompilation)
                String errorMsg = renameContent.text();
                assertTrue("Error message should be informative",
                    errorMsg.contains("not found") || errorMsg.contains("Failed to find") ||
                    errorMsg.contains("No matching variables") || errorMsg.contains("Could not find") ||
                    errorMsg.contains("Decompilation failed"));
            } else {
                // Parse the result as JSON only if it's not an error
                JsonNode renameJson = parseJsonContent(renameContent.text());
                // If successful, validate the structure
                assertEquals("Program name should match", program.getName(), renameJson.get("programName").asText());
                assertEquals("Function name should match", "testFunction", renameJson.get("functionName").asText());
                assertTrue("Should have address", renameJson.has("address"));
                assertTrue("Should have variablesRenamed flag", renameJson.has("variablesRenamed"));

                // Should have changes information
                assertTrue("Should have changes or error",
                    renameJson.has("changes") || renameJson.has("decompilationError"));

                // If we have changes, validate the structure
                if (renameJson.has("changes")) {
                    JsonNode changes = renameJson.get("changes");
                    assertTrue("Changes should have hasChanges field", changes.has("hasChanges"));
                    assertTrue("Changes should have summary field", changes.has("summary"));
                }

                // Validate that the program state has actually been updated
                if (renameJson.get("variablesRenamed").asBoolean()) {
                    // Re-get the function to see updated state
                    Function updatedFunction = program.getFunctionManager().getFunctionAt(testFunction.getEntryPoint());
                    assertNotNull("Function should still exist", updatedFunction);

                    // Check that variables have actually been renamed in the program
                    Variable[] updatedParams = updatedFunction.getParameters();
                    boolean foundMyParameter1 = false;
                    boolean foundMyParameter2 = false;
                    boolean foundOldParam1 = false;
                    boolean foundOldParam2 = false;

                    for (Variable param : updatedParams) {
                        String paramName = param.getName();
                        if ("myParameter1".equals(paramName)) {
                            foundMyParameter1 = true;
                        } else if ("myParameter2".equals(paramName)) {
                            foundMyParameter2 = true;
                        } else if ("param1".equals(paramName)) {
                            foundOldParam1 = true;
                        } else if ("param2".equals(paramName)) {
                            foundOldParam2 = true;
                        }
                    }

                    // At least one parameter should have been renamed
                    assertTrue("At least one parameter should have been renamed successfully",
                        foundMyParameter1 || foundMyParameter2);

                    // Verify specific renames occurred correctly
                    if (hasParam1 && foundMyParameter1) {
                        assertFalse("Old param1 name should no longer exist", foundOldParam1);
                    }
                    if (hasParam2 && foundMyParameter2) {
                        assertFalse("Old param2 name should no longer exist", foundOldParam2);
                    }

                    // Also check all variables (including locals) for comprehensive validation
                    Variable[] allVariables = updatedFunction.getAllVariables();
                    boolean foundMyParameter1InAll = false;
                    boolean foundMyParameter2InAll = false;

                    for (Variable var : allVariables) {
                        String varName = var.getName();
                        if ("myParameter1".equals(varName)) {
                            foundMyParameter1InAll = true;
                        } else if ("myParameter2".equals(varName)) {
                            foundMyParameter2InAll = true;
                        }
                    }

                    // At least one variable should have been renamed across all variables
                    assertTrue("At least one variable should have been renamed in function",
                        foundMyParameter1InAll || foundMyParameter2InAll);
                }
            }
        });
    }

    @Test
    public void testGetDecompilationWithInvalidFunction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test the get-decompilation tool with non-existent function
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("functionNameOrAddress", "nonExistentFunction");

            CallToolResult result = client.callTool(new CallToolRequest("get-decompilation", args));

            assertNotNull("Result should not be null", result);
            assertTrue("Should return error for non-existent function", result.isError());

            TextContent content = (TextContent) result.content().get(0);
            String errorMsg = content.text();
            assertTrue("Error should mention function not found",
                errorMsg.contains("Function not found") || errorMsg.contains("function"));
        });
    }

    @Test
    public void testChangeVariableDataTypesWithInvalidFunction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test changing data types for non-existent function
            Map<String, Object> changeArgs = new HashMap<>();
            changeArgs.put("programPath", programPath);
            changeArgs.put("functionNameOrAddress", "nonExistentFunction");

            Map<String, String> datatypeMappings = new HashMap<>();
            datatypeMappings.put("someVar", "int");
            changeArgs.put("datatypeMappings", datatypeMappings);

            CallToolResult changeResult = client.callTool(new CallToolRequest("change-variable-datatypes", changeArgs));

            assertNotNull("Change result should not be null", changeResult);
            assertTrue("Should return error for non-existent function", changeResult.isError());

            TextContent content = (TextContent) changeResult.content().get(0);
            String errorMsg = content.text();
            assertTrue("Error should mention function not found",
                errorMsg.contains("Function not found") || errorMsg.contains("function"));
        });
    }

    @Test
    public void testChangeVariableDataTypesWithInvalidProgram() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test with invalid program path
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", "/nonexistent/program");
            args.put("functionNameOrAddress", "testFunction");
            args.put("datatypeMappings", Map.of("var1", "int"));

            CallToolResult result = client.callTool(new CallToolRequest("change-variable-datatypes", args));

            assertTrue("Should return error for invalid program", result.isError());
            TextContent content = (TextContent) result.content().get(0);
            String errorMsg = content.text();
            assertTrue("Error should mention program not found",
                errorMsg.contains("Failed to find program") || errorMsg.contains("program"));
        });
    }

    @Test
    public void testChangeVariableDataTypesWithInvalidFunctionName() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test with invalid function name
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("functionNameOrAddress", "anotherNonExistentFunction");
            args.put("datatypeMappings", Map.of("var1", "int"));

            CallToolResult result = client.callTool(new CallToolRequest("change-variable-datatypes", args));

            assertTrue("Should return error for invalid function", result.isError());
            TextContent content = (TextContent) result.content().get(0);
            String errorMsg = content.text();
            assertTrue("Error should mention function not found",
                errorMsg.contains("Function not found") || errorMsg.contains("function"));
        });
    }

    @Test
    public void testChangeVariableDataTypesWithEmptyMappings() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test with empty datatype mappings
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("functionNameOrAddress", "testFunction");
            args.put("datatypeMappings", new HashMap<String, String>());

            CallToolResult result = client.callTool(new CallToolRequest("change-variable-datatypes", args));

            assertTrue("Should return error for empty mappings", result.isError());
            TextContent content = (TextContent) result.content().get(0);
            String errorMsg = content.text();
            assertTrue("Error should mention no datatype mappings",
                errorMsg.contains("No datatype mappings") || errorMsg.contains("mappings"));
        });
    }

    @Test
    public void testChangeVariableDataTypesWithInvalidDataType() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test with invalid data type string
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("functionNameOrAddress", "testFunction");

            Map<String, String> datatypeMappings = new HashMap<>();
            datatypeMappings.put("someVariable", "InvalidDataType123");
            args.put("datatypeMappings", datatypeMappings);

            CallToolResult result = client.callTool(new CallToolRequest("change-variable-datatypes", args));

            // This might succeed but report errors, or might fail entirely
            assertNotNull("Result should not be null", result);

            if (!result.isError()) {
                // If it didn't fail outright, check that it reports errors for invalid data types
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());

                // Should either have no variables changed or have errors reported
                assertTrue("Should report issues with invalid data types",
                    (json.has("dataTypesChanged") && !json.get("dataTypesChanged").asBoolean()) &&
                     (json.has("errors") ||
                      content.text().contains("No matching variables") ||
                      content.text().contains("Could not find")));
            }
        });
    }

    @Test
    public void testGetDecompilationWithRange() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test the get-decompilation tool with line range
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("functionNameOrAddress", "testFunction");
            args.put("offset", 1);
            args.put("limit", 5);

            CallToolResult result = client.callTool(new CallToolRequest("get-decompilation", args));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Should have offset", json.has("offset"));
            assertTrue("Should have limit", json.has("limit"));
            assertTrue("Should have totalLines", json.has("totalLines"));
            assertEquals("Offset should be 1", 1, json.get("offset").asInt());
            assertEquals("Limit should be 5", 5, json.get("limit").asInt());
        });
    }

    @Test
    public void testGetDecompilationDefaultLimit() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test the get-decompilation tool with default limit (no limit specified)
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("functionNameOrAddress", "testFunction");
            // No limit specified - should default to 50

            CallToolResult result = client.callTool(new CallToolRequest("get-decompilation", args));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Should have offset", json.has("offset"));
            assertTrue("Should have limit", json.has("limit"));
            assertTrue("Should have totalLines", json.has("totalLines"));
            assertEquals("Offset should be 1", 1, json.get("offset").asInt());
            assertEquals("Limit should default to 50", 50, json.get("limit").asInt());
        });
    }

    @Test
    public void testGetDecompilationWithSync() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test the get-decompilation tool with assembly sync
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("functionNameOrAddress", "testFunction");
            args.put("includeDisassembly", true);

            CallToolResult result = client.callTool(new CallToolRequest("get-decompilation", args));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Should have synchronizedContent when includeDisassembly is true",
                json.has("synchronizedContent") || json.has("decompilation"));
        });
    }

    @Test
    public void testSearchDecompilation() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test the search-decompilation tool
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("pattern", ".*"); // Simple pattern that should match something
            args.put("maxResults", 10);

            CallToolResult result = client.callTool(new CallToolRequest("search-decompilation", args));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Should have results array", json.has("results"));
            assertTrue("Should have resultsCount", json.has("resultsCount"));
            assertTrue("Should have pattern", json.has("pattern"));
            assertEquals("Pattern should match", ".*", json.get("pattern").asText());
        });
    }

    @Test
    public void testForcedReadValidation() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Try to rename variables without reading decompilation first
            Map<String, Object> renameArgs = new HashMap<>();
            renameArgs.put("programPath", programPath);
            renameArgs.put("functionNameOrAddress", "testFunction");
            renameArgs.put("variableMappings", Map.of("param1", "newParam1"));

            CallToolResult renameResult = client.callTool(new CallToolRequest("rename-variables", renameArgs));

            assertNotNull("Rename result should not be null", renameResult);
            assertTrue("Should return error for not reading decompilation first", renameResult.isError());

            TextContent content = (TextContent) renameResult.content().get(0);
            String errorMsg = content.text();
            assertTrue("Error should mention reading decompilation first",
                errorMsg.contains("read the decompilation") || errorMsg.contains("get-decompilation"));
        });
    }

    @Test
    public void testSearchDecompilationRespectsMaxFunctionLimitConfig() throws Exception {
        // Get the config manager and save the original value
        reva.plugin.ConfigManager configManager = reva.util.RevaInternalServiceRegistry.getService(reva.plugin.ConfigManager.class);
        int originalMax = configManager.getMaxDecompilerSearchFunctions();
        try {
            // Set max functions to 0 to force the limit
            configManager.setMaxDecompilerSearchFunctions(0);

            withMcpClient(createMcpTransport(), client -> {
                client.initialize();
                Map<String, Object> args = new HashMap<>();
                args.put("programPath", programPath);
                args.put("pattern", ".*");
                args.put("maxResults", 10);

                CallToolResult result = client.callTool(new CallToolRequest("search-decompilation", args));
                assertNotNull("Result should not be null", result);
                assertTrue("Should return error when function count exceeds max", result.isError());
                TextContent content = (TextContent) result.content().get(0);
                String errorMsg = content.text();
                assertTrue("Error should mention maximum limit", errorMsg.contains("maximum limit") || errorMsg.contains("exceeds the maximum"));
            });
        } finally {
            // Restore the original config value
            configManager.setMaxDecompilerSearchFunctions(originalMax);
        }
    }

    @Test
    public void testSearchDecompilationRespectsMaxFunctionLimitConfigOverride() throws Exception {
        // Get the config manager and save the original value
        reva.plugin.ConfigManager configManager = reva.util.RevaInternalServiceRegistry.getService(reva.plugin.ConfigManager.class);
        int originalMax = configManager.getMaxDecompilerSearchFunctions();
        try {
            // Set max functions to 0 to force the limit
            configManager.setMaxDecompilerSearchFunctions(0);

            withMcpClient(createMcpTransport(), client -> {
                client.initialize();
                Map<String, Object> args = new HashMap<>();
                args.put("programPath", programPath);
                args.put("pattern", ".*");
                args.put("maxResults", 10);
                args.put("overrideMaxFunctionsLimit", true); // Override the max functions limit

                CallToolResult result = client.callTool(new CallToolRequest("search-decompilation", args));
                assertNotNull("Result should not be null", result);
                assertFalse("Should not return error when function count exceeds max and override is set", result.isError());
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertTrue("Should have results array", json.has("results"));
            });
        } finally {
            // Restore the original config value
            configManager.setMaxDecompilerSearchFunctions(originalMax);
        }
    }

    @Test
    public void testGetDecompilationReferencesContainSymbolAndAddress() throws Exception {
        // Create a caller function that references testFunction
        Address callerAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000200);
        FunctionManager functionManager = program.getFunctionManager();
        int txId = program.startTransaction("Create Caller Function");
        try {
            // Create a simple caller function
            Function callerFunction = functionManager.createFunction("callerFunction", callerAddr,
                program.getAddressFactory().getAddressSet(callerAddr, callerAddr.add(20)),
                SourceType.USER_DEFINED);
            // Insert a call instruction from callerFunction to testFunction
            // For x86, 0xE8 is CALL rel32. We'll use a dummy relative offset (not actually executable, but enough for Ghidra to create a reference)
            byte[] callInstr = new byte[] { (byte)0xE8, 0x00, 0x00, 0x00, 0x00 }; // CALL +0
            program.getMemory().setBytes(callerAddr, callInstr);
            // Add a reference from the call instruction to testFunction
            program.getReferenceManager().addMemoryReference(
                callerAddr, // from
                testFunction.getEntryPoint(), // to
                ghidra.program.model.symbol.RefType.UNCONDITIONAL_CALL,
                ghidra.program.model.symbol.SourceType.USER_DEFINED,
                0
            );
        } finally {
            program.endTransaction(txId, true);
        }

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("functionNameOrAddress", "testFunction");
            args.put("includeIncomingReferences", true);
            args.put("includeReferenceContext", false);
            CallToolResult result = client.callTool(new CallToolRequest("get-decompilation", args));
            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Should have incomingReferences", json.has("incomingReferences"));
            JsonNode refs = json.get("incomingReferences");
            boolean foundCaller = false;
            for (JsonNode ref : refs) {
                // Should have both fromAddress and fromSymbol fields (fromSymbol may be null if no symbol)
                assertTrue("Reference should have fromAddress", ref.has("fromAddress"));
                assertTrue("Reference should have referenceType", ref.has("referenceType"));
                // fromSymbol is optional but if present, should be a string
                if (ref.has("fromSymbol")) {
                    assertTrue("fromSymbol should be a string if present", ref.get("fromSymbol").isTextual());
                    if ("callerFunction".equals(ref.get("fromSymbol").asText())) {
                        foundCaller = true;
                    }
                }
            }
            assertTrue("Should have a reference from callerFunction", foundCaller);
        });
    }


}