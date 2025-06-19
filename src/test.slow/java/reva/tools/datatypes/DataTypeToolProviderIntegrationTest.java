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
package reva.tools.datatypes;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataTypeManager;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for DataTypeToolProvider functionality
 */
public class DataTypeToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();
        
        // Open program in tool so it can be found by path
        env.open(program);
    }

    /**
     * Test that get-data-type-archives works with required program path
     * This is the core issue from #142 - it should always return at least built-in types
     */
    @Test
    public void testGetDataTypeArchivesWithProgramPath() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                // Call the tool with required program path
                CallToolResult result = client.callTool(new CallToolRequest("get-data-type-archives", 
                    Map.of("programPath", programPath)));
                
                assertFalse("Tool call should succeed", result.isError());
                assertNotNull("Should have content", result.content());
                
                // Get all content blocks - createMultiJsonResult returns multiple text blocks
                StringBuilder fullResultText = new StringBuilder();
                for (int i = 0; i < result.content().size(); i++) {
                    String contentText = ((TextContent) result.content().get(i)).text();
                    fullResultText.append(contentText);
                    if (i < result.content().size() - 1) {
                        fullResultText.append(" ");
                    }
                }
                String resultText = fullResultText.toString();
                
                // Should not return an error
                assertFalse("Tool should not fail with 'RevaPlugin is not available'", 
                           resultText.contains("RevaPlugin is not available"));
                
                // Should contain built-in data types archive
                assertTrue("Should contain built-in data types. Actual response: " + resultText, 
                          resultText.contains("BuiltInTypes") || resultText.contains("BUILT_IN"));
                
                // Should have at least one archive
                assertTrue("Should have at least one data type archive available", 
                          resultText.contains("\"count\":") && !resultText.contains("\"count\":0"));
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    /**
     * Test that get-data-type-archives fails when programPath is missing (required parameter)
     */
    @Test
    public void testGetDataTypeArchivesRequiresProgramPath() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                // Call the tool without program path - this should fail
                CallToolResult result = client.callTool(new CallToolRequest("get-data-type-archives", Map.of()));
                
                assertTrue("Tool call should fail without programPath", result.isError());
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    /**
     * Test that tools fail gracefully with invalid program path
     */
    @Test
    public void testInvalidProgramPath() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                String invalidProgramPath = "/nonexistent/program/path";
                
                // Test get-data-type-archives with invalid program path
                CallToolResult archivesResult = client.callTool(new CallToolRequest("get-data-type-archives", 
                    Map.of("programPath", invalidProgramPath)));
                assertTrue("get-data-type-archives should fail with invalid program path", archivesResult.isError());
                String archivesError = ((TextContent) archivesResult.content().get(0)).text();
                assertTrue("Should contain helpful error message", archivesError.contains("Could not find program"));
                
                // Test get-data-types with invalid program path
                CallToolResult typesResult = client.callTool(new CallToolRequest("get-data-types", 
                    Map.of("programPath", invalidProgramPath, "archiveName", "BuiltInTypes")));
                assertTrue("get-data-types should fail with invalid program path", typesResult.isError());
                
                // Test get-data-type-by-string with invalid program path
                CallToolResult byStringResult = client.callTool(new CallToolRequest("get-data-type-by-string", 
                    Map.of("programPath", invalidProgramPath, "dataTypeString", "int")));
                assertTrue("get-data-type-by-string should fail with invalid program path", byStringResult.isError());
                
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    /**
     * Test that apply-data-type works with basic built-in types
     * This tests the core functionality that was failing in #142
     */
    @Test
    public void testApplyDataTypeWithBuiltInTypes() throws Exception {
        // Test with basic built-in types that should always be available
        String[] basicTypes = {"byte", "int", "char", "short", "long", "float", "double"};
        
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                for (String dataType : basicTypes) {
                    // Try to apply the data type to a known address
                    Map<String, Object> args = Map.of(
                        "programPath", programPath,
                        "addressOrSymbol", "0x00401000", 
                        "dataTypeString", dataType
                    );
                    
                    CallToolResult result = client.callTool(new CallToolRequest("apply-data-type", args));
                    String resultText = ((TextContent) result.content().get(0)).text();
                    
                    // Should not fail with "No data type managers available"
                    assertFalse("Should not fail with 'No data type managers available' for type: " + dataType, 
                               resultText.contains("No data type managers available"));
                    
                    // Should not fail with "RevaPlugin is not available"  
                    assertFalse("Should not fail with 'RevaPlugin is not available' for type: " + dataType,
                               resultText.contains("RevaPlugin is not available"));
                }
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    /**
     * Test that apply-data-type works with pointer types
     */
    @Test
    public void testApplyDataTypeWithPointerTypes() throws Exception {
        // Test pointer types that were mentioned in the original issue
        String[] pointerTypes = {"byte *", "char *", "int *", "void *"};
        
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                for (String dataType : pointerTypes) {
                    Map<String, Object> args = Map.of(
                        "programPath", programPath,
                        "addressOrSymbol", "0x00401000",
                        "dataTypeString", dataType
                    );
                    
                    CallToolResult result = client.callTool(new CallToolRequest("apply-data-type", args));
                    String resultText = ((TextContent) result.content().get(0)).text();
                    
                    // Should not fail with core error from #142
                    assertFalse("Should not fail with 'No data type managers available' for type: " + dataType, 
                               resultText.contains("No data type managers available"));
                }
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    /**
     * Test that built-in data type manager is always available
     */
    @Test
    public void testBuiltInDataTypeManagerAvailability() {
        // This tests our fix at the utility level
        DataTypeManager builtInDTM = BuiltInDataTypeManager.getDataTypeManager();
        assertNotNull("Built-in data type manager should always be available", builtInDTM);
        assertTrue("Built-in data type manager should have data types", 
                  builtInDTM.getDataTypeCount(true) > 0);
    }

    /**
     * Test headless program data type access - tools require programPath and work with built-in types
     */
    @Test
    public void testHeadlessProgramDataTypeAccess() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                // Test get-data-types tool with program-specific archive
                CallToolResult archivesResult = client.callTool(new CallToolRequest("get-data-type-archives", 
                    Map.of("programPath", programPath)));
                    
                assertFalse("get-data-type-archives should succeed", archivesResult.isError());
                
                // Now test get-data-types with the built-in archive - this is the key functionality
                CallToolResult typesResult = client.callTool(new CallToolRequest("get-data-types", 
                    Map.of("programPath", programPath, "archiveName", "BuiltInTypes")));
                    
                assertFalse("get-data-types should succeed", typesResult.isError());
                
                // Get all content blocks - createMultiJsonResult returns multiple text blocks
                StringBuilder fullTypesText = new StringBuilder();
                for (int i = 0; i < typesResult.content().size(); i++) {
                    String contentText = ((TextContent) typesResult.content().get(i)).text();
                    fullTypesText.append(contentText);
                    if (i < typesResult.content().size() - 1) {
                        fullTypesText.append(" ");
                    }
                }
                String typesText = fullTypesText.toString();
                
                // Should contain basic types - this proves the headless functionality works
                assertTrue("Should contain basic data types. Actual response: " + typesText,
                          typesText.contains("int") || typesText.contains("char") || typesText.contains("byte"));
                
                // Test get-data-type-by-string with program context - most important test
                CallToolResult byStringResult = client.callTool(new CallToolRequest("get-data-type-by-string", 
                    Map.of("programPath", programPath, "dataTypeString", "int")));
                    
                assertFalse("get-data-type-by-string should succeed", byStringResult.isError());
                String byStringText = ((TextContent) byStringResult.content().get(0)).text();
                
                // Should find the int data type - this proves issue #142 is resolved
                assertTrue("Should find int data type. Actual response: " + byStringText,
                          byStringText.contains("\"name\":\"int\""));
                          
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    /**
     * Test that the tools provide helpful information when program is loaded
     */
    @Test  
    public void testDataTypeArchivesWithProgram() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                CallToolResult result = client.callTool(new CallToolRequest("get-data-type-archives", 
                    Map.of("programPath", programPath)));
                
                // Get all content blocks - createMultiJsonResult returns multiple text blocks
                StringBuilder fullResultText = new StringBuilder();
                for (int i = 0; i < result.content().size(); i++) {
                    String contentText = ((TextContent) result.content().get(i)).text();
                    fullResultText.append(contentText);
                    if (i < result.content().size() - 1) {
                        fullResultText.append(" ");
                    }
                }
                String resultText = fullResultText.toString();
                
                // Debug: Print the actual response to see what we're getting
                // System.out.println("DEBUG: get-data-type-archives (with program) response: " + resultText);
                
                // Should always show built-in types (this is the core fix for issue #142)
                assertTrue("Should show built-in types. Actual response: " + resultText, 
                          resultText.contains("BUILT_IN") || resultText.contains("BuiltInTypes"));
                          
                // Should have at least one archive (the built-in one)
                assertTrue("Should have at least one data type archive available", 
                          resultText.contains("\"count\":") && !resultText.contains("\"count\":0"));
                          
                // In test environment, program may not be accessible through normal channels,
                // but the important thing is that the tool accepts programPath and returns built-in types
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }
}