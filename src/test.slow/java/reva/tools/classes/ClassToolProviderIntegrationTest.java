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
package reva.tools.classes;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for ClassToolProvider functionality, specifically 
 * testing the new RTTI reconstruction capabilities.
 */
public class ClassToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();
        
        // Open program in tool so it can be found by path
        env.open(program);
    }

    /**
     * Test that list-classes provides guidance when no classes are found.
     * This verifies the enhancement we added to suggest RTTI reconstruction.
     */
    @Test
    public void testListClassesWithGuidance() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                // Call the list-classes tool
                CallToolResult result = client.callTool(new CallToolRequest("list-classes", 
                    Map.of("programPath", programPath)));
                
                assertFalse("Tool call should succeed", result.isError());
                assertNotNull("Should have content", result.content());
                
                // Get the result text
                String resultText = getResultText(result);
                
                // Should not return an error
                assertFalse("Tool should not fail with 'RevaPlugin is not available'", 
                           resultText.contains("RevaPlugin is not available"));
                
                // The test program likely has no classes, so we should see guidance
                if (resultText.contains("\"count\":0") || resultText.contains("No classes found")) {
                    assertTrue("Should provide RTTI guidance when no classes found. Actual response: " + resultText, 
                              resultText.contains("reconstruct-classes-from-rtti") || 
                              resultText.contains("RTTI data"));
                }
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    /**
     * Test that reconstruct-classes-from-rtti tool is properly registered and accessible.
     */
    @Test
    public void testRttiReconstructionToolAvailable() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                // List available tools to ensure our new tool is registered
                var listResult = client.listTools();
                
                assertNotNull("List tools should return result", listResult);
                assertNotNull("Should have tools", listResult.tools());
                
                // Find our RTTI reconstruction tool
                boolean foundRttiTool = listResult.tools().stream()
                    .anyMatch(tool -> "reconstruct-classes-from-rtti".equals(tool.name()));
                
                assertTrue("Should have reconstruct-classes-from-rtti tool available", foundRttiTool);
                
                // Check the tool has proper schema
                var rttiTool = listResult.tools().stream()
                    .filter(tool -> "reconstruct-classes-from-rtti".equals(tool.name()))
                    .findFirst()
                    .orElse(null);
                
                assertNotNull("RTTI tool should be found", rttiTool);
                assertNotNull("RTTI tool should have input schema", rttiTool.inputSchema());
                
                // Should have programPath parameter
                assertTrue("Should have programPath parameter in schema",
                    rttiTool.inputSchema().toString().contains("programPath"));
                
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    /**
     * Test that reconstruct-classes-from-rtti tool validates required parameters.
     */
    @Test
    public void testRttiReconstructionRequiresProgramPath() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                // Call the tool without program path - this should fail
                CallToolResult result = client.callTool(new CallToolRequest("reconstruct-classes-from-rtti", 
                    Map.of()));
                
                assertTrue("Tool call should fail without required programPath parameter", result.isError());
                String errorText = getResultText(result);
                assertTrue("Error should mention missing programPath parameter", 
                          errorText.contains("programPath") || errorText.contains("required"));
                
            } catch (Exception e) {
                // Some validation errors might be thrown as exceptions
                assertTrue("Exception should mention programPath or validation", 
                          e.getMessage().contains("programPath") || e.getMessage().contains("required"));
            }
        });
    }

    /**
     * Test that reconstruct-classes-from-rtti tool handles programs without RTTI data gracefully.
     */
    @Test
    public void testRttiReconstructionWithoutRttiData() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                // Call the tool with our test program (which likely doesn't have RTTI)
                CallToolResult result = client.callTool(new CallToolRequest("reconstruct-classes-from-rtti", 
                    Map.of("programPath", programPath)));
                
                // Our implementation now returns an error when no RTTI data is found
                assertTrue("Tool should return error when no RTTI data is found", result.isError());
                assertNotNull("Should have content", result.content());
                
                String resultText = getResultText(result);
                
                // Should provide helpful feedback about lack of RTTI data
                assertTrue("Should indicate no RTTI data found. Actual response: " + resultText,
                          resultText.contains("does not appear to contain RTTI data") || 
                          resultText.contains("no RTTI") ||
                          resultText.contains("RTTI data not found") ||
                          resultText.contains("run the RTTI analyzer"));
                
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    /**
     * Test that reconstruct-classes-from-rtti tool properly fails in test environment.
     */
    @Test
    public void testRttiReconstructionWithRunAnalysis() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                // Call the tool with runAnalysis=true
                CallToolResult result = client.callTool(new CallToolRequest("reconstruct-classes-from-rtti", 
                    Map.of("programPath", programPath, "runAnalysis", true)));
                
                assertTrue("Tool call should fail in test environment when script system unavailable", result.isError());
                assertNotNull("Should have content", result.content());
                
                String resultText = getResultText(result);
                
                // Should mention why it failed and provide guidance
                assertTrue("Should explain failure and provide guidance. Actual response: " + resultText,
                          (resultText.contains("Script system not available") ||
                           resultText.contains("Couldn't find script") ||
                           resultText.contains("test environment") ||
                           resultText.contains("bundleHost") ||
                           resultText.contains("BundleHost")) &&
                          (resultText.contains("RTTI") ||
                           resultText.contains("guidance") ||
                           resultText.contains("Ghidra")));
                
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    /**
     * Test that get-class-info tool properly reports error when class not found.
     */
    @Test
    public void testGetClassInfo() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                // Call the tool with a hypothetical class name
                CallToolResult result = client.callTool(new CallToolRequest("get-class-info", 
                    Map.of("programPath", programPath, "className", "TestClass")));
                
                assertTrue("Tool call should error when class not found", result.isError());
                assertNotNull("Should have content", result.content());
                
                String resultText = getResultText(result);
                
                // Should indicate class was not found and provide guidance
                assertTrue("Should indicate class not found and provide guidance. Actual response: " + resultText,
                          resultText.contains("Class namespace not found") &&
                          resultText.contains("TestClass") &&
                          (resultText.contains("list-classes") || 
                           resultText.contains("RTTI")));
                
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    /**
     * Helper method to extract text content from CallToolResult
     */
    private String getResultText(CallToolResult result) {
        if (result.content() == null || result.content().isEmpty()) {
            return "";
        }
        
        StringBuilder fullResultText = new StringBuilder();
        for (int i = 0; i < result.content().size(); i++) {
            String contentText = ((TextContent) result.content().get(i)).text();
            fullResultText.append(contentText);
            if (i < result.content().size() - 1) {
                fullResultText.append(" ");
            }
        }
        return fullResultText.toString();
    }
}
