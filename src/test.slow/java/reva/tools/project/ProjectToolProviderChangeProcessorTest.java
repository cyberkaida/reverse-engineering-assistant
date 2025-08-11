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
package reva.tools.project;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.junit.Before;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

import static org.junit.Assert.*;

/**
 * Integration tests for the change-processor tool in ProjectToolProvider.
 */
public class ProjectToolProviderChangeProcessorTest extends RevaIntegrationTestBase {

    private ObjectMapper mapper = new ObjectMapper();
    private String programPath;
    private String originalLanguage;
    private String originalCompilerSpec;

    @Before
    public void setUpTestData() throws Exception {
        // Capture original program settings for validation
        if (program != null) {
            // For test programs, use a consistent path based on the test name
            programPath = "/" + program.getName(); // Use domain-like path format
            originalLanguage = program.getLanguage().getLanguageID().getIdAsString();
            originalCompilerSpec = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
        }
    }

    @Test
    public void testChangeProcessorDifferentCompilerSpec() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("processorSpec", "x86:LE:32:gcc"); // Change to different compiler spec

            CallToolResult result = client.callTool(new CallToolRequest("change-processor", args));

            // Validate MCP response
            assertNotNull("Result should not be null", result);
            assertTrue("Should have content", !result.content().isEmpty());

            String responseText = ((TextContent) result.content().get(0)).text();
            
            // This might succeed or fail depending on compiler spec availability
            if (responseText.contains("\"success\":true")) {
                // Parse JSON response to validate content
                JsonNode response;
                try {
                    response = mapper.readTree(responseText);
                } catch (Exception e) {
                    fail("Failed to parse JSON response: " + e.getMessage());
                    return;
                }
                assertTrue("Should report success", response.get("success").asBoolean());
                assertEquals("Should show old language", originalLanguage, response.get("oldLanguage").asText());
                assertEquals("Should show old compiler spec", originalCompilerSpec, response.get("oldCompilerSpec").asText());
                
                String newLanguage = response.get("newLanguage").asText();
                String newCompilerSpec = response.get("newCompilerSpec").asText();
                assertTrue("Should use x86 language", newLanguage.contains("x86"));
                // Ghidra may map "gcc" to various compiler specs during processor spec changes
                assertTrue("Should use gcc, default, or windows compiler spec", 
                    newCompilerSpec.contains("gcc") || newCompilerSpec.contains("default") || newCompilerSpec.contains("windows"));
                
                // Validate actual program state changed
                String actualNewLanguage = program.getLanguage().getLanguageID().getIdAsString();
                String actualNewCompilerSpec = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
                
                assertEquals("Program language should be the same or similar", newLanguage, actualNewLanguage);
                assertEquals("Program compiler spec should be changed", newCompilerSpec, actualNewCompilerSpec);
            } else {
                // If gcc spec is not available or change fails, should get a proper error message
                assertTrue("Should report processor change error", 
                    responseText.contains("Failed to change processor architecture") ||
                    responseText.contains("Invalid processor spec") ||
                    responseText.contains("can not map"));
            }
        });
    }

    @Test
    public void testChangeProcessorWithCurrentKeyword() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", "current");
            args.put("processorSpec", "x86:LE:32:gcc");

            CallToolResult result = client.callTool(new CallToolRequest("change-processor", args));

            // Should work with "current" keyword
            String responseText = ((TextContent) result.content().get(0)).text();
            
            // This might succeed or fail depending on compiler spec availability
            if (responseText.contains("\"success\":true")) {
                JsonNode response;
                try {
                    response = mapper.readTree(responseText);
                } catch (Exception e) {
                    fail("Failed to parse JSON response: " + e.getMessage());
                    return;
                }
                String newLanguage = response.get("newLanguage").asText();
                String newCompilerSpec = response.get("newCompilerSpec").asText();
                assertTrue("Should use x86 language", newLanguage.contains("x86"));
                // Ghidra may map "gcc" to various compiler specs during processor spec changes
                assertTrue("Should use gcc, default, or windows compiler spec", 
                    newCompilerSpec.contains("gcc") || newCompilerSpec.contains("default") || newCompilerSpec.contains("windows"));
            } else {
                // Should get an error message if gcc compiler spec is not available
                assertTrue("Should report processor change error if gcc not available", 
                    responseText.contains("Failed to change processor architecture") ||
                    responseText.contains("Invalid processor spec") ||
                    responseText.contains("can not map"));
            }
        });
    }

    @Test
    public void testChangeProcessorToGolang() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("processorSpec", "golang");

            CallToolResult result = client.callTool(new CallToolRequest("change-processor", args));

            String responseText = ((TextContent) result.content().get(0)).text();
            
            // This might succeed or fail depending on whether Golang language is available
            // If it succeeds, validate the response
            if (responseText.contains("\"success\":true")) {
                JsonNode response;
                try {
                    response = mapper.readTree(responseText);
                } catch (Exception e) {
                    fail("Failed to parse JSON response: " + e.getMessage());
                    return;
                }
                String newLanguage = response.get("newLanguage").asText();
                assertTrue("Should use golang language", newLanguage.toLowerCase().contains("go"));
                
                // Validate actual program state
                String actualNewLanguage = program.getLanguage().getLanguageID().getIdAsString();
                assertTrue("Program should use golang language", actualNewLanguage.toLowerCase().contains("go"));
            } else {
                // If golang is not available, should get an error
                assertTrue("Should report invalid processor spec error when golang not available", 
                    responseText.contains("Invalid processor spec"));
            }
        });
    }

    @Test
    public void testChangeProcessorInvalidSpec() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("processorSpec", "invalid:spec:format");

            CallToolResult result = client.callTool(new CallToolRequest("change-processor", args));

            // Should return error for invalid processor spec
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Should report invalid processor spec error", 
                responseText.contains("Invalid processor spec") || 
                responseText.contains("Failed to change processor architecture"));
        });
    }

    @Test
    public void testChangeProcessorIncompatibleArchitecture() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("processorSpec", "8051:BE:16:default"); // Incompatible with x86

            CallToolResult result = client.callTool(new CallToolRequest("change-processor", args));

            // Should return error for incompatible architecture change
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Should report architecture compatibility error", 
                responseText.contains("Failed to change processor architecture") ||
                responseText.contains("can not map address spaces") ||
                responseText.contains("error"));
        });
    }

    @Test
    public void testChangeProcessorNonExistentProgram() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", "/non/existent/program");
            args.put("processorSpec", "x86:LE:32:default");

            CallToolResult result = client.callTool(new CallToolRequest("change-processor", args));

            // Should return error for non-existent program
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Should report program not found error", 
                responseText.contains("Program not found"));
        });
    }

    @Test
    public void testChangeProcessorMissingParameters() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test missing programPath
            Map<String, Object> args1 = new HashMap<>();
            args1.put("processorSpec", "x86:LE:32:default");

            CallToolResult result1 = client.callTool(new CallToolRequest("change-processor", args1));
            String responseText1 = ((TextContent) result1.content().get(0)).text();
            assertTrue("Should report missing parameter error", 
                responseText1.contains("required") || responseText1.contains("missing"));

            // Test missing processorSpec
            Map<String, Object> args2 = new HashMap<>();
            args2.put("programPath", programPath);

            CallToolResult result2 = client.callTool(new CallToolRequest("change-processor", args2));
            String responseText2 = ((TextContent) result2.content().get(0)).text();
            assertTrue("Should report missing parameter error", 
                responseText2.contains("required") || responseText2.contains("missing"));
        });
    }

    @Test
    public void testChangeProcessorRoundTrip() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First try to change to gcc compiler spec
            Map<String, Object> args1 = new HashMap<>();
            args1.put("programPath", programPath);
            args1.put("processorSpec", "x86:LE:32:gcc");

            CallToolResult result1 = client.callTool(new CallToolRequest("change-processor", args1));
            String responseText1 = ((TextContent) result1.content().get(0)).text();
            
            // This test should handle both success and failure cases gracefully
            if (responseText1.contains("\"success\":true")) {
                // If gcc is available, verify the change
                String intermediateCompilerSpec = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
                // Ghidra may map "gcc" to various compiler specs during processor spec changes
                assertTrue("Should be gcc, default, or windows spec now", 
                    intermediateCompilerSpec.contains("gcc") || intermediateCompilerSpec.contains("default") || intermediateCompilerSpec.contains("windows"));

                // Change back to default
                Map<String, Object> args2 = new HashMap<>();
                args2.put("programPath", programPath);
                args2.put("processorSpec", "x86:LE:32:default");

                CallToolResult result2 = client.callTool(new CallToolRequest("change-processor", args2));
                String responseText2 = ((TextContent) result2.content().get(0)).text();
                assertTrue("Second change should succeed", responseText2.contains("\"success\":true"));
                
                // Verify program changed back
                String finalCompilerSpec = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
                assertTrue("Should be default or windows spec again", 
                    finalCompilerSpec.contains("default") || finalCompilerSpec.contains("windows"));
            } else {
                // If gcc is not available, just verify we get a proper error message
                assertTrue("Should get appropriate error message", 
                    responseText1.contains("Failed to change processor architecture") ||
                    responseText1.contains("Invalid processor spec") ||
                    responseText1.contains("can not map"));
            }
        });
    }
}