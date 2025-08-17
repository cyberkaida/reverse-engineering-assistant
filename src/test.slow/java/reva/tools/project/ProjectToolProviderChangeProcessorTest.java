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
            programPath = program.getDomainFile().getPathname();
            originalLanguage = program.getLanguage().getLanguageID().getIdAsString();
            originalCompilerSpec = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
        }
    }

    @Test
    public void testChangeProcessorX86To8051() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("processorSpec", "8051:BE:16:default");

            CallToolResult result = client.callTool(new CallToolRequest("change-processor", args));

            // Validate MCP response
            assertNotNull("Result should not be null", result);
            assertTrue("Should have content", !result.content().isEmpty());

            String responseText = ((TextContent) result.content().get(0)).text();
            assertFalse("Response should not be an error", responseText.contains("error"));
            assertTrue("Response should indicate success", responseText.contains("\"success\":true"));

            // Parse JSON response
            JsonNode response = mapper.readTree(responseText);
            assertTrue("Should report success", response.get("success").asBoolean());
            assertEquals("Should show old language", originalLanguage, response.get("oldLanguage").asText());
            assertEquals("Should show old compiler spec", originalCompilerSpec, response.get("oldCompilerSpec").asText());
            
            String newLanguage = response.get("newLanguage").asText();
            String newCompilerSpec = response.get("newCompilerSpec").asText();
            assertTrue("Should use 8051 language", newLanguage.contains("8051"));
            
            // Validate actual program state changed
            String actualNewLanguage = program.getLanguage().getLanguageID().getIdAsString();
            String actualNewCompilerSpec = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
            
            assertEquals("Program language should be changed", newLanguage, actualNewLanguage);
            assertEquals("Program compiler spec should be changed", newCompilerSpec, actualNewCompilerSpec);
            assertNotEquals("Language should have changed", originalLanguage, actualNewLanguage);
        });
    }

    @Test
    public void testChangeProcessorWithCurrentKeyword() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", "current");
            args.put("processorSpec", "8051:BE:16:default");

            CallToolResult result = client.callTool(new CallToolRequest("change-processor", args));

            // Should work with "current" keyword
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Response should indicate success", responseText.contains("\"success\":true"));

            JsonNode response = mapper.readTree(responseText);
            String newLanguage = response.get("newLanguage").asText();
            assertTrue("Should use 8051 language", newLanguage.contains("8051"));
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
                JsonNode response = mapper.readTree(responseText);
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

            // First change to 8051
            Map<String, Object> args1 = new HashMap<>();
            args1.put("programPath", programPath);
            args1.put("processorSpec", "8051:BE:16:default");

            CallToolResult result1 = client.callTool(new CallToolRequest("change-processor", args1));
            String responseText1 = ((TextContent) result1.content().get(0)).text();
            assertTrue("First change should succeed", responseText1.contains("\"success\":true"));
            
            // Verify program changed
            String intermediateLanguage = program.getLanguage().getLanguageID().getIdAsString();
            assertTrue("Should be 8051 now", intermediateLanguage.contains("8051"));

            // Change back to x86
            Map<String, Object> args2 = new HashMap<>();
            args2.put("programPath", programPath);
            args2.put("processorSpec", "x86:LE:32:default");

            CallToolResult result2 = client.callTool(new CallToolRequest("change-processor", args2));
            String responseText2 = ((TextContent) result2.content().get(0)).text();
            assertTrue("Second change should succeed", responseText2.contains("\"success\":true"));
            
            // Verify program changed back
            String finalLanguage = program.getLanguage().getLanguageID().getIdAsString();
            assertTrue("Should be x86 again", finalLanguage.contains("x86"));
        });
    }
}