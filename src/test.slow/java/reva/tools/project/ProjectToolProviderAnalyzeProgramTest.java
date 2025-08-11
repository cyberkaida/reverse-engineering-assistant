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

import ghidra.program.util.GhidraProgramUtilities;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

import static org.junit.Assert.*;

/**
 * Integration tests for the analyze-program tool in ProjectToolProvider.
 */
public class ProjectToolProviderAnalyzeProgramTest extends RevaIntegrationTestBase {

    private ObjectMapper mapper = new ObjectMapper();
    private String programPath;

    @Before
    public void setUpTestData() throws Exception {
        // Get the program path for testing - use domain-like path format
        if (program != null) {
            programPath = "/" + program.getName(); // Use domain-like path format
        }
    }

    @Test
    public void testAnalyzeProgramFirstTime() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Reset analysis flags to ensure we're testing first-time analysis
            GhidraProgramUtilities.resetAnalysisFlags(program);
            assertFalse("Program should not be analyzed initially", GhidraProgramUtilities.isAnalyzed(program));

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);

            CallToolResult result = client.callTool(new CallToolRequest("analyze-program", args));

            // Validate MCP response
            assertNotNull("Result should not be null", result);
            assertTrue("Should have content", !result.content().isEmpty());

            String responseText = ((TextContent) result.content().get(0)).text();
            assertFalse("Response should not be an error", responseText.contains("error"));
            assertTrue("Response should indicate success", responseText.contains("\"success\":true"));

            // Parse JSON response
            JsonNode response;
            try {
                response = mapper.readTree(responseText);
            } catch (Exception e) {
                fail("Failed to parse JSON response: " + e.getMessage());
                return;
            }

            assertTrue("Should report success", response.get("success").asBoolean());
            assertTrue("Should have program path", response.has("programPath"));
            assertEquals("Should match program path", programPath, response.get("programPath").asText());
            
            assertFalse("Should not have been already analyzed", response.get("wasAlreadyAnalyzed").asBoolean());
            assertTrue("Should have triggered analysis", response.get("analysisTriggered").asBoolean());
            assertFalse("Should not be forced", response.get("forced").asBoolean());
            assertTrue("Should have analysis info", response.has("analysisInfo"));
            
            JsonNode analysisInfo = response.get("analysisInfo");
            assertTrue("Should have functions found", analysisInfo.has("functionsFound"));
            assertTrue("Should have symbols found", analysisInfo.has("symbolsFound"));
            assertTrue("Should have time elapsed", analysisInfo.has("timeElapsedMs"));
            assertTrue("Should have memory size", analysisInfo.has("memorySize"));

            // Validate actual program state changed
            assertTrue("Program should now be analyzed", GhidraProgramUtilities.isAnalyzed(program));
        });
    }

    @Test
    public void testAnalyzeProgramAlreadyAnalyzed() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Ensure program is already analyzed
            GhidraProgramUtilities.markProgramAnalyzed(program);
            assertTrue("Program should be analyzed", GhidraProgramUtilities.isAnalyzed(program));

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);

            CallToolResult result = client.callTool(new CallToolRequest("analyze-program", args));

            // Should get success but no analysis triggered
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Response should indicate success", responseText.contains("\"success\":true"));

            JsonNode response;
            try {
                response = mapper.readTree(responseText);
            } catch (Exception e) {
                fail("Failed to parse JSON response: " + e.getMessage());
                return;
            }

            assertTrue("Should report success", response.get("success").asBoolean());
            assertTrue("Should have been already analyzed", response.get("wasAlreadyAnalyzed").asBoolean());
            assertFalse("Should not have triggered analysis", response.get("analysisTriggered").asBoolean());
            assertTrue("Should have hint", response.has("hint"));
            assertTrue("Should have current analysis info", response.has("currentAnalysisInfo"));
            
            String hint = response.get("hint").asText();
            assertTrue("Hint should mention force parameter", hint.contains("force: true"));
        });
    }

    @Test
    public void testAnalyzeProgramForceReAnalysis() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Ensure program is already analyzed
            GhidraProgramUtilities.markProgramAnalyzed(program);
            assertTrue("Program should be analyzed", GhidraProgramUtilities.isAnalyzed(program));

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("force", true);

            CallToolResult result = client.callTool(new CallToolRequest("analyze-program", args));

            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Response should indicate success", responseText.contains("\"success\":true"));

            JsonNode response;
            try {
                response = mapper.readTree(responseText);
            } catch (Exception e) {
                fail("Failed to parse JSON response: " + e.getMessage());
                return;
            }

            assertTrue("Should report success", response.get("success").asBoolean());
            assertTrue("Should have been already analyzed", response.get("wasAlreadyAnalyzed").asBoolean());
            assertTrue("Should have triggered analysis", response.get("analysisTriggered").asBoolean());
            assertTrue("Should be forced", response.get("forced").asBoolean());
            assertTrue("Should have analysis info", response.has("analysisInfo"));
            
            String message = response.get("message").asText();
            assertTrue("Message should indicate re-analysis", message.contains("Re-analysis completed"));

            // Program should still be analyzed after force re-analysis
            assertTrue("Program should still be analyzed", GhidraProgramUtilities.isAnalyzed(program));
        });
    }

    @Test
    public void testAnalyzeProgramInvalidProgramPath() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", "/non/existent/program");

            CallToolResult result = client.callTool(new CallToolRequest("analyze-program", args));

            // Should return error for non-existent program
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Should report program not found error", 
                responseText.contains("Program not found") || 
                responseText.contains("No such program"));
        });
    }

    @Test
    public void testAnalyzeProgramMissingProgramPath() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            // Missing programPath parameter

            CallToolResult result = client.callTool(new CallToolRequest("analyze-program", args));

            // Should return error for missing parameter
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Should report missing parameter error", 
                responseText.contains("required") || 
                responseText.contains("missing") ||
                responseText.contains("programPath"));
        });
    }

    @Test
    public void testAnalyzeProgramCurrentKeyword() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Reset analysis flags
            GhidraProgramUtilities.resetAnalysisFlags(program);
            assertFalse("Program should not be analyzed initially", GhidraProgramUtilities.isAnalyzed(program));

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", "current"); // Use "current" keyword

            CallToolResult result = client.callTool(new CallToolRequest("analyze-program", args));

            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Response should indicate success with 'current' keyword", 
                responseText.contains("\"success\":true"));

            JsonNode response;
            try {
                response = mapper.readTree(responseText);
            } catch (Exception e) {
                fail("Failed to parse JSON response: " + e.getMessage());
                return;
            }

            assertTrue("Should report success", response.get("success").asBoolean());
            assertTrue("Should have triggered analysis", response.get("analysisTriggered").asBoolean());

            // Validate actual program state changed
            assertTrue("Program should now be analyzed", GhidraProgramUtilities.isAnalyzed(program));
        });
    }

    @Test
    public void testAnalyzeProgramAnalysisProgressValidation() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Reset analysis flags
            GhidraProgramUtilities.resetAnalysisFlags(program);
            
            // Get function count before analysis
            int functionsBefore = program.getFunctionManager().getFunctionCount();
            int symbolsBefore = program.getSymbolTable().getNumSymbols();

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);

            CallToolResult result = client.callTool(new CallToolRequest("analyze-program", args));

            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Response should indicate success", responseText.contains("\"success\":true"));

            JsonNode response;
            try {
                response = mapper.readTree(responseText);
            } catch (Exception e) {
                fail("Failed to parse JSON response: " + e.getMessage());
                return;
            }

            // Get function count after analysis
            int functionsAfter = program.getFunctionManager().getFunctionCount();
            int symbolsAfter = program.getSymbolTable().getNumSymbols();

            JsonNode analysisInfo = response.get("analysisInfo");
            int reportedFunctions = analysisInfo.get("functionsFound").asInt();
            int reportedSymbols = analysisInfo.get("symbolsFound").asInt();
            
            // Validate the analysis results match actual program state
            assertEquals("Reported function count should match actual", functionsAfter, reportedFunctions);
            assertEquals("Reported symbol count should match actual", symbolsAfter, reportedSymbols);
            
            // Analysis should typically find more functions and symbols (unless it's a trivial binary)
            assertTrue("Analysis time should be recorded", analysisInfo.get("timeElapsedMs").asLong() >= 0);
            assertTrue("Memory size should be positive", analysisInfo.get("memorySize").asLong() > 0);
        });
    }
}