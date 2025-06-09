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
package reva.plugin;

import static org.junit.Assert.*;

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.junit.Before;
import org.junit.After;

import com.fasterxml.jackson.databind.JsonNode;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema.ListToolsResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import reva.RevaIntegrationTestBase;

/**
 * Integration tests for the MCP server functionality in RevaPlugin
 */
public class RevaPluginMcpIntegrationTest extends RevaIntegrationTestBase {

    private ConfigManager configManager;

    @Before
    public void setUpMcpTest() throws Exception {
        // Get the config manager from the plugin's server manager
        // The plugin already has its own ConfigManager instance
        configManager = reva.util.RevaInternalServiceRegistry.getService(ConfigManager.class);
        assertNotNull("ConfigManager should be registered", configManager);
    }

    @After
    public void tearDownMcpTest() throws Exception {
        // No need to disable server - let the plugin manage its own lifecycle
    }

    @Test
    public void testMcpServerStarts() throws Exception {
        // The server starts asynchronously, so we need to give it more time
        // and retry a few times
        int port = configManager.getServerPort();
        URL url = URI.create("http://localhost:" + port + "/").toURL();

        boolean connected = false;
        Exception lastException = null;

        // Try to connect up to 10 times with 500ms delay between attempts
        for (int i = 0; i < 10; i++) {
            try {
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("GET");
                connection.setConnectTimeout(1000);
                connection.setReadTimeout(1000);

                int responseCode = connection.getResponseCode();

                // The MCP server should respond with something (even if it's an error for GET)
                // We're just checking that it's listening
                if (responseCode > 0) {
                    connected = true;
                    break;
                }
            } catch (Exception e) {
                lastException = e;
                Thread.sleep(500); // Wait before retrying
            }
        }

        assertTrue("Should be able to connect to MCP server" +
                   (lastException != null ? ": " + lastException.getMessage() : ""),
                   connected);
    }

    @Test
    public void testServerConfiguration() {
        assertTrue("Server should be enabled", configManager.isServerEnabled());
        // Check that the server is using the default port (8080)
        assertEquals("Server port should be default", 8080, configManager.getServerPort());
    }

    @Test
    public void testToolsAreRegistered() throws Exception {
        // Wait a bit for server to fully initialize
        Thread.sleep(1000);

        try {
            ListToolsResult toolsResult = getAvailableTools();
            assertNotNull("Tools result should not be null", toolsResult);

            List<Tool> tools = toolsResult.tools();
            assertNotNull("Tools list should not be null", tools);
            assertFalse("Should have at least one tool registered", tools.isEmpty());

            // Verify we have tools registered
            assertTrue("Should have multiple tools registered", tools.size() > 5);

            // Verify that tools have required properties
            for (Tool tool : tools) {
                assertNotNull("Tool name should not be null", tool.name());
                assertFalse("Tool name should not be empty", tool.name().trim().isEmpty());
                assertNotNull("Tool description should not be null", tool.description());
            }
        } catch (Exception e) {
            fail("Failed to connect to MCP server: " + e.getMessage());
            throw e;
        }
    }

    @Test
    public void testExpectedToolsArePresent() throws Exception {
        ListToolsResult toolsResult = getAvailableTools();
        List<Tool> tools = toolsResult.tools();

        // Convert to a list of tool names for easier checking
        List<String> toolNames = tools.stream()
            .map(Tool::name)
            .collect(java.util.stream.Collectors.toList());

        // Check for some expected tool categories - these should be present based on the tool providers
        assertTrue("Should have memory-related tools",
            toolNames.stream().anyMatch(name -> name.contains("memory")));
        assertTrue("Should have function-related tools",
            toolNames.stream().anyMatch(name -> name.contains("function")));
        assertTrue("Should have string-related tools",
            toolNames.stream().anyMatch(name -> name.contains("string")));
        assertTrue("Should have symbol-related tools",
            toolNames.stream().anyMatch(name -> name.contains("symbol")));
    }

    /**
     * Regression test for program lookup bug that caused tools to hang when programs change.
     * This test verifies that tools can find programs without requiring special test masking.
     *
     * Background: Previously, RevaProgramManager.getProgramByPath() failed in test environments
     * because ToolManager.getRunningTools() returned empty arrays. The fix added a fallback
     * mechanism to check the RevaPlugin tool directly.
     */
    @Test
    public void testProgramLookupAfterProgramChanges() throws Exception {
        // Create a test function for verification
        String programPath = program.getDomainFile().getPathname();
        int txId = program.startTransaction("Add test function for regression test");
        try {
            Address funcAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);

            // Add a simple instruction sequence (ret instruction)
            byte[] retBytes = {(byte) 0xc3}; // x86 ret instruction
            program.getMemory().setBytes(funcAddr, retBytes);

            // Create the instruction first
            ghidra.app.cmd.disassemble.DisassembleCommand cmd = new ghidra.app.cmd.disassemble.DisassembleCommand(
                funcAddr, null, true);
            cmd.applyTo(program, TaskMonitor.DUMMY);

            // Create address set for the function body
            ghidra.program.model.address.AddressSet funcBody = new ghidra.program.model.address.AddressSet(funcAddr, funcAddr);

            // Now create the function
            FunctionManager funcMgr = program.getFunctionManager();
            funcMgr.createFunction("testRegressionFunction", funcAddr, funcBody, ghidra.program.model.symbol.SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(txId, true);
        }

        // Verify program is opened through normal flow (no special test masking)
        env.open(program);
        ProgramManager programManager = tool.getService(ProgramManager.class);
        if (programManager != null) {
            programManager.openProgram(program);
        }
        if (serverManager != null) {
            serverManager.programOpened(program, tool);
        }

        // Test 1: Verify basic tool call works
        Map<String, Object> getDecompArgs = new HashMap<>();
        getDecompArgs.put("programPath", programPath);
        getDecompArgs.put("functionNameOrAddress", "testRegressionFunction");

        String result = callMcpTool("get-decompilation", getDecompArgs);
        JsonNode resultJson = parseJsonContent(result);
        assertTrue("Tool should succeed with normal program lookup", resultJson.has("decompilation"));

        // Test 2: Simulate program change by closing and reopening
        if (serverManager != null) {
            serverManager.programClosed(program, tool);
        }
        programManager.closeProgram(program, false);

        // Reopen the program
        programManager.openProgram(program);
        if (serverManager != null) {
            serverManager.programOpened(program, tool);
        }

        // Test 3: Verify tool still works after program change
        String result2 = callMcpTool("get-decompilation", getDecompArgs);
        JsonNode resultJson2 = parseJsonContent(result2);
        assertTrue("Tool should still work after program change (regression test)", resultJson2.has("decompilation"));
    }
}