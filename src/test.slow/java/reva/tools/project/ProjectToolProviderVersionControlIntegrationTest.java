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

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.spec.McpSchema;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for version control operations in ProjectToolProvider.
 * Tests fix for issue #154 (save before checkin) and save fallback for unversioned files.
 */
public class ProjectToolProviderVersionControlIntegrationTest extends RevaIntegrationTestBase {

    private ObjectMapper objectMapper;

    @Before
    public void setUp() {
        objectMapper = new ObjectMapper();
    }

    /**
     * Test checkin-program works correctly.
     * This test verifies the fix for issue #154 - the tool should handle saves properly.
     */
    @Test
    public void testCheckinProgram() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Create a test program
                Program program = createDefaultProgram("test-checkin", "x86:LE:64:default", this);
                String programPath = program.getDomainFile().getPathname();

                // Make changes to the program (add a label)
                int transactionID = program.startTransaction("Add test label");
                try {
                    SymbolTable symbolTable = program.getSymbolTable();
                    symbolTable.createLabel(program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000),
                        "test_label", SourceType.USER_DEFINED);
                    program.endTransaction(transactionID, true);
                } catch (Exception e) {
                    program.endTransaction(transactionID, false);
                    throw e;
                }

                // Try to checkin - this should save first, then add to version control or save
                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "checkin-program",
                    Map.of(
                        "programPath", programPath,
                        "message", "Test commit"
                    )
                ));

                // Verify the response
                assertNotNull("Result should not be null", result);
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertEquals("Checkin should be successful", true, response.get("success"));

                // Should either be added_to_version_control (new file) or saved (if not versioned)
                String action = (String) response.get("action");
                assertTrue("Action should be added_to_version_control or saved",
                    "added_to_version_control".equals(action) || "saved".equals(action));

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            }
        });
    }

    /**
     * Test checkin-program returns appropriate action based on version control support.
     * This test verifies that the tool handles both versioned and unversioned files correctly.
     */
    @Test
    public void testCheckinHandlesVersionControlStatus() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Create a test program
                Program program = createDefaultProgram("test-unversioned", "x86:LE:64:default", this);
                String programPath = program.getDomainFile().getPathname();
                DomainFile domainFile = program.getDomainFile();

                // Make changes to the program
                int transactionID = program.startTransaction("Add test label");
                try {
                    SymbolTable symbolTable = program.getSymbolTable();
                    symbolTable.createLabel(program.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000),
                        "test_label_unversioned", SourceType.USER_DEFINED);
                    program.endTransaction(transactionID, true);
                } catch (Exception e) {
                    program.endTransaction(transactionID, false);
                    throw e;
                }

                // Check if file can be added to version control
                boolean canAddToVCS = domainFile.canAddToRepository();

                // Try to checkin - should work regardless of version control support
                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "checkin-program",
                    Map.of(
                        "programPath", programPath,
                        "message", "Test commit"
                    )
                ));

                // Verify the response
                assertNotNull("Result should not be null", result);
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertEquals("Operation should be successful", true, response.get("success"));

                // Action should depend on version control support
                String action = (String) response.get("action");
                assertNotNull("Action should be present", action);

                if (canAddToVCS) {
                    assertEquals("Action should be added_to_version_control when supported", "added_to_version_control", action);
                } else {
                    assertEquals("Action should be saved when version control not supported", "saved", action);
                    assertEquals("Response should indicate file is not versioned", false, response.get("isVersioned"));
                }

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            }
        });
    }

    /**
     * Test that checkin-program accepts commit message parameter.
     */
    @Test
    public void testCheckinWithCommitMessage() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Create a test program
                Program program = createDefaultProgram("test-message", "x86:LE:64:default", this);
                String programPath = program.getDomainFile().getPathname();

                // Make changes to the program
                int transactionID = program.startTransaction("Add test label");
                try {
                    SymbolTable symbolTable = program.getSymbolTable();
                    symbolTable.createLabel(program.getAddressFactory().getDefaultAddressSpace().getAddress(0x3000),
                        "test_label_message", SourceType.USER_DEFINED);
                    program.endTransaction(transactionID, true);
                } catch (Exception e) {
                    program.endTransaction(transactionID, false);
                    throw e;
                }

                String commitMessage = "Test commit message for version control";

                // Try to checkin with specific message
                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "checkin-program",
                    Map.of(
                        "programPath", programPath,
                        "message", commitMessage
                    )
                ));

                // Verify the response
                assertNotNull("Result should not be null", result);
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertEquals("Operation should be successful", true, response.get("success"));
                assertEquals("Response should include the commit message", commitMessage, response.get("message"));

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            }
        });
    }
}
