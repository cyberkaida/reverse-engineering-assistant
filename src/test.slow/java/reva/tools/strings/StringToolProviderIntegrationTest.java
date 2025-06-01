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
package reva.tools.strings;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.Listing;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.ListToolsResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import reva.RevaIntegrationTestBase;

/**
 * Integration tests for StringToolProvider using MCP client.
 * Tests the full end-to-end flow from MCP client through the server to Ghidra.
 */
public class StringToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;
    private Address stringAddress1;
    private Address stringAddress2;
    private Address stringAddress3;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();
        
        // Set up test string data in the program
        int txId = program.startTransaction("Setup test string data");
        try {
            Listing listing = program.getListing();

            // Create test addresses for strings
            stringAddress1 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
            stringAddress2 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000200);
            stringAddress3 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000300);

            // Create string data at these addresses
            String testString1 = "Hello World";
            String testString2 = "Test String";
            String testString3 = "Another String";

            // Write string bytes to memory (including null terminator for terminated strings)
            byte[] bytes1 = (testString1 + "\0").getBytes();
            byte[] bytes2 = (testString2 + "\0").getBytes();
            byte[] bytes3 = (testString3 + "\0").getBytes();

            program.getMemory().setBytes(stringAddress1, bytes1);
            program.getMemory().setBytes(stringAddress2, bytes2);
            program.getMemory().setBytes(stringAddress3, bytes3);

            // Create string data types at these addresses - use different types for variety
            listing.createData(stringAddress1, new StringDataType(), testString1.length());
            listing.createData(stringAddress2, new TerminatedStringDataType(), bytes2.length);
            listing.createData(stringAddress3, new StringDataType(), testString3.length());

        } finally {
            program.endTransaction(txId, true);
        }

        // Open the program in the tool's ProgramManager so it can be found by RevaProgramManager
        env.open(program);
        
        // Also open it directly in the tool's ProgramManager service to ensure it's available
        ghidra.app.services.ProgramManager programManager = tool.getService(ghidra.app.services.ProgramManager.class);
        if (programManager != null) {
            programManager.openProgram(program);
        }
        
        // Register the program directly with RevaProgramManager for test environments
        reva.plugin.RevaProgramManager.registerProgram(program);
        
        // Register the program with the server manager so it can be found by the tools
        if (serverManager != null) {
            serverManager.programOpened(program);
        }
    }

    @Test
    public void testListToolsIncludesStringTools() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            ListToolsResult tools = client.listTools(null);
            assertNotNull("Tools result should not be null", tools);
            assertNotNull("Tools list should not be null", tools.tools());

            // Look for our string tools
            boolean foundGetStringsCount = false;
            boolean foundGetStrings = false;

            for (Tool tool : tools.tools()) {
                if ("get-strings-count".equals(tool.name())) {
                    foundGetStringsCount = true;
                    assertEquals("get-strings-count description should match",
                        "Get the total count of strings in the program (use this before calling get-strings to plan pagination)",
                        tool.description());
                }
                if ("get-strings".equals(tool.name())) {
                    foundGetStrings = true;
                    assertEquals("get-strings description should match",
                        "Get strings from the selected program with pagination (use get-strings-count first to determine total count)",
                        tool.description());
                }
            }

            assertTrue("get-strings-count tool should be available", foundGetStringsCount);
            assertTrue("get-strings tool should be available", foundGetStrings);
        });
    }

    @Test
    public void testGetStringsCountWithValidProgram() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);

            CallToolResult result = client.callTool(new CallToolRequest("get-strings-count", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result get-strings-count should not be an error");
            assertNotNull("Result content should not be null", result.content());
            assertFalse("Result content should not be empty", result.content().isEmpty());

            // Parse the JSON content
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Result should contain count field", json.has("count"));
            int count = json.get("count").asInt();

            // We added 3 test strings, so count should be at least 3
            assertTrue("String count should be at least 3, but was: " + count, count >= 3);
        });
    }

    @Test
    public void testGetStringsWithValidProgram() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("startIndex", 0);
            arguments.put("maxCount", 10);

            CallToolResult result = client.callTool(new CallToolRequest("get-strings", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not have error");
            assertNotNull("Result content should not be null", result.content());
            assertFalse("Result content should not be empty", result.content().isEmpty());

            // Parse the JSON content
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            // Should be an array with pagination info first, then string data
            assertTrue("Result should be an array", json.isArray());
            assertTrue("Result should have at least pagination info", json.size() >= 1);

            // Check pagination info (first element)
            JsonNode paginationInfo = json.get(0);
            assertTrue("Pagination info should have startIndex", paginationInfo.has("startIndex"));
            assertTrue("Pagination info should have requestedCount", paginationInfo.has("requestedCount"));
            assertTrue("Pagination info should have actualCount", paginationInfo.has("actualCount"));
            assertTrue("Pagination info should have nextStartIndex", paginationInfo.has("nextStartIndex"));

            assertEquals("Start index should be 0", 0, paginationInfo.get("startIndex").asInt());
            assertEquals("Requested count should be 10", 10, paginationInfo.get("requestedCount").asInt());

            // Check string data (remaining elements)
            int actualCount = paginationInfo.get("actualCount").asInt();
            if (actualCount > 0) {
                // Verify we have the right number of string entries
                assertEquals("Should have pagination info + string data",
                    1 + actualCount, json.size());

                // Check the first string entry
                JsonNode firstString = json.get(1);
                assertTrue("String should have address", firstString.has("address"));
                assertTrue("String should have content", firstString.has("content"));
                assertTrue("String should have length", firstString.has("length"));
                assertTrue("String should have dataType", firstString.has("dataType"));
                assertTrue("String should have representation", firstString.has("representation"));

                // Verify address format
                String address = firstString.get("address").asText();
                assertTrue("Address should start with 0x", address.startsWith("0x"));

                // Verify content is not empty
                String stringContent = firstString.get("content").asText();
                assertFalse("String content should not be empty", stringContent.isEmpty());

                // Verify length matches content
                int length = firstString.get("length").asInt();
                assertEquals("Length should match content length", stringContent.length(), length);

                // Verify we can find our test strings
                boolean foundTestString = false;
                for (int i = 1; i <= actualCount; i++) {
                    JsonNode stringEntry = json.get(i);
                    String entryContent = stringEntry.get("content").asText();
                    if ("Hello World".equals(entryContent) || "Test String".equals(entryContent) || "Another String".equals(entryContent)) {
                        foundTestString = true;
                        break;
                    }
                }
                assertTrue("Should find at least one of our test strings", foundTestString);
            }
        });
    }

    @Test
    public void testGetStringsWithPagination() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First, get strings count
            Map<String, Object> countArgs = new HashMap<>();
            countArgs.put("programPath", programPath);

            CallToolResult countResult = client.callTool(new CallToolRequest("get-strings-count", countArgs));
            TextContent countContent = (TextContent) countResult.content().get(0);
            JsonNode countJson = parseJsonContent(countContent.text());
            int totalCount = countJson.get("count").asInt();

            if (totalCount > 1) {
                // Test pagination by requesting strings in chunks of 1
                Map<String, Object> arguments = new HashMap<>();
                arguments.put("programPath", programPath);
                arguments.put("startIndex", 0);
                arguments.put("maxCount", 1);

                CallToolResult result = client.callTool(new CallToolRequest("get-strings", arguments));
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());

                JsonNode paginationInfo = json.get(0);
                int actualCount = paginationInfo.get("actualCount").asInt();
                int nextStartIndex = paginationInfo.get("nextStartIndex").asInt();

                // Should return at most 1 string
                assertTrue("Should return at most 1 string", actualCount <= 1);
                assertEquals("Next start index should be 0 + actualCount", actualCount, nextStartIndex);

                // Test second page if there are more strings
                if (nextStartIndex < totalCount) {
                    arguments.put("startIndex", nextStartIndex);
                    CallToolResult secondResult = client.callTool(new CallToolRequest("get-strings", arguments));
                    TextContent secondContent = (TextContent) secondResult.content().get(0);
                    JsonNode secondJson = parseJsonContent(secondContent.text());

                    JsonNode secondPaginationInfo = secondJson.get(0);
                    assertEquals("Second page start index should match",
                        nextStartIndex, secondPaginationInfo.get("startIndex").asInt());
                }
            }
        });
    }

    @Test
    public void testGetStringsWithDefaultParameters() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test with only programPath (should use default startIndex=0, maxCount=100)
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);

            CallToolResult result = client.callTool(new CallToolRequest("get-strings", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not have error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            JsonNode paginationInfo = json.get(0);
            assertEquals("Default start index should be 0", 0, paginationInfo.get("startIndex").asInt());
            assertEquals("Default max count should be 100", 100, paginationInfo.get("requestedCount").asInt());
        });
    }

    @Test
    public void testGetStringsWithNoArguments() throws Exception {
        verifyMcpToolFailsWithError("get-strings", new HashMap<>(), "program");
    }

    @Test
    public void testGetStringsCountWithNoArguments() throws Exception {
        verifyMcpToolFailsWithError("get-strings-count", new HashMap<>(), "program");
    }

    @Test
    public void testGetStringsWithInvalidProgramPath() throws Exception {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("programPath", "/this/path/does/not/exist");

        verifyMcpToolFailsWithError("get-strings", arguments, "Program");
    }

    @Test
    public void testGetStringsCountWithInvalidProgramPath() throws Exception {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("programPath", "/this/path/does/not/exist");

        verifyMcpToolFailsWithError("get-strings-count", arguments, "Program");
    }

    @Test
    public void testStringDataSetupVerification() throws Exception {
        // Verify the test string data was set up correctly
        Listing listing = program.getListing();

        // Check that string data exists at our test addresses
        ghidra.program.model.listing.Data data1 = listing.getDataAt(stringAddress1);
        assertNotNull("String data should exist at stringAddress1", data1);
        assertTrue("Data should be a string", data1.getValue() instanceof String);
        assertEquals("String content should match", "Hello World", (String) data1.getValue());

        ghidra.program.model.listing.Data data2 = listing.getDataAt(stringAddress2);
        assertNotNull("String data should exist at stringAddress2", data2);
        assertTrue("Data should be a string", data2.getValue() instanceof String);
        assertEquals("String content should match", "Test String", (String) data2.getValue());

        ghidra.program.model.listing.Data data3 = listing.getDataAt(stringAddress3);
        assertNotNull("String data should exist at stringAddress3", data3);
        assertTrue("Data should be a string", data3.getValue() instanceof String);
        assertEquals("String content should match", "Another String", (String) data3.getValue());
    }
}