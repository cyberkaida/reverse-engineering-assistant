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

    @Test
    public void testSearchStringsRegexWithValidPattern() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Search for strings containing "String"
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("regexPattern", ".*String.*");

            CallToolResult result = client.callTool(new CallToolRequest("search-strings-regex", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not have error");
            assertNotNull("Result content should not be null", result.content());
            assertFalse("Result content should not be empty", result.content().isEmpty());

            // Parse the JSON content
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            // Should be an array with metadata first, then matching strings
            assertTrue("Result should be an array", json.isArray());
            assertTrue("Result should have at least metadata", json.size() >= 1);

            // Check metadata (first element)
            JsonNode metadata = json.get(0);
            assertTrue("Metadata should have regexPattern", metadata.has("regexPattern"));
            assertTrue("Metadata should have totalStringsProcessed", metadata.has("totalStringsProcessed"));
            assertTrue("Metadata should have totalMatches", metadata.has("totalMatches"));
            assertTrue("Metadata should have actualCount", metadata.has("actualCount"));

            assertEquals("Regex pattern should match", ".*String.*", metadata.get("regexPattern").asText());

            int totalMatches = metadata.get("totalMatches").asInt();
            int actualCount = metadata.get("actualCount").asInt();

            // Should find at least 2 strings: "Test String" and "Another String"
            assertTrue("Should find at least 2 matches", totalMatches >= 2);
            assertEquals("Should have metadata + matching strings", 1 + actualCount, json.size());

            // Verify the matching strings contain "String"
            for (int i = 1; i <= actualCount; i++) {
                JsonNode stringEntry = json.get(i);
                String content2 = stringEntry.get("content").asText();
                assertTrue("String should contain 'String': " + content2, content2.contains("String"));
            }
        });
    }

    @Test
    public void testSearchStringsRegexWithExactMatch() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Search for exact match of "Hello World"
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("regexPattern", "^Hello World$");

            CallToolResult result = client.callTool(new CallToolRequest("search-strings-regex", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not have error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            JsonNode metadata = json.get(0);
            int totalMatches = metadata.get("totalMatches").asInt();
            int actualCount = metadata.get("actualCount").asInt();

            // Should find exactly 1 match
            assertEquals("Should find exactly 1 match", 1, totalMatches);
            assertEquals("Actual count should be 1", 1, actualCount);

            // Verify the match
            if (actualCount > 0) {
                JsonNode stringEntry = json.get(1);
                assertEquals("String should be 'Hello World'", "Hello World", stringEntry.get("content").asText());
            }
        });
    }

    @Test
    public void testSearchStringsRegexWithNoMatches() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Search for pattern that won't match anything
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("regexPattern", "^NoMatchPattern12345$");

            CallToolResult result = client.callTool(new CallToolRequest("search-strings-regex", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not have error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            JsonNode metadata = json.get(0);
            assertEquals("Total matches should be 0", 0, metadata.get("totalMatches").asInt());
            assertEquals("Actual count should be 0", 0, metadata.get("actualCount").asInt());
            assertEquals("Result should only have metadata", 1, json.size());
        });
    }

    @Test
    public void testSearchStringsRegexWithInvalidPattern() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Invalid regex pattern
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("regexPattern", "[invalid(regex");

            CallToolResult result = client.callTool(new CallToolRequest("search-strings-regex", arguments));

            // Should return an error for invalid regex
            assertNotNull("Result should not be null", result);

            // The tool should return an error result
            TextContent content = (TextContent) result.content().get(0);
            String text = content.text();
            assertTrue("Should contain error about invalid regex",
                text.contains("Invalid regex pattern") || text.contains("error"));
        });
    }

    @Test
    public void testSearchStringsRegexWithPagination() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Search with pagination - get only 1 result at a time
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("regexPattern", ".*");  // Match all strings
            arguments.put("startIndex", 0);
            arguments.put("maxCount", 1);

            CallToolResult result = client.callTool(new CallToolRequest("search-strings-regex", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not have error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            JsonNode metadata = json.get(0);
            int totalMatches = metadata.get("totalMatches").asInt();
            int actualCount = metadata.get("actualCount").asInt();

            // Should return at most 1 match
            assertTrue("Should return at most 1 match", actualCount <= 1);

            // If there are more matches, test second page
            if (totalMatches > 1) {
                arguments.put("startIndex", 1);
                CallToolResult secondResult = client.callTool(new CallToolRequest("search-strings-regex", arguments));

                TextContent secondContent = (TextContent) secondResult.content().get(0);
                JsonNode secondJson = parseJsonContent(secondContent.text());

                JsonNode secondMetadata = secondJson.get(0);
                assertEquals("Second page start index should be 1", 1, secondMetadata.get("startIndex").asInt());

                // Verify we get different content on second page
                if (secondJson.size() > 1 && json.size() > 1) {
                    String firstPageString = json.get(1).get("content").asText();
                    String secondPageString = secondJson.get(1).get("content").asText();
                    assertNotEquals("Second page should have different string", firstPageString, secondPageString);
                }
            }
        });
    }

    @Test
    public void testSearchStringsRegexWithNoArguments() throws Exception {
        verifyMcpToolFailsWithError("search-strings-regex", new HashMap<>(), "program");
    }

    @Test
    public void testSearchStringsRegexWithMissingPattern() throws Exception {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("programPath", programPath);

        verifyMcpToolFailsWithError("search-strings-regex", arguments, "pattern");
    }

    @Test
    public void testSearchStringsRegexWithInvalidProgramPath() throws Exception {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("programPath", "/invalid/path");
        arguments.put("regexPattern", ".*");

        verifyMcpToolFailsWithError("search-strings-regex", arguments, "Program");
    }
}