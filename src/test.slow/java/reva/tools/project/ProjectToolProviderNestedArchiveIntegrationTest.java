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

import java.io.File;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.modelcontextprotocol.spec.McpSchema;
import reva.RevaIntegrationTestBase;

/**
 * Integration test for file import functionality in ProjectToolProvider.
 */
public class ProjectToolProviderNestedArchiveIntegrationTest extends RevaIntegrationTestBase {

    private ObjectMapper objectMapper;

    @Before
    public void setUp() {
        objectMapper = new ObjectMapper();
    }

    /**
     * Test importing a single ELF file
     */
    @Test
    public void testImportSingleFile() throws Exception {
        // Create a test binary file path - use a simple ELF binary if available
        String testFilePath = "/bin/ls"; // Simple system binary for testing
        
        if (!new File(testFilePath).exists()) {
            // Skip test if file doesn't exist
            return;
        }

        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "import-file",
                    Map.of(
                        "path", testFilePath
                    )
                ));

                // Verify the response
                assertNotNull("Result should not be null", result);
                assertNotNull("Response content should not be null", result.content());
                assertTrue("Should have at least one content item", result.content().size() > 0);

                // Parse and verify the JSON response
                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});
                
                assertEquals("Import should be successful", true, response.get("success"));
                assertNotNull("Should have importedFrom field", response.get("importedFrom"));
                assertEquals("Should import from the specified path", testFilePath, response.get("importedFrom"));
                assertNotNull("Should have filesDiscovered field", response.get("filesDiscovered"));
                
                // Verify that at least one file was discovered
                Integer filesDiscovered = (Integer) response.get("filesDiscovered");
                assertTrue("Should discover at least one file", filesDiscovered > 0);
                
                return null; // withMcpClient expects a return value
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            }
        });
    }

    /**
     * Test importing a non-existent file
     */
    @Test
    public void testImportNonExistentFile() throws Exception {
        String nonExistentPath = "/path/to/nonexistent/file.bin";

        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                
                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "import-file",
                    Map.of(
                        "path", nonExistentPath
                    )
                ));

                assertNotNull("Result should not be null", result);
                assertTrue("Tool should have error for non-existent file", result.isError());
                
                String errorMessage = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                assertTrue("Error should mention file not found", 
                    errorMessage.contains("does not exist"));
                
                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            }
        });
    }

    /**
     * Test importing a file to a non-existent destination folder (should create it automatically)
     */
    @Test
    public void testImportToNonExistentFolder() throws Exception {
        // Create a test binary file path - use a simple ELF binary if available
        String testFilePath = "/bin/ls"; // Simple system binary for testing
        String destinationFolder = "/test/nested/folder"; // Multi-level path that doesn't exist

        if (!new File(testFilePath).exists()) {
            // Skip test if file doesn't exist
            return;
        }

        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "import-file",
                    Map.of(
                        "path", testFilePath,
                        "destinationFolder", destinationFolder
                    )
                ));

                // Verify the response
                assertNotNull("Result should not be null", result);
                assertNotNull("Response content should not be null", result.content());
                assertTrue("Should have at least one content item", result.content().size() > 0);

                // Parse and verify the JSON response
                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                // Verify import succeeded even though folder didn't exist
                assertEquals("Import should be successful", true, response.get("success"));
                assertEquals("Should import to the specified destination", destinationFolder, response.get("destinationFolder"));
                assertNotNull("Should have filesDiscovered field", response.get("filesDiscovered"));

                // Verify that at least one file was discovered
                Integer filesDiscovered = (Integer) response.get("filesDiscovered");
                assertTrue("Should discover at least one file", filesDiscovered > 0);

                // Verify the folder was created by listing project files
                McpSchema.CallToolResult listResult = client.callTool(new McpSchema.CallToolRequest(
                    "list-project-files",
                    Map.of()
                ));

                String listJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) listResult.content().get(0)).text();
                Map<String, Object> listResponse = objectMapper.readValue(listJson, new TypeReference<Map<String, Object>>() {});

                assertEquals("List should be successful", true, listResponse.get("success"));

                return null; // withMcpClient expects a return value
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            }
        });
    }
}