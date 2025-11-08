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
     * Test importing a file with version control enabled (default behavior)
     */
    @Test
    public void testImportWithVersionControlEnabled() throws Exception {
        String testFilePath = "/bin/ls";

        if (!new File(testFilePath).exists()) {
            // Skip test if file doesn't exist
            return;
        }

        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Import with default enableVersionControl=true
                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "import-file",
                    Map.of(
                        "path", testFilePath
                    )
                ));

                assertNotNull("Result should not be null", result);
                assertNotNull("Response content should not be null", result.content());
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertTrue("Import should be successful", Boolean.TRUE.equals(response.get("success")));
                assertTrue("enableVersionControl should be true by default", Boolean.TRUE.equals(response.get("enableVersionControl")));

                // If project supports version control, should have filesAddedToVersionControl count
                // (This may be 0 if project doesn't support version control, but field should exist)
                if (response.containsKey("filesAddedToVersionControl")) {
                    Integer versionedCount = (Integer) response.get("filesAddedToVersionControl");
                    assertNotNull("filesAddedToVersionControl should not be null", versionedCount);
                    assertTrue("filesAddedToVersionControl should be >= 0", versionedCount >= 0);
                }

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            }
        });
    }

    /**
     * Test importing a file with version control explicitly disabled
     */
    @Test
    public void testImportWithVersionControlDisabled() throws Exception {
        String testFilePath = "/bin/ls";

        if (!new File(testFilePath).exists()) {
            // Skip test if file doesn't exist
            return;
        }

        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Import with enableVersionControl=false
                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "import-file",
                    Map.of(
                        "path", testFilePath,
                        "enableVersionControl", false
                    )
                ));

                assertNotNull("Result should not be null", result);
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertTrue("Import should be successful", Boolean.TRUE.equals(response.get("success")));
                assertFalse("enableVersionControl should be false", Boolean.TRUE.equals(response.get("enableVersionControl")));

                // Should not have filesAddedToVersionControl field when disabled
                assertFalse("Should not have filesAddedToVersionControl when disabled",
                    response.containsKey("filesAddedToVersionControl"));

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            }
        });
    }
}