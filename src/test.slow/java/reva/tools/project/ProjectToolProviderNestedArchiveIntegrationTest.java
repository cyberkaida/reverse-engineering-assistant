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
import java.util.List;
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

    // ==================== Archive Import Tests ====================

    /**
     * Get the path to the test fixtures directory.
     * Test fixtures are stored in tests/fixtures/ and include pre-compiled binaries.
     */
    private String getTestFixturesPath() {
        // Navigate from project root to tests/fixtures
        File projectRoot = new File(System.getProperty("user.dir"));
        File fixturesDir = new File(projectRoot, "tests/fixtures");
        return fixturesDir.getAbsolutePath();
    }

    /**
     * Test importing a zip archive containing multiple binaries.
     * The test archive contains:
     * - test_arm64: ARM64 Mach-O binary
     * - test_x86_64: x86_64 Mach-O binary
     * - test_fat_binary: Fat Mach-O with both arm64 and x86_64 slices
     *
     * Expected result: 4 programs imported (1 + 1 + 2 from fat binary)
     */
    @Test
    public void testImportZipArchive() throws Exception {
        String archivePath = getTestFixturesPath() + "/test_archive.zip";

        if (!new File(archivePath).exists()) {
            System.out.println("Skipping test: test archive not found at " + archivePath);
            return;
        }

        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "import-file",
                    Map.of(
                        "path", archivePath,
                        "enableVersionControl", false
                    )
                ));

                assertNotNull("Result should not be null", result);
                assertFalse("Tool should not have error: " +
                    (result.content().isEmpty() ? "no content" :
                        ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text()),
                    result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertTrue("Import should be successful", Boolean.TRUE.equals(response.get("success")));

                // Verify archive was discovered
                Integer filesDiscovered = (Integer) response.get("filesDiscovered");
                assertNotNull("Should have filesDiscovered", filesDiscovered);
                assertTrue("Should discover files from archive (found " + filesDiscovered + ")", filesDiscovered >= 3);

                // Verify files were imported
                Integer filesImported = (Integer) response.get("filesImported");
                assertNotNull("Should have filesImported", filesImported);
                // Archive has 3 source files, but fat binary produces 2 programs = 4 total
                assertTrue("Should import multiple files (imported " + filesImported + ")", filesImported >= 3);

                // Verify importedPrograms list
                @SuppressWarnings("unchecked")
                List<String> importedPrograms = (List<String>) response.get("importedPrograms");
                assertNotNull("Should have importedPrograms list", importedPrograms);
                assertTrue("Should have multiple imported programs", importedPrograms.size() >= 3);

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            }
        });
    }

    /**
     * Test importing a fat Mach-O binary.
     * The fat binary contains both arm64 and x86_64 slices.
     * Expected result: 2 programs imported (one per slice)
     */
    @Test
    public void testImportFatMachoBinary() throws Exception {
        String fatBinaryPath = getTestFixturesPath() + "/test_fat_binary";

        if (!new File(fatBinaryPath).exists()) {
            System.out.println("Skipping test: fat binary not found at " + fatBinaryPath);
            return;
        }

        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "import-file",
                    Map.of(
                        "path", fatBinaryPath,
                        "enableVersionControl", false
                    )
                ));

                assertNotNull("Result should not be null", result);
                assertFalse("Tool should not have error: " +
                    (result.content().isEmpty() ? "no content" :
                        ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text()),
                    result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertTrue("Import should be successful", Boolean.TRUE.equals(response.get("success")));

                // Fat binary should produce 2 programs (arm64 + x86_64)
                Integer filesImported = (Integer) response.get("filesImported");
                assertNotNull("Should have filesImported", filesImported);
                assertEquals("Fat binary should produce 2 programs", Integer.valueOf(2), filesImported);

                // Verify importedPrograms list has 2 entries
                @SuppressWarnings("unchecked")
                List<String> importedPrograms = (List<String>) response.get("importedPrograms");
                assertNotNull("Should have importedPrograms list", importedPrograms);
                assertEquals("Should have 2 imported programs from fat binary", 2, importedPrograms.size());

                // Verify both slices are represented
                boolean hasArm64 = importedPrograms.stream().anyMatch(p -> p.contains("arm64") || p.contains("AARCH64"));
                boolean hasX86_64 = importedPrograms.stream().anyMatch(p -> p.contains("x86_64") || p.contains("x86-64"));
                assertTrue("Should have arm64 slice", hasArm64);
                assertTrue("Should have x86_64 slice", hasX86_64);

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            }
        });
    }

    /**
     * Test that all new response fields are present in import response.
     */
    @Test
    public void testImportResponseNewFields() throws Exception {
        String testFilePath = getTestFixturesPath() + "/test_arm64";

        if (!new File(testFilePath).exists()) {
            // Fallback to /bin/ls
            testFilePath = "/bin/ls";
            if (!new File(testFilePath).exists()) {
                System.out.println("Skipping test: no test binary available");
                return;
            }
        }

        final String finalPath = testFilePath;
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "import-file",
                    Map.of(
                        "path", finalPath,
                        "enableVersionControl", false
                    )
                ));

                assertNotNull("Result should not be null", result);
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                // Verify required fields
                assertTrue("Should have success field", response.containsKey("success"));
                assertTrue("Should have importedFrom field", response.containsKey("importedFrom"));
                assertTrue("Should have filesDiscovered field", response.containsKey("filesDiscovered"));
                assertTrue("Should have filesImported field", response.containsKey("filesImported"));
                assertTrue("Should have importedPrograms field", response.containsKey("importedPrograms"));

                // Verify group tracking fields
                assertTrue("Should have enabledGroups field", response.containsKey("enabledGroups"));
                assertTrue("Should have skippedGroups field", response.containsKey("skippedGroups"));
                assertTrue("Should have groupsCreated field", response.containsKey("groupsCreated"));

                // Verify path handling fields
                assertTrue("Should have stripLeadingPath field", response.containsKey("stripLeadingPath"));
                assertTrue("Should have stripAllContainerPath field", response.containsKey("stripAllContainerPath"));
                assertTrue("Should have mirrorFs field", response.containsKey("mirrorFs"));

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            }
        });
    }

    /**
     * Test importing with analysis enabled.
     * This verifies the analyzeAfterImport parameter works correctly.
     */
    @Test
    public void testImportWithAnalysis() throws Exception {
        String testFilePath = getTestFixturesPath() + "/test_arm64";

        if (!new File(testFilePath).exists()) {
            // Fallback to /bin/ls
            testFilePath = "/bin/ls";
            if (!new File(testFilePath).exists()) {
                System.out.println("Skipping test: no test binary available");
                return;
            }
        }

        final String finalPath = testFilePath;
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "import-file",
                    Map.of(
                        "path", finalPath,
                        "enableVersionControl", false,
                        "analyzeAfterImport", true
                    )
                ));

                assertNotNull("Result should not be null", result);
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertTrue("Import should be successful", Boolean.TRUE.equals(response.get("success")));

                // When analysis is requested, should have analyzedPrograms field
                assertTrue("Should have analyzedPrograms when analyzeAfterImport=true",
                    response.containsKey("analyzedPrograms"));

                @SuppressWarnings("unchecked")
                List<String> analyzedPrograms = (List<String>) response.get("analyzedPrograms");
                assertNotNull("analyzedPrograms should not be null", analyzedPrograms);
                assertTrue("Should have analyzed at least one program", analyzedPrograms.size() > 0);

                // Verify filesAnalyzed count matches
                Integer filesAnalyzed = (Integer) response.get("filesAnalyzed");
                assertNotNull("Should have filesAnalyzed count", filesAnalyzed);
                assertEquals("filesAnalyzed should match analyzedPrograms size",
                    Integer.valueOf(analyzedPrograms.size()), filesAnalyzed);

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            }
        });
    }

    /**
     * Test importing without analysis (default behavior).
     */
    @Test
    public void testImportWithoutAnalysis() throws Exception {
        String testFilePath = getTestFixturesPath() + "/test_arm64";

        if (!new File(testFilePath).exists()) {
            // Fallback to /bin/ls
            testFilePath = "/bin/ls";
            if (!new File(testFilePath).exists()) {
                System.out.println("Skipping test: no test binary available");
                return;
            }
        }

        final String finalPath = testFilePath;
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "import-file",
                    Map.of(
                        "path", finalPath,
                        "enableVersionControl", false,
                        "analyzeAfterImport", false
                    )
                ));

                assertNotNull("Result should not be null", result);
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertTrue("Import should be successful", Boolean.TRUE.equals(response.get("success")));

                // When analysis is not requested, should NOT have analyzedPrograms field
                assertFalse("Should NOT have analyzedPrograms when analyzeAfterImport=false",
                    response.containsKey("analyzedPrograms"));

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            }
        });
    }
}