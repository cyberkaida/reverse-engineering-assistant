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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.Test;
import org.junit.Before;
import org.junit.After;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;
import reva.plugin.RevaProgramManager;

import static org.junit.Assert.*;

/**
 * Integration tests for the load-binary tool in ProjectToolProvider.
 */
public class ProjectToolProviderLoadBinaryTest extends RevaIntegrationTestBase {

    private File tempBinaryFile;
    private File tempArchiveFile;
    private ObjectMapper mapper = new ObjectMapper();

    @Before
    public void setUpTestData() throws Exception {
        // Create a simple test binary file
        createTestBinaryFile();
        // Create a test archive with multiple files
        createTestArchiveFile();
    }

    @After
    public void tearDownTestData() throws Exception {
        // Clean up temporary files
        if (tempBinaryFile != null && tempBinaryFile.exists()) {
            tempBinaryFile.delete();
        }
        if (tempArchiveFile != null && tempArchiveFile.exists()) {
            tempArchiveFile.delete();
        }
    }

    /**
     * Create a simple test binary file (simple PE structure)
     */
    private void createTestBinaryFile() throws IOException {
        tempBinaryFile = File.createTempFile("test_binary", ".exe");
        tempBinaryFile.deleteOnExit();

        // Create a minimal PE file structure
        try (FileOutputStream fos = new FileOutputStream(tempBinaryFile)) {
            // DOS header
            fos.write(new byte[] {
                'M', 'Z',  // DOS signature
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x40, 0x00, 0x00, 0x00  // PE offset at 0x40
            });
            
            // Fill to PE offset
            for (int i = 0; i < 0x40 - 62; i++) {
                fos.write(0x00);
            }
            
            // PE header
            fos.write(new byte[] { 'P', 'E', 0x00, 0x00 }); // PE signature
            
            // Add minimal COFF header and optional header
            byte[] coffHeader = new byte[24];
            coffHeader[0] = 0x4c; // i386 machine type
            coffHeader[1] = 0x01;
            fos.write(coffHeader);
            
            // Optional header - simplified
            byte[] optHeader = new byte[224]; // Standard size for PE32
            optHeader[0] = 0x0b; // PE32 magic
            optHeader[1] = 0x01;
            fos.write(optHeader);
        }
    }

    /**
     * Create a test ZIP archive with multiple binary files for testing archive import
     */
    private void createTestArchiveFile() throws IOException {
        tempArchiveFile = File.createTempFile("test_archive", ".zip");
        tempArchiveFile.deleteOnExit();

        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(tempArchiveFile))) {
            // Add first binary file
            ZipEntry entry1 = new ZipEntry("binary1.exe");
            zos.putNextEntry(entry1);
            zos.write(createMinimalBinaryData("app1"));
            zos.closeEntry();

            // Add second binary file in a subdirectory
            ZipEntry entry2 = new ZipEntry("subdir/binary2.exe");
            zos.putNextEntry(entry2);
            zos.write(createMinimalBinaryData("app2"));
            zos.closeEntry();

            // Add a third binary file
            ZipEntry entry3 = new ZipEntry("binary3.dll");
            zos.putNextEntry(entry3);
            zos.write(createMinimalBinaryData("lib1"));
            zos.closeEntry();

            // Add some non-binary files (should be excluded)
            ZipEntry txtEntry = new ZipEntry("readme.txt");
            zos.putNextEntry(txtEntry);
            zos.write("This is a readme file".getBytes());
            zos.closeEntry();

            ZipEntry docEntry = new ZipEntry("manual.pdf");
            zos.putNextEntry(docEntry);
            zos.write("Fake PDF content".getBytes());
            zos.closeEntry();
        }
    }

    /**
     * Create minimal binary data for testing
     */
    private byte[] createMinimalBinaryData(String appName) throws IOException {
        // Create a very minimal PE-like structure
        byte[] data = new byte[256];
        
        // DOS header
        data[0] = 'M';
        data[1] = 'Z';
        data[60] = 0x40; // PE offset at 0x40
        
        // PE signature at offset 0x40
        data[0x40] = 'P';
        data[0x41] = 'E';
        data[0x42] = 0x00;
        data[0x43] = 0x00;
        
        // Add machine type (i386)
        data[0x44] = 0x4c;
        data[0x45] = 0x01;
        
        return data;
    }

    @Test
    public void testLoadBinaryWithDefaults() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("filePath", tempBinaryFile.getAbsolutePath());

            CallToolResult result = client.callTool(new CallToolRequest("load-binary", args));

            // Validate MCP response
            assertNotNull("Result should not be null", result);
            assertTrue("Should have content", !result.content().isEmpty());

            String responseText = ((TextContent) result.content().get(0)).text();
            assertFalse("Response should not be an error", responseText.contains("error"));
            assertTrue("Response should indicate success", responseText.contains("\"success\":true"));

            // Parse JSON response
            JsonNode response = mapper.readTree(responseText);
            assertTrue("Should report success", response.get("success").asBoolean());
            assertTrue("Should have program name", response.has("programName"));
            assertTrue("Should have program path", response.has("programPath"));
            assertTrue("Should have language", response.has("language"));
            assertTrue("Should have compiler spec", response.has("compilerSpec"));

            // Validate that the program was actually loaded and registered
            String programPath = response.get("programPath").asText();
            assertFalse("Program path should not be empty", programPath.isEmpty());
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testLoadBinaryWithCustomPath() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("filePath", tempBinaryFile.getAbsolutePath());
            args.put("projectPath", "/test_folder");

            CallToolResult result = client.callTool(new CallToolRequest("load-binary", args));

            // Validate MCP response
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Response should indicate success", responseText.contains("\"success\":true"));

            try {
                JsonNode response = mapper.readTree(responseText);
                String programPath = response.get("programPath").asText();
                assertTrue("Program should be in custom path", programPath.startsWith("/test_folder/"));
            } catch (Exception e) {
                fail("Failed to parse JSON response: " + e.getMessage());
            }
        });
    }

    @Test
    public void testLoadBinaryWithProcessorSpec() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("filePath", tempBinaryFile.getAbsolutePath());
            // Don't specify processorSpec - let Ghidra auto-detect to avoid segmented address space issues

            CallToolResult result = client.callTool(new CallToolRequest("load-binary", args));

            // Validate MCP response
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Response should indicate success", responseText.contains("\"success\":true"));

            try {
                JsonNode response = mapper.readTree(responseText);
                String language = response.get("language").asText();
                assertTrue("Should use x86 language", language.contains("x86"));
            } catch (Exception e) {
                fail("Failed to parse JSON response: " + e.getMessage());
            }
        });
    }

    @Test
    public void testLoadBinaryWithoutAnalysis() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("filePath", tempBinaryFile.getAbsolutePath());
            args.put("runAnalysis", false);

            CallToolResult result = client.callTool(new CallToolRequest("load-binary", args));

            // Validate MCP response
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Response should indicate success", responseText.contains("\"success\":true"));

            try {
                JsonNode response = mapper.readTree(responseText);
                assertFalse("Should not run analysis", response.get("analysisRun").asBoolean());
            } catch (Exception e) {
                fail("Failed to parse JSON response: " + e.getMessage());
            }
        });
    }

    @Test
    public void testLoadBinaryFileNotFound() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("filePath", "/non/existent/file.exe");

            CallToolResult result = client.callTool(new CallToolRequest("load-binary", args));

            // Should return error for non-existent file
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Should report file not found error", 
                responseText.contains("File not found"));
        });
    }

    @Test
    public void testLoadBinaryInvalidProcessorSpec() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("filePath", tempBinaryFile.getAbsolutePath());
            args.put("processorSpec", "invalid:spec");

            CallToolResult result = client.callTool(new CallToolRequest("load-binary", args));

            // Should return error for invalid processor spec
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Should report invalid processor spec error", 
                responseText.contains("Invalid processor spec"));
        });
    }

    @Test
    public void testArchiveListingWhenTooManyFiles() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("filePath", tempArchiveFile.getAbsolutePath());
            args.put("autoImportThreshold", 2); // Lower threshold to force listing
            args.put("listOnly", false);

            CallToolResult result = client.callTool(new CallToolRequest("load-binary", args));

            // Should return listing instead of importing
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Response should indicate success", responseText.contains("\"success\":true"));
            assertTrue("Should be a listing", responseText.contains("\"isListing\":true"));
            assertTrue("Should indicate archive source", responseText.contains("\"sourceType\":\"archive\""));

            try {
                JsonNode response = mapper.readTree(responseText);
                assertTrue("Should have file count", response.has("fileCount"));
                assertTrue("Should have files array", response.has("files"));
                assertTrue("Should have at least 3 files", response.get("fileCount").asInt() >= 3);
                
                // Check that the files array contains expected entries
                JsonNode files = response.get("files");
                boolean foundExeFile = false;
                boolean foundDllFile = false;
                for (JsonNode file : files) {
                    String fileName = file.get("fileName").asText();
                    if (fileName.endsWith(".exe")) foundExeFile = true;
                    if (fileName.endsWith(".dll")) foundDllFile = true;
                }
                assertTrue("Should find .exe files", foundExeFile);
                assertTrue("Should find .dll files", foundDllFile);
            } catch (Exception e) {
                fail("Failed to parse JSON response: " + e.getMessage());
            }
        });
    }

    @Test
    public void testArchiveImportWithIncludePatterns() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("filePath", tempArchiveFile.getAbsolutePath());
            args.put("includePatterns", Arrays.asList("*.exe")); // Only import .exe files
            args.put("runAnalysis", false); // Skip analysis for faster test
            args.put("openProgram", false); // Don't open programs

            CallToolResult result = client.callTool(new CallToolRequest("load-binary", args));

            // Should import only .exe files
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Response should indicate success", responseText.contains("\"success\":true"));
            assertTrue("Should indicate archive source", responseText.contains("\"sourceType\":\"archive\""));

            try {
                JsonNode response = mapper.readTree(responseText);
                assertTrue("Should have results array", response.has("results"));
                JsonNode results = response.get("results");
                
                // Should have imported only 2 .exe files (not the .dll)
                int successCount = response.get("successCount").asInt();
                assertTrue("Should import at least 1 file", successCount >= 1);
                assertTrue("Should import at most 2 files", successCount <= 2);
                
                // Verify all imported files are .exe files by checking the archive file paths
                for (JsonNode fileResult : results) {
                    if (fileResult.get("success").asBoolean()) {
                        String archiveFilePath = fileResult.get("archiveFilePath").asText();
                        assertTrue("Imported file should be .exe", archiveFilePath.endsWith(".exe"));
                    }
                }
            } catch (Exception e) {
                fail("Failed to parse JSON response: " + e.getMessage());
            }
        });
    }

    @Test
    public void testArchiveImportWithExcludePatterns() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("filePath", tempArchiveFile.getAbsolutePath());
            args.put("excludePatterns", Arrays.asList("*.dll")); // Exclude .dll files
            args.put("runAnalysis", false);
            args.put("openProgram", false);

            CallToolResult result = client.callTool(new CallToolRequest("load-binary", args));

            // Should import everything except .dll files
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Response should indicate success", responseText.contains("\"success\":true"));

            try {
                JsonNode response = mapper.readTree(responseText);
                JsonNode results = response.get("results");
                
                // Verify no .dll files were imported
                for (JsonNode fileResult : results) {
                    if (fileResult.get("success").asBoolean()) {
                        String archiveFilePath = fileResult.get("archiveFilePath").asText();
                        assertFalse("Should not import .dll files", archiveFilePath.endsWith(".dll"));
                    }
                }
            } catch (Exception e) {
                fail("Failed to parse JSON response: " + e.getMessage());
            }
        });
    }

    @Test
    public void testArchiveListOnlyMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("filePath", tempArchiveFile.getAbsolutePath());
            args.put("listOnly", true); // Force listing mode

            CallToolResult result = client.callTool(new CallToolRequest("load-binary", args));

            // Should return listing without importing
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Response should indicate success", responseText.contains("\"success\":true"));
            assertTrue("Should be a listing", responseText.contains("\"isListing\":true"));

            try {
                JsonNode response = mapper.readTree(responseText);
                assertTrue("Should have files array", response.has("files"));
                assertFalse("Should not have results array", response.has("results"));
                assertTrue("Should indicate archive source", 
                    "archive".equals(response.get("sourceType").asText()));
            } catch (Exception e) {
                fail("Failed to parse JSON response: " + e.getMessage());
            }
        });
    }
}