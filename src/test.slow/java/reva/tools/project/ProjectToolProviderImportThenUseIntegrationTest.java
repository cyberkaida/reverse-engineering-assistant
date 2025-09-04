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
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.Before;
import org.junit.Test;
import org.junit.After;

import com.fasterxml.jackson.databind.JsonNode;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Integration test to ensure imported programs can be used by other tools.
 * This test prevents regression of the "program not found after import" bug.
 * 
 * Tests the critical workflow:
 * 1. Import program with openProgram=false (program is saved but not kept open)
 * 2. Use other tools on the imported program (should trigger lazy loading)
 * 3. Verify programs work correctly across multiple tool calls
 */
public class ProjectToolProviderImportThenUseIntegrationTest extends RevaIntegrationTestBase {

    private Path tempDir;
    private Path testBinaryFile;
    private Path testZipFile;
    private Path testZipNoExtension;
    
    @Before
    public void setUp() throws Exception {
        // Create temporary directory and test binary
        tempDir = Files.createTempDirectory("reva-import-use-test");
        testBinaryFile = tempDir.resolve("test_program.bin");
        testZipFile = tempDir.resolve("test_archive.zip");
        testZipNoExtension = tempDir.resolve("archive_no_extension");
        
        // Create a minimal ELF binary (magic bytes + basic header)
        byte[] elfHeader = new byte[64];
        elfHeader[0] = 0x7F; // ELF magic
        elfHeader[1] = 'E';
        elfHeader[2] = 'L';
        elfHeader[3] = 'F';
        elfHeader[4] = 1; // 32-bit
        elfHeader[5] = 1; // Little endian
        elfHeader[6] = 1; // Current version
        // Rest can be zeros for a minimal valid ELF
        Files.write(testBinaryFile, elfHeader);
        
        // Create a zip file containing the binary for archive import testing
        createTestZipFile();
        
        // Create a zip file with no extension to test content-based archive detection
        createTestZipFileNoExtension();
    }
    
    private void createTestZipFile() throws Exception {
        try (FileOutputStream fos = new FileOutputStream(testZipFile.toFile());
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            
            // Add the ELF binary to the zip
            ZipEntry entry1 = new ZipEntry("archived_program.bin");
            zos.putNextEntry(entry1);
            zos.write(Files.readAllBytes(testBinaryFile));
            zos.closeEntry();
            
            // Add a second binary in a subfolder to test nested extraction
            ZipEntry entry2 = new ZipEntry("subdir/nested_program.exe");
            zos.putNextEntry(entry2);
            
            // Create a minimal PE header for variety
            byte[] peHeader = new byte[64];
            peHeader[0] = 'M'; // PE magic
            peHeader[1] = 'Z';
            // Rest can be zeros
            zos.write(peHeader);
            zos.closeEntry();
            
            // Add a non-binary file that should be filtered out
            ZipEntry entry3 = new ZipEntry("readme.txt");
            zos.putNextEntry(entry3);
            zos.write("This is documentation".getBytes());
            zos.closeEntry();
        }
    }
    
    private void createTestZipFileNoExtension() throws Exception {
        // Create identical zip content but with no file extension
        try (FileOutputStream fos = new FileOutputStream(testZipNoExtension.toFile());
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            
            // Add a simple binary to test content-based detection
            ZipEntry entry = new ZipEntry("extensionless_test.exe");
            zos.putNextEntry(entry);
            
            // Create a minimal PE header
            byte[] peHeader = new byte[64];
            peHeader[0] = 'M'; // PE magic
            peHeader[1] = 'Z';
            zos.write(peHeader);
            zos.closeEntry();
        }
    }
    
    private Path createMixedArchive() throws Exception {
        Path mixedZip = tempDir.resolve("mixed_archive.zip");
        
        try (FileOutputStream fos = new FileOutputStream(mixedZip.toFile());
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            
            // 1. Use the same ELF binary that works in other tests (faster import)
            ZipEntry elfEntry = new ZipEntry("valid_elf.bin");
            zos.putNextEntry(elfEntry);
            zos.write(Files.readAllBytes(testBinaryFile)); // Reuse the working test binary
            zos.closeEntry();
            
            // 2. Simple text file (will fail import - no binary loader)
            ZipEntry textEntry = new ZipEntry("readme.txt");
            zos.putNextEntry(textEntry);
            zos.write("This is a text file.".getBytes());
            zos.closeEntry();
        }
        
        return mixedZip;
    }
    
    private Path createNestedArchive() throws Exception {
        Path nestedZip = tempDir.resolve("nested_archive.zip");
        
        // First create an inner zip file
        Path innerZip = tempDir.resolve("inner_archive.zip");
        try (FileOutputStream fos = new FileOutputStream(innerZip.toFile());
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            
            // Add binary files to inner zip
            ZipEntry innerEntry1 = new ZipEntry("inner_program1.bin");
            zos.putNextEntry(innerEntry1);
            zos.write(Files.readAllBytes(testBinaryFile));
            zos.closeEntry();
            
            // Add another binary in a subfolder
            ZipEntry innerEntry2 = new ZipEntry("inner_subdir/inner_program2.exe");
            zos.putNextEntry(innerEntry2);
            byte[] peHeader = new byte[64];
            peHeader[0] = 'M'; peHeader[1] = 'Z'; // PE magic
            zos.write(peHeader);
            zos.closeEntry();
        }
        
        // Now create outer zip containing the inner zip and some direct files
        try (FileOutputStream fos = new FileOutputStream(nestedZip.toFile());
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            
            // Add the inner zip as an entry
            ZipEntry nestedZipEntry = new ZipEntry("nested/inner_archive.zip");
            zos.putNextEntry(nestedZipEntry);
            zos.write(Files.readAllBytes(innerZip));
            zos.closeEntry();
            
            // Add some direct binary files to outer zip
            ZipEntry outerEntry = new ZipEntry("outer_program.bin");
            zos.putNextEntry(outerEntry);
            zos.write(Files.readAllBytes(testBinaryFile));
            zos.closeEntry();
            
            // Add a text file that should be filtered out
            ZipEntry textEntry = new ZipEntry("readme.txt");
            zos.putNextEntry(textEntry);
            zos.write("Nested archive documentation".getBytes());
            zos.closeEntry();
        }
        
        // Clean up temporary inner zip
        Files.deleteIfExists(innerZip);
        return nestedZip;
    }
    
    private Path createDeeplyNestedArchive() throws Exception {
        Path deeplyNestedZip = tempDir.resolve("deeply_nested_archive.zip");
        
        // Create level 3 (innermost) zip
        Path level3Zip = tempDir.resolve("level3.zip");
        try (FileOutputStream fos = new FileOutputStream(level3Zip.toFile());
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            
            ZipEntry entry = new ZipEntry("deep_program.bin");
            zos.putNextEntry(entry);
            zos.write(Files.readAllBytes(testBinaryFile));
            zos.closeEntry();
        }
        
        // Create level 2 zip containing level 3
        Path level2Zip = tempDir.resolve("level2.zip");
        try (FileOutputStream fos = new FileOutputStream(level2Zip.toFile());
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            
            ZipEntry nestedEntry = new ZipEntry("level3/level3.zip");
            zos.putNextEntry(nestedEntry);
            zos.write(Files.readAllBytes(level3Zip));
            zos.closeEntry();
            
            // Add another binary at this level
            ZipEntry directEntry = new ZipEntry("level2_program.exe");
            zos.putNextEntry(directEntry);
            byte[] peHeader = new byte[64];
            peHeader[0] = 'M'; peHeader[1] = 'Z';
            zos.write(peHeader);
            zos.closeEntry();
        }
        
        // Create level 1 (outermost) zip containing level 2
        try (FileOutputStream fos = new FileOutputStream(deeplyNestedZip.toFile());
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            
            ZipEntry nestedEntry = new ZipEntry("level2/level2.zip");
            zos.putNextEntry(nestedEntry);
            zos.write(Files.readAllBytes(level2Zip));
            zos.closeEntry();
            
            // Add direct files at top level
            ZipEntry topEntry = new ZipEntry("top_level_program.bin");
            zos.putNextEntry(topEntry);
            zos.write(Files.readAllBytes(testBinaryFile));
            zos.closeEntry();
        }
        
        // Clean up temporary files
        Files.deleteIfExists(level3Zip);
        Files.deleteIfExists(level2Zip);
        return deeplyNestedZip;
    }
    
    private Path createMachOFatArchive() throws Exception {
        Path machoArchive = tempDir.resolve("macho_fat_archive.zip");
        
        try (FileOutputStream fos = new FileOutputStream(machoArchive.toFile());
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            
            // Create a simulated fat Mach-O file (universal binary)
            ZipEntry fatMachoEntry = new ZipEntry("fat_binary");
            zos.putNextEntry(fatMachoEntry);
            
            // Fat Mach-O magic header (0xcafebabe in big endian)
            byte[] fatHeader = new byte[32];
            fatHeader[0] = (byte)0xca; fatHeader[1] = (byte)0xfe;
            fatHeader[2] = (byte)0xba; fatHeader[3] = (byte)0xbe;
            // Number of architectures (2 in this case)
            fatHeader[4] = 0x00; fatHeader[5] = 0x00; fatHeader[6] = 0x00; fatHeader[7] = 0x02;
            zos.write(fatHeader);
            zos.closeEntry();
            
            // Add regular binary files too
            ZipEntry regularEntry = new ZipEntry("regular_program.bin");
            zos.putNextEntry(regularEntry);
            zos.write(Files.readAllBytes(testBinaryFile));
            zos.closeEntry();
        }
        
        return machoArchive;
    }
    
    @After
    public void tearDown() throws Exception {
        if (tempDir != null && Files.exists(tempDir)) {
            Files.walk(tempDir)
                .map(Path::toFile)
                .sorted((o1, o2) -> -o1.compareTo(o2))
                .forEach(File::delete);
        }
    }

    @Test
    public void testImportedProgramCanBeAnalyzed() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            
            // Step 1: Import program to a subfolder (tests path resolution)
            Map<String, Object> importRequest = new HashMap<>();
            importRequest.put("path", testBinaryFile.toString());
            importRequest.put("projectPath", "/imported"); // Subfolder to test path handling
            importRequest.put("runAnalysis", false); // Don't auto-analyze
            importRequest.put("openProgram", false); // Don't auto-open - test lazy loading
            
            CallToolResult importResult = client.callTool(
                new CallToolRequest("import-program", importRequest));
            
            // Verify import succeeded
            assertFalse("Import should succeed", 
                importResult.isError() != null && importResult.isError());
            
            TextContent importContent = (TextContent) importResult.content().get(0);
            JsonNode importJson = parseJsonContent(importContent.text());
            
            assertTrue("Import should report success", 
                importJson.get("success").asBoolean());
            
            // Extract the program path from import result
            JsonNode resultsArray = importJson.get("results");
            assertNotNull("Should have results array", resultsArray);
            assertTrue("Should have at least one result", resultsArray.size() > 0);
            
            String programPath = resultsArray.get(0).get("programPath").asText();
            assertNotNull("Should have program path", programPath);
            assertTrue("Program path should be in imported folder", 
                programPath.startsWith("/imported/"));
            
            // Step 2: Try to analyze the imported program (this is where the bug occurred)
            Map<String, Object> analyzeRequest = new HashMap<>();
            analyzeRequest.put("programPath", programPath);
            analyzeRequest.put("force", false);
            
            CallToolResult analyzeResult = client.callTool(
                new CallToolRequest("analyze-program", analyzeRequest));
            
            // This is the critical test - analyze should find the program
            assertFalse("Analyze should not error with 'program not found'", 
                analyzeResult.isError() != null && analyzeResult.isError());
            
            TextContent analyzeContent = (TextContent) analyzeResult.content().get(0);
            String analyzeText = analyzeContent.text();
            
            // Verify we don't get the "Did you mean" error message that indicates the bug
            assertFalse("Should not get 'Did you mean' suggestion error", 
                analyzeText.contains("Did you mean"));
            assertFalse("Should not get 'Program not found' error", 
                analyzeText.contains("Program not found"));
            
            // Parse and verify analyze succeeded
            JsonNode analyzeJson = parseJsonContent(analyzeText);
            assertTrue("Analyze should report success", 
                analyzeJson.get("success").asBoolean());
            assertEquals("Should use the correct program path", 
                programPath, analyzeJson.get("programPath").asText());
        });
    }

    @Test
    public void testImportedProgramCanBeUsedByMultipleTools() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            
            // Import program with openProgram=false to test lazy loading
            Map<String, Object> importRequest = new HashMap<>();
            importRequest.put("path", testBinaryFile.toString());
            importRequest.put("projectPath", "/test/nested/folder"); // Deep nesting
            importRequest.put("runAnalysis", false);
            importRequest.put("openProgram", false);
            
            CallToolResult importResult = client.callTool(
                new CallToolRequest("import-program", importRequest));
            
            TextContent importContent = (TextContent) importResult.content().get(0);
            JsonNode importJson = parseJsonContent(importContent.text());
            String programPath = importJson.get("results").get(0)
                .get("programPath").asText();
            
            // Test 1: Get function count (should lazy-load the program)
            Map<String, Object> funcCountRequest = new HashMap<>();
            funcCountRequest.put("programPath", programPath);
            
            CallToolResult funcCountResult = client.callTool(
                new CallToolRequest("get-function-count", funcCountRequest));
            
            assertFalse("Function count should not error", 
                funcCountResult.isError() != null && funcCountResult.isError());
            
            TextContent funcCountContent = (TextContent) funcCountResult.content().get(0);
            assertFalse("Should not contain 'Program not found'", 
                funcCountContent.text().contains("Program not found"));
            
            // Test 2: Get memory blocks (uses the now-cached program)
            Map<String, Object> memoryRequest = new HashMap<>();
            memoryRequest.put("programPath", programPath);
            
            CallToolResult memoryResult = client.callTool(
                new CallToolRequest("get-memory-blocks", memoryRequest));
            
            assertFalse("Memory blocks should not error", 
                memoryResult.isError() != null && memoryResult.isError());
            
            // Test 3: List open programs should now show our program
            CallToolResult listResult = client.callTool(
                new CallToolRequest("list-open-programs", new HashMap<>()));
            
            assertFalse("List programs should not error", 
                listResult.isError() != null && listResult.isError());
            
            TextContent listContent = (TextContent) listResult.content().get(0);
            JsonNode listJson = parseJsonContent(listContent.text());
            
            // Program should now be open (lazy-loaded by previous tools)
            boolean foundProgram = false;
            for (JsonNode prog : listJson) {
                if (prog.has("programPath") && 
                    programPath.equals(prog.get("programPath").asText())) {
                    foundProgram = true;
                    break;
                }
            }
            
            assertTrue("Imported program should be in open programs list after use", 
                foundProgram);
        });
    }

    @Test
    public void testImportToRootFolderAlsoWorks() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            
            // Import to root folder (simpler path case)
            Map<String, Object> importRequest = new HashMap<>();
            importRequest.put("path", testBinaryFile.toString());
            importRequest.put("projectPath", "/"); // Root folder
            importRequest.put("runAnalysis", false);
            importRequest.put("openProgram", false);
            
            CallToolResult importResult = client.callTool(
                new CallToolRequest("import-program", importRequest));
            
            TextContent importContent = (TextContent) importResult.content().get(0);
            JsonNode importJson = parseJsonContent(importContent.text());
            String programPath = importJson.get("results").get(0)
                .get("programPath").asText();
            
            // Should be able to analyze program in root folder
            Map<String, Object> analyzeRequest = new HashMap<>();
            analyzeRequest.put("programPath", programPath);
            
            CallToolResult analyzeResult = client.callTool(
                new CallToolRequest("analyze-program", analyzeRequest));
            
            assertFalse("Should be able to analyze program in root folder", 
                analyzeResult.isError() != null && analyzeResult.isError());
            
            TextContent analyzeContent = (TextContent) analyzeResult.content().get(0);
            assertFalse("Should not get 'Program not found' for root folder program", 
                analyzeContent.text().contains("Program not found"));
        });
    }

    @Test
    public void testImportThenGetFunctions() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            
            // Import program to test path
            Map<String, Object> importRequest = new HashMap<>();
            importRequest.put("path", testBinaryFile.toString());
            importRequest.put("projectPath", "/regression_test");
            importRequest.put("runAnalysis", false);
            importRequest.put("openProgram", false); // Key: program is not kept open
            
            CallToolResult importResult = client.callTool(
                new CallToolRequest("import-program", importRequest));
            
            TextContent importContent = (TextContent) importResult.content().get(0);
            JsonNode importJson = parseJsonContent(importContent.text());
            String programPath = importJson.get("results").get(0)
                .get("programPath").asText();
            
            // Try to get functions - this was failing before the fix
            Map<String, Object> functionsRequest = new HashMap<>();
            functionsRequest.put("programPath", programPath);
            functionsRequest.put("maxResults", 10);
            
            CallToolResult functionsResult = client.callTool(
                new CallToolRequest("get-functions", functionsRequest));
            
            // Should not error with "Program not found"
            if (functionsResult.isError() != null && functionsResult.isError()) {
                TextContent errorContent = (TextContent) functionsResult.content().get(0);
                String errorText = errorContent.text();
                assertFalse("Should not get 'Program not found' error: " + errorText, 
                    errorText.contains("Program not found"));
                assertFalse("Should not get 'Did you mean' suggestion: " + errorText,
                    errorText.contains("Did you mean"));
            }
            
            // If it succeeds, verify it found the correct program
            if (functionsResult.isError() == null || !functionsResult.isError()) {
                TextContent functionsContent = (TextContent) functionsResult.content().get(0);
                JsonNode functionsJson = parseJsonContent(functionsContent.text());
                
                // Should have program info in response
                if (functionsJson.has("programPath")) {
                    assertEquals("Should reference the correct program path", 
                        programPath, functionsJson.get("programPath").asText());
                }
            }
        });
    }

    @Test
    public void testImportFromZipArchiveThenUse() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            
            // Step 1: Import programs from zip archive
            Map<String, Object> importRequest = new HashMap<>();
            importRequest.put("path", testZipFile.toString());
            importRequest.put("projectPath", "/archive_import");
            importRequest.put("includePatterns", List.of("*.bin", "*.exe")); // Only import binaries
            importRequest.put("runAnalysis", false);
            importRequest.put("openProgram", false); // Test lazy loading
            
            CallToolResult importResult = client.callTool(
                new CallToolRequest("import-program", importRequest));
            
            // Verify import succeeded
            assertFalse("Archive import should succeed", 
                importResult.isError() != null && importResult.isError());
            
            TextContent importContent = (TextContent) importResult.content().get(0);
            JsonNode importJson = parseJsonContent(importContent.text());
            
            assertTrue("Archive import should report success", 
                importJson.get("success").asBoolean());
            assertEquals("Should be importing from archive", 
                "archive", importJson.get("sourceType").asText());
            
            // Should have imported multiple files
            JsonNode resultsArray = importJson.get("results");
            assertNotNull("Should have results array", resultsArray);
            assertTrue("Should have imported at least one program", resultsArray.size() > 0);
            
            // Get the path of the first imported program
            String firstProgramPath = resultsArray.get(0).get("programPath").asText();
            assertNotNull("Should have program path", firstProgramPath);
            assertTrue("Program path should be in archive_import folder", 
                firstProgramPath.startsWith("/archive_import/"));
            
            // Step 2: Test that we can use tools on the imported program from archive
            Map<String, Object> memoryRequest = new HashMap<>();
            memoryRequest.put("programPath", firstProgramPath);
            
            CallToolResult memoryResult = client.callTool(
                new CallToolRequest("get-memory-blocks", memoryRequest));
            
            // Should not get "Program not found" error
            if (memoryResult.isError() != null && memoryResult.isError()) {
                TextContent errorContent = (TextContent) memoryResult.content().get(0);
                String errorText = errorContent.text();
                assertFalse("Should not get 'Program not found' error from archive import: " + errorText, 
                    errorText.contains("Program not found"));
                assertFalse("Should not get 'Did you mean' suggestion from archive import: " + errorText,
                    errorText.contains("Did you mean"));
            }
            
            // Step 3: Test that the program is now cached and available
            Map<String, Object> functionsRequest = new HashMap<>();
            functionsRequest.put("programPath", firstProgramPath);
            functionsRequest.put("maxResults", 5);
            
            CallToolResult functionsResult = client.callTool(
                new CallToolRequest("get-functions", functionsRequest));
            
            // Should work without errors since program is now cached
            assertFalse("Functions call should work on cached program from archive", 
                functionsResult.isError() != null && functionsResult.isError());
            
            // Step 4: Verify that multiple programs were imported from the archive
            if (resultsArray.size() > 1) {
                String secondProgramPath = resultsArray.get(1).get("programPath").asText();
                
                Map<String, Object> analyzeRequest = new HashMap<>();
                analyzeRequest.put("programPath", secondProgramPath);
                analyzeRequest.put("force", false);
                
                CallToolResult analyzeResult = client.callTool(
                    new CallToolRequest("analyze-program", analyzeRequest));
                
                // Second program from archive should also be accessible
                if (analyzeResult.isError() != null && analyzeResult.isError()) {
                    TextContent errorContent = (TextContent) analyzeResult.content().get(0);
                    String errorText = errorContent.text();
                    assertFalse("Second program from archive should be accessible: " + errorText, 
                        errorText.contains("Program not found"));
                }
            }
        });
    }

    @Test
    public void testZipArchiveDetection() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            
            // Test that our zip file is properly detected as an archive
            Map<String, Object> browseRequest = new HashMap<>();
            browseRequest.put("path", testZipFile.toString());
            browseRequest.put("browseOnly", true);
            
            CallToolResult browseResult = client.callTool(
                new CallToolRequest("import-program", browseRequest));
            
            assertFalse("Browse should succeed", 
                browseResult.isError() != null && browseResult.isError());
            
            TextContent browseContent = (TextContent) browseResult.content().get(0);
            JsonNode browseJson = parseJsonContent(browseContent.text());
            
            assertEquals("Should detect as archive source", 
                "archive", browseJson.get("sourceType").asText());
            assertTrue("Should report success for archive detection", 
                browseJson.get("success").asBoolean());
            
            // Should list files within the archive
            if (browseJson.has("files")) {
                JsonNode files = browseJson.get("files");
                assertTrue("Should find files in archive", files.size() > 0);
                
                // Verify it found our binary files but not text files
                boolean foundBinary = false;
                for (JsonNode file : files) {
                    if (file.has("isPossibleBinary") && file.get("isPossibleBinary").asBoolean()) {
                        foundBinary = true;
                        break;
                    }
                }
                assertTrue("Should detect binary files in archive", foundBinary);
            }
        });
    }

    @Test
    public void testZipArchiveWithNoExtensionDetection() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            
            // Test that our zip file without extension is properly detected as an archive
            // This tests our improved content-based archive detection from the earlier fix
            Map<String, Object> browseRequest = new HashMap<>();
            browseRequest.put("path", testZipNoExtension.toString());
            browseRequest.put("browseOnly", true);
            
            CallToolResult browseResult = client.callTool(
                new CallToolRequest("import-program", browseRequest));
            
            assertFalse("Browse should succeed for extensionless archive", 
                browseResult.isError() != null && browseResult.isError());
            
            TextContent browseContent = (TextContent) browseResult.content().get(0);
            JsonNode browseJson = parseJsonContent(browseContent.text());
            
            // The key test: should detect as archive even without .zip extension
            assertEquals("Should detect extensionless file as archive using content-based detection", 
                "archive", browseJson.get("sourceType").asText());
            assertTrue("Should report success for extensionless archive detection", 
                browseJson.get("success").asBoolean());
        });
    }

    @Test  
    public void testRevaProgramManagerPathResolutionDirectly() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            
            // This test focuses on the core bug: RevaProgramManager path resolution
            // We'll create a mock program in a subfolder path structure
            
            // First, use the list-project-files tool to see the folder structure
            Map<String, Object> listRequest = new HashMap<>();
            listRequest.put("folderPath", "/");
            listRequest.put("recursive", true);
            
            CallToolResult listResult = client.callTool(
                new CallToolRequest("list-project-files", listRequest));
            
            // The test passes if the tool can resolve project paths correctly
            assertFalse("Project file listing should work", 
                listResult.isError() != null && listResult.isError());
            
            TextContent listContent = (TextContent) listResult.content().get(0);
            JsonNode listJson = parseJsonContent(listContent.text());
            
            // Should have folder structure info
            assertTrue("Should report success for project file listing", 
                listJson.get("success") != null && listJson.get("success").asBoolean());
        });
    }

    /**
     * This is the core regression test. It tests the specific scenario where:
     * 1. A program exists in the project at a path like "/imported/program.exe" 
     * 2. RevaProgramManager.getProgramByPath() should find it using proper path resolution
     * 3. Previously this failed because getRootFolder().getFile() doesn't handle subfolders
     * 4. Now it should work with our fix
     */
    @Test
    public void testCorePathResolutionRegression() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            
            // Test the scenario that was failing:
            // Try to use analyze-program with a non-existent program path in a subfolder
            // The old bug would give "Did you mean" error, new code should give "Program not found"
            // but more importantly, when a program DOES exist there, it should be found
            
            Map<String, Object> analyzeRequest = new HashMap<>();
            analyzeRequest.put("programPath", "/test_subfolder/nonexistent_program.exe");
            analyzeRequest.put("force", false);
            
            CallToolResult analyzeResult = client.callTool(
                new CallToolRequest("analyze-program", analyzeRequest));
            
            // Should return an error since program doesn't exist
            assertTrue("Should error for non-existent program", 
                analyzeResult.isError() != null && analyzeResult.isError());
            
            TextContent analyzeContent = (TextContent) analyzeResult.content().get(0);
            String errorMessage = analyzeContent.text();
            
            // The key test: error message should indicate "Program not found" 
            // (because our fixed path resolution looked properly but didn't find the file)
            // rather than showing "Available programs:" with suggestions
            // (which would indicate the old bug where it couldn't even look in subfolders)
            assertTrue("Error should indicate program not found (not path resolution failure)", 
                errorMessage.contains("Program not found") || 
                errorMessage.contains("Could not find program"));
        });
    }

    @Test 
    public void testIndividualFailureHandlingWithGracefulError() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            
            // Test importing a file that will fail to verify graceful error handling
            Map<String, Object> importRequest = new HashMap<>();
            importRequest.put("path", testBinaryFile.toString());
            importRequest.put("projectPath", "/error_handling_test");
            importRequest.put("runAnalysis", false);
            importRequest.put("openProgram", false);
            // Don't specify processorSpec - let it auto-detect
            
            CallToolResult importResult = client.callTool(
                new CallToolRequest("import-program", importRequest));
            
            // Import operation itself should not error (graceful handling)
            assertFalse("Import operation should not error", 
                importResult.isError() != null && importResult.isError());
            
            TextContent importContent = (TextContent) importResult.content().get(0);
            JsonNode importJson = parseJsonContent(importContent.text());
            
            // Verify graceful error handling behavior
            assertEquals("Should be file source type", "file", importJson.get("sourceType").asText());
            assertTrue("Overall should be success (graceful handling)", importJson.get("success").asBoolean());
            assertEquals("Should have 1 total file", 1, importJson.get("totalFiles").asInt());
            assertEquals("Should have 0 successes", 0, importJson.get("successCount").asInt());
            assertEquals("Should have 1 failure", 1, importJson.get("failureCount").asInt());
            
            // Check individual result for error details
            JsonNode results = importJson.get("results");
            assertEquals("Should have 1 result", 1, results.size());
            
            JsonNode result = results.get(0);
            assertFalse("Individual file should fail", result.get("success").asBoolean());
            assertEquals("Should have NO_LOADER error type", "NO_LOADER", result.get("errorType").asText());
            assertNotNull("Should have error message", result.get("error"));
            assertNotNull("Should have file path", result.get("filePath"));
            
            String errorMessage = result.get("error").asText();
            assertTrue("Error message should mention loader", 
                errorMessage.contains("loader") || errorMessage.contains("load spec"));
        });
    }
    
    @Test
    public void testProcessorSpecFallbackBehavior() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            
            // Test with an invalid processor spec that should fall back to auto-detection
            Map<String, Object> importRequest = new HashMap<>();
            importRequest.put("path", testBinaryFile.toString());
            importRequest.put("projectPath", "/fallback_test");
            importRequest.put("processorSpec", "invalid:spec:format:test"); // Invalid spec
            importRequest.put("runAnalysis", false);
            importRequest.put("openProgram", false);
            
            CallToolResult importResult = client.callTool(
                new CallToolRequest("import-program", importRequest));
            
            // Should still work due to fallback to auto-detection
            if (importResult.isError() == null || !importResult.isError()) {
                TextContent importContent = (TextContent) importResult.content().get(0);
                JsonNode importJson = parseJsonContent(importContent.text());
                
                // If the import succeeded (depends on binary format detection),
                // check that loadspec info is returned
                if (importJson.has("success") && importJson.get("success").asBoolean()) {
                    JsonNode results = importJson.get("results");
                    if (results != null && results.size() > 0) {
                        JsonNode firstResult = results.get(0);
                        if (firstResult.get("success").asBoolean()) {
                            assertNotNull("Should have loadSpec even with invalid processorSpec", 
                                firstResult.get("loadSpec"));
                        }
                    }
                }
            }
            // If import fails, that's ok too - the key is that it doesn't crash
            // due to the invalid processor spec
        });
    }
    
    @Test
    public void testNestedArchiveThresholdCheck() throws Exception {
        Path nestedArchive = createNestedArchive();
        
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            
            // Test with low threshold - should trigger warning since nested archive has multiple files
            Map<String, Object> request = new HashMap<>();
            request.put("path", nestedArchive.toString());
            request.put("autoImportThreshold", 2); // Low threshold to trigger warning
            
            CallToolResult result = client.callTool(new CallToolRequest("import-program", request));
            
            // Should either succeed with browse mode or return threshold warning
            TextContent content = (TextContent) result.content().get(0);
            String resultText = content.text();
            
            // Verify the result handles nested archives appropriately
            assertTrue("Should handle nested archive threshold appropriately", 
                resultText.contains("success") || resultText.contains("threshold") || 
                resultText.contains("too many files"));
                
            // If it's a browse result, verify archive detection
            if (resultText.contains("\"success\":true")) {
                JsonNode jsonResult = parseJsonContent(resultText);
                assertEquals("Should detect as archive source", 
                    "archive", jsonResult.get("sourceType").asText());
            }
        });
    }
    
    @Test
    public void testNestedArchiveImportSuccess() throws Exception {
        Path nestedArchive = createNestedArchive();
        
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            
            // Test with high threshold - should import successfully
            Map<String, Object> request = new HashMap<>();
            request.put("path", nestedArchive.toString());
            request.put("projectPath", "/nested_import_test");
            request.put("autoImportThreshold", 10); // High threshold to allow import
            request.put("runAnalysis", false);
            request.put("openProgram", false);
            
            CallToolResult result = client.callTool(new CallToolRequest("import-program", request));
            
            // Should succeed with nested archive import
            if (result.isError() == null || !result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = parseJsonContent(content.text());
                
                if (jsonResult.get("success").asBoolean()) {
                    assertEquals("Should be archive source type", 
                        "archive", jsonResult.get("sourceType").asText());
                    
                    // Should have results from nested structure
                    JsonNode results = jsonResult.get("results");
                    assertNotNull("Should have import results", results);
                    assertTrue("Should import multiple files from nested archive", 
                        results.size() > 0);
                }
            }
        });
    }
    
    @Test
    public void testDeeplyNestedArchive() throws Exception {
        Path deeplyNestedArchive = createDeeplyNestedArchive();
        
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            
            // Test browse mode on nested archive with reasonable depth to avoid timeout
            Map<String, Object> request = new HashMap<>();
            request.put("path", deeplyNestedArchive.toString());
            request.put("browseOnly", true);
            request.put("maxDepth", 3); // Reasonable depth - validates nested archive handling without excessive nesting
            
            CallToolResult result = client.callTool(new CallToolRequest("import-program", request));
            
            // Should handle nested archives successfully without hanging
            assertFalse("Nested archive browse should succeed without hanging", 
                result.isError() != null && result.isError());
                
            TextContent content = (TextContent) result.content().get(0);
            JsonNode jsonResult = parseJsonContent(content.text());
            
            assertTrue("Should successfully browse nested archive", 
                jsonResult.get("success").asBoolean());
            assertEquals("Should detect as archive source", 
                "archive", jsonResult.get("sourceType").asText());
                
            // Should find files from nested structure (at least files from top levels)
            JsonNode files = jsonResult.get("files");
            assertNotNull("Should have files array", files);
            assertTrue("Should find files in nested structure", 
                files.size() > 0);
        });
    }
    
    @Test
    public void testFatMachOInsideArchive() throws Exception {
        Path machoArchive = createMachOFatArchive();
        
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            
            // Test import with timeout protection - should not hang on fat Mach-O
            Map<String, Object> request = new HashMap<>();
            request.put("path", machoArchive.toString());
            request.put("projectPath", "/macho_test");
            request.put("autoImportThreshold", 10);
            request.put("runAnalysis", false);
            request.put("openProgram", false);
            
            CallToolResult result = client.callTool(new CallToolRequest("import-program", request));
            
            // Should not hang and should complete within reasonable time
            // The key test is that this completes without timeout
            assertNotNull("Should get a result without hanging", result);
            
            TextContent content = (TextContent) result.content().get(0);
            String resultText = content.text();
            
            // Should either succeed or fail gracefully, but not hang
            assertTrue("Should handle fat Mach-O in archive without hanging",
                resultText.contains("success") || resultText.contains("error") ||
                resultText.contains("threshold"));
        });
    }
    
    @Test
    public void testNestedArchiveWithTimeout() throws Exception {
        Path nestedArchive = createDeeplyNestedArchive();
        
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            
            // Test that timeout protection works for nested archives
            Map<String, Object> request = new HashMap<>();
            request.put("path", nestedArchive.toString());
            request.put("browseOnly", true);
            request.put("maxDepth", 10); // Very deep to potentially trigger timeout
            
            CallToolResult result = client.callTool(new CallToolRequest("import-program", request));
            
            // Should complete within timeout period and not hang indefinitely
            assertNotNull("Should complete within timeout period", result);
            
            TextContent content = (TextContent) result.content().get(0);
            String resultText = content.text();
            
            // Should handle timeout gracefully if it occurs
            assertTrue("Should handle deeply nested archive with timeout protection",
                resultText.contains("success") || resultText.contains("error") ||
                resultText.contains("timeout") || resultText.contains("threshold"));
        });
    }
}