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
import java.util.HashMap;
import java.util.Map;

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
    private ObjectMapper mapper = new ObjectMapper();

    @Before
    public void setUpTestData() throws Exception {
        // Create a simple test binary file
        createTestBinaryFile();
    }

    @After
    public void tearDownTestData() throws Exception {
        // Clean up temporary file
        if (tempBinaryFile != null && tempBinaryFile.exists()) {
            tempBinaryFile.delete();
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

            JsonNode response = mapper.readTree(responseText);
            String programPath = response.get("programPath").asText();
            assertTrue("Program should be in custom path", programPath.startsWith("/test_folder/"));
        });
    }

    @Test
    public void testLoadBinaryWithProcessorSpec() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("filePath", tempBinaryFile.getAbsolutePath());
            args.put("processorSpec", "x86:LE:32:default");

            CallToolResult result = client.callTool(new CallToolRequest("load-binary", args));

            // Validate MCP response
            String responseText = ((TextContent) result.content().get(0)).text();
            assertTrue("Response should indicate success", responseText.contains("\"success\":true"));

            JsonNode response = mapper.readTree(responseText);
            String language = response.get("language").asText();
            assertTrue("Should use x86 language", language.contains("x86"));
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

            JsonNode response = mapper.readTree(responseText);
            assertFalse("Should not run analysis", response.get("analysisRun").asBoolean());
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
}