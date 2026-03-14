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
package reva.tools.structures;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.ListToolsResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for StructureToolProvider
 */
public class StructureToolProviderIntegrationTest extends RevaIntegrationTestBase {
    private String programPath;

    @Before
    public void setUpStructureTests() throws Exception {
        // Get program path for use in tests - this is how RevaProgramManager identifies programs
        programPath = program.getDomainFile().getPathname();

        // Open the program in the tool's ProgramManager so it can be found by RevaProgramManager
        env.open(program);

        // Also open it directly in the tool's ProgramManager service to ensure it's available
        ghidra.app.services.ProgramManager programManager = tool.getService(ghidra.app.services.ProgramManager.class);
        if (programManager != null) {
            programManager.openProgram(program);
        }


        // Register the program with the server manager so it can be found by the tools
        if (serverManager != null) {
            serverManager.programOpened(program, tool);
        }
    }

    @Test
    public void testListToolsIncludesStructureTools() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            ListToolsResult tools = client.listTools(null);
            assertNotNull("Tools result should not be null", tools);
            assertNotNull("Tools list should not be null", tools.tools());

            // Look for our structure tools
            boolean foundParseC = false;
            boolean foundValidateC = false;
            boolean foundCreateStructure = false;
            boolean foundAddStructureField = false;
            boolean foundModifyStructureField = false;
            boolean foundModifyStructureFromC = false;

            for (Tool tool : tools.tools()) {
                if ("parse-c-structure".equals(tool.name())) {
                    foundParseC = true;
                }
                if ("validate-c-structure".equals(tool.name())) {
                    foundValidateC = true;
                }
                if ("create-structure".equals(tool.name())) {
                    foundCreateStructure = true;
                }
                if ("add-structure-field".equals(tool.name())) {
                    foundAddStructureField = true;
                }
                if ("modify-structure-field".equals(tool.name())) {
                    foundModifyStructureField = true;
                }
                if ("modify-structure-from-c".equals(tool.name())) {
                    foundModifyStructureFromC = true;
                }
            }

            assertTrue("parse-c-structure tool should be available", foundParseC);
            assertTrue("validate-c-structure tool should be available", foundValidateC);
            // Removed tools should NOT be present
            assertFalse("create-structure tool should have been removed", foundCreateStructure);
            assertFalse("add-structure-field tool should have been removed", foundAddStructureField);
            assertFalse("modify-structure-field tool should have been removed", foundModifyStructureField);
            assertFalse("modify-structure-from-c tool should have been removed", foundModifyStructureFromC);
        });
    }

    @Test
    public void testParseCStructure() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("cDefinition", "struct TestStruct { int field1; char field2[32]; };");

            CallToolResult result = client.callTool(new CallToolRequest("parse-c-structure", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            // Parse the JSON content
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertEquals("TestStruct", json.get("name").asText());
            assertEquals("Successfully created structure: TestStruct", json.get("message").asText());

            // Verify structure was created in program
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByName(dtm, "TestStruct");
            assertNotNull("Structure should exist in program", dt);
            assertTrue("Should be a Structure", dt instanceof Structure);

            Structure struct = (Structure) dt;
            assertEquals("Should have 2 components", 2, struct.getNumComponents());
        });
    }

    @Test
    public void testParseCStructureReplacesExisting() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create initial structure
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("programPath", programPath);
            createArgs.put("cDefinition", "struct ReplaceTest { int field1; char field2; };");

            CallToolResult createResult = client.callTool(new CallToolRequest("parse-c-structure", createArgs));
            assertMcpResultNotError(createResult, "Structure creation should succeed");

            // Verify initial structure
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByName(dtm, "ReplaceTest");
            assertNotNull("Structure should exist", dt);
            Structure struct = (Structure) dt;
            assertEquals("Should have 2 fields initially", 2, struct.getNumComponents());

            // Replace structure with different fields using parse-c-structure
            Map<String, Object> replaceArgs = new HashMap<>();
            replaceArgs.put("programPath", programPath);
            replaceArgs.put("cDefinition", "struct ReplaceTest { int field1; short field2; long field3; };");

            CallToolResult replaceResult = client.callTool(new CallToolRequest("parse-c-structure", replaceArgs));
            assertMcpResultNotError(replaceResult, "Structure replacement should succeed");

            TextContent content = (TextContent) replaceResult.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertEquals("Successfully modified structure from C definition: ReplaceTest",
                         json.get("message").asText());
            assertEquals(3, json.get("fieldsCount").asInt());

            // Verify the structure was modified in the program
            dt = findDataTypeByName(dtm, "ReplaceTest");
            struct = (Structure) dt;
            assertEquals("Should now have 3 fields", 3, struct.getNumComponents());

            // Verify field types
            ghidra.program.model.data.DataTypeComponent field1 = struct.getComponent(0);
            ghidra.program.model.data.DataTypeComponent field2 = struct.getComponent(1);
            ghidra.program.model.data.DataTypeComponent field3 = struct.getComponent(2);

            assertEquals("field1", field1.getFieldName());
            assertEquals("field2", field2.getFieldName());
            assertEquals("field3", field3.getFieldName());

            assertTrue("field2 should be short", field2.getDataType().getName().contains("short"));
            assertTrue("field3 should be long", field3.getDataType().getName().contains("long"));
        });
    }

    @Test
    public void testValidateCStructure() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test valid structure
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("cDefinition", "struct ValidStruct { int x; int y; };");

            CallToolResult result = client.callTool(new CallToolRequest("validate-c-structure", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Should be valid", json.get("valid").asBoolean());
            assertEquals("ValidStruct", json.get("parsedType").asText());

            // Test invalid structure
            arguments.put("cDefinition", "struct InvalidStruct { unknown_type field; };");
            result = client.callTool(new CallToolRequest("validate-c-structure", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            content = (TextContent) result.content().get(0);
            json = parseJsonContent(content.text());

            assertFalse("Should be invalid", json.get("valid").asBoolean());
            assertNotNull("Should have error message", json.get("error"));
        });
    }

    @Test
    public void testGetStructureInfo() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create a structure with fields
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("cDefinition", "struct InfoStruct { int id; char name[20]; void* next; };");

            CallToolResult createResult = client.callTool(new CallToolRequest("parse-c-structure", args));
            assertMcpResultNotError(createResult, "Create structure should not error");

            // Get structure info
            Map<String, Object> infoArgs = new HashMap<>();
            infoArgs.put("programPath", programPath);
            infoArgs.put("structureName", "InfoStruct");

            CallToolResult result = client.callTool(new CallToolRequest("get-structure-info", infoArgs));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertEquals("InfoStruct", json.get("name").asText());
            assertEquals(3, json.get("numComponents").asInt());

            JsonNode fields = json.get("fields");
            assertNotNull("Should have fields", fields);
            assertEquals("Should have 3 fields", 3, fields.size());

            // Check first field
            JsonNode firstField = fields.get(0);
            assertEquals("id", firstField.get("fieldName").asText());
            assertEquals("int", firstField.get("dataType").asText());
        });
    }

    @Test
    public void testGetStructureInfoHasCRepresentation() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create a structure
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("cDefinition", "struct CRepTest { int x; char name[16]; void* ptr; };");

            CallToolResult createResult = client.callTool(new CallToolRequest("parse-c-structure", args));
            assertMcpResultNotError(createResult, "Create structure should not error");

            // Get structure info
            Map<String, Object> infoArgs = new HashMap<>();
            infoArgs.put("programPath", programPath);
            infoArgs.put("structureName", "CRepTest");

            CallToolResult result = client.callTool(new CallToolRequest("get-structure-info", infoArgs));
            assertMcpResultNotError(result, "Get info should not error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            // Verify C representation is present and well-formed
            JsonNode cRep = json.get("cRepresentation");
            assertNotNull("Should have C representation", cRep);
            String cCode = cRep.asText();

            assertTrue("C representation should start with struct keyword",
                cCode.startsWith("struct CRepTest {"));
            assertTrue("C representation should end with };",
                cCode.endsWith("};"));
            assertTrue("C representation should contain field x",
                cCode.contains("x;"));
            assertTrue("C representation should contain field name",
                cCode.contains("name;"));
            assertTrue("C representation should contain field ptr",
                cCode.contains("ptr;"));
        });
    }

    @Test
    public void testListStructures() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create multiple structures
            String[] structDefs = {
                "struct Struct1 { int a; };",
                "struct Struct2 { char b; };",
                "union Union1 { int x; float y; };"
            };

            for (String def : structDefs) {
                Map<String, Object> args = new HashMap<>();
                args.put("programPath", programPath);
                args.put("cDefinition", def);
                CallToolResult createResult = client.callTool(new CallToolRequest("parse-c-structure", args));
                assertMcpResultNotError(createResult, "Create structure should not error: " + def);
            }

            // List structures
            Map<String, Object> listArgs = new HashMap<>();
            listArgs.put("programPath", programPath);

            CallToolResult result = client.callTool(new CallToolRequest("list-structures", listArgs));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            JsonNode structures = json.get("structures");

            // Should have at least the 3 we created
            assertTrue("Should have at least 3 structures", structures.size() >= 3);

            // Verify our structures are in the list
            boolean foundStruct1 = false, foundStruct2 = false, foundUnion1 = false;
            for (JsonNode struct : structures) {
                String name = struct.get("name").asText();
                if ("Struct1".equals(name)) foundStruct1 = true;
                if ("Struct2".equals(name)) foundStruct2 = true;
                if ("Union1".equals(name)) foundUnion1 = true;
            }

            assertTrue("Should find Struct1", foundStruct1);
            assertTrue("Should find Struct2", foundStruct2);
            assertTrue("Should find Union1", foundUnion1);
        });
    }

    @Test
    public void testDeleteStructure() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create a structure using parse-c-structure
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("programPath", programPath);
            createArgs.put("cDefinition", "struct ToBeDeleted { int dummy; };");

            CallToolResult createResult = client.callTool(new CallToolRequest("parse-c-structure", createArgs));
            assertMcpResultNotError(createResult, "Create structure should not error");

            // Verify it exists
            DataType dt = findDataTypeByName(program.getDataTypeManager(), "ToBeDeleted");
            assertNotNull("Structure should exist before deletion", dt);

            // Delete it
            Map<String, Object> deleteArgs = new HashMap<>();
            deleteArgs.put("programPath", programPath);
            deleteArgs.put("structureName", "ToBeDeleted");

            CallToolResult result = client.callTool(new CallToolRequest("delete-structure", deleteArgs));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Should be deleted", json.get("deleted").asBoolean());

            // Verify it's gone
            dt = findDataTypeByName(program.getDataTypeManager(), "ToBeDeleted");
            assertNull("Structure should not exist after deletion", dt);
        });
    }

    @Test
    public void testDeleteStructureWithForceParameter() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create a structure using parse-c-structure
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("programPath", programPath);
            createArgs.put("cDefinition", "struct DeleteTestForce { int field1; };");

            CallToolResult createResult = client.callTool(new CallToolRequest("parse-c-structure", createArgs));
            assertMcpResultNotError(createResult, "Structure creation should succeed");

            // Verify structure exists
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByName(dtm, "DeleteTestForce");
            assertNotNull("Structure should exist", dt);

            // Delete structure (no references, so should succeed even without force)
            Map<String, Object> deleteArgs = new HashMap<>();
            deleteArgs.put("programPath", programPath);
            deleteArgs.put("structureName", "DeleteTestForce");

            CallToolResult deleteResult = client.callTool(new CallToolRequest("delete-structure", deleteArgs));
            assertMcpResultNotError(deleteResult, "Delete should succeed");

            TextContent content = (TextContent) deleteResult.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("deleted should be true", json.get("deleted").asBoolean());
            assertEquals("Successfully deleted structure: DeleteTestForce", json.get("message").asText());

            // Verify structure was deleted
            dt = findDataTypeByName(dtm, "DeleteTestForce");
            assertNull("Structure should be deleted", dt);
        });
    }

    @Test
    public void testParseCHeader() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            String headerContent =
                "struct Point { int x; int y; };\n" +
                "struct Rectangle { int width; int height; };";

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("headerContent", headerContent);

            CallToolResult result = client.callTool(new CallToolRequest("parse-c-header", args));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            JsonNode createdTypes = json.get("createdTypes");

            assertTrue("Should create at least one type", createdTypes.size() >= 1);

            // Verify at least one structure was created
            DataTypeManager dtm = program.getDataTypeManager();
            DataType point = findDataTypeByName(dtm, "Point");
            DataType rectangle = findDataTypeByName(dtm, "Rectangle");

            assertTrue("At least one structure (Point or Rectangle) should exist",
                point != null || rectangle != null);
        });
    }

    @Test
    public void testComplexNestedStructure() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            String complexDef =
                "struct Node {\n" +
                "    int value;\n" +
                "    struct Node* left;\n" +
                "    struct Node* right;\n" +
                "    union {\n" +
                "        int intData;\n" +
                "        float floatData;\n" +
                "    } data;\n" +
                "};";

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("cDefinition", complexDef);

            CallToolResult result = client.callTool(new CallToolRequest("parse-c-structure", args));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            // Get detailed info
            Map<String, Object> infoArgs = new HashMap<>();
            infoArgs.put("programPath", programPath);
            infoArgs.put("structureName", "Node");

            result = client.callTool(new CallToolRequest("get-structure-info", infoArgs));

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertNotNull("Should have C representation", json.get("cRepresentation"));
            assertEquals("Should have 4 components", 4, json.get("numComponents").asInt());
        });
    }

    /**
     * Helper method to find a data type by name in all categories
     */
    private DataType findDataTypeByName(DataTypeManager dtm, String name) {
        java.util.Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(name)) {
                return dt;
            }
        }
        return null;
    }
}
