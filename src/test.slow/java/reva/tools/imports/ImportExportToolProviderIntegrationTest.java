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
package reva.tools.imports;

import static org.junit.Assert.*;
import java.util.Map;
import org.junit.Test;
import com.fasterxml.jackson.databind.JsonNode;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.AnalyzedFixtureSupport;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for the imports/exports tool package against a REAL analyzed
 * Mach-O fixture (test_x86_64, built from test_program.c with a printf call in main).
 *
 * <p>Expected values are pinned to the tool's observed behavior on this fixture.
 * Mach-O imports are prefixed with an underscore (e.g. {@code _printf}), so name
 * matching is done by reading a real import name from {@code list-imports} and
 * feeding it back into {@code find-import-references} rather than hardcoding.
 */
public class ImportExportToolProviderIntegrationTest extends RevaIntegrationTestBase {

    /**
     * Read the ungrouped import list and return the import entry whose name matches
     * "printf" or "_printf" (case-insensitive). Returns null if none is present.
     */
    private static JsonNode findPrintfImport(JsonNode importsArray) {
        for (JsonNode imp : importsArray) {
            String name = imp.path("name").asText();
            if (name.equalsIgnoreCase("printf") || name.equalsIgnoreCase("_printf")) {
                return imp;
            }
        }
        return null;
    }

    @Test
    public void testListImportsContainsPrintf() throws Exception {
        String path = AnalyzedFixtureSupport.importAndAnalyze(this, "test_x86_64");
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            // groupByLibrary defaults to true (-> "libraries"); request ungrouped to get "imports".
            CallToolResult r = client.callTool(new CallToolRequest("list-imports",
                Map.of("programPath", path, "maxResults", 500, "groupByLibrary", false)));
            assertMcpResultNotError(r, "list-imports");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            assertEquals("programPath echoed back", path, json.get("programPath").asText());
            assertTrue("fixture should have imports", json.get("totalCount").asInt() > 0);

            JsonNode imports = json.get("imports");
            assertNotNull("ungrouped result has an imports array", imports);
            assertTrue("imports array is non-empty", imports.size() > 0);

            JsonNode printf = findPrintfImport(imports);
            assertNotNull("printf should appear among imports", printf);
            assertTrue("import entry has a name", printf.has("name"));
            assertTrue("import entry has a library", printf.has("library"));
        });
    }

    @Test
    public void testListImportsGroupedByLibrary() throws Exception {
        String path = AnalyzedFixtureSupport.importAndAnalyze(this, "test_x86_64");
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            // Default grouping: result carries "libraries", not "imports".
            CallToolResult r = client.callTool(new CallToolRequest("list-imports",
                Map.of("programPath", path, "maxResults", 500)));
            assertMcpResultNotError(r, "list-imports grouped");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            assertTrue("default grouping returns a libraries array", json.has("libraries"));
            assertFalse("grouped result should not carry a flat imports array", json.has("imports"));
            JsonNode libraries = json.get("libraries");
            assertTrue("at least one library group", libraries.size() > 0);
            for (JsonNode lib : libraries) {
                assertTrue("library group has a name", lib.has("name"));
                assertTrue("library group has importCount", lib.has("importCount"));
                assertTrue("library group has nested imports", lib.has("imports"));
            }
        });
    }

    @Test
    public void testFindImportReferencesToPrintf() throws Exception {
        String path = AnalyzedFixtureSupport.importAndAnalyze(this, "test_x86_64");
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Resolve the real import name (printf vs _printf) from list-imports first.
            CallToolResult listResult = client.callTool(new CallToolRequest("list-imports",
                Map.of("programPath", path, "maxResults", 500, "groupByLibrary", false)));
            assertMcpResultNotError(listResult, "list-imports");
            JsonNode listJson = parseJsonContent(((TextContent) listResult.content().get(0)).text());
            JsonNode printfImport = findPrintfImport(listJson.get("imports"));
            assertNotNull("fixture must expose a printf import to reference", printfImport);
            String printfName = printfImport.get("name").asText();

            CallToolResult r = client.callTool(new CallToolRequest("find-import-references",
                Map.of("programPath", path, "importName", printfName)));
            assertMcpResultNotError(r, "find-import-references");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            assertEquals("searchedImport echoed back", printfName, json.get("searchedImport").asText());
            assertTrue("matched at least one import", json.get("matchedImports").size() > 0);
            assertEquals("referenceCount matches references size",
                json.get("references").size(), json.get("referenceCount").asInt());
            assertTrue("main references printf", json.get("references").size() > 0);

            boolean anyCall = false;
            for (JsonNode ref : json.get("references")) {
                assertTrue("reference has fromAddress", ref.has("fromAddress"));
                assertTrue("reference has referenceType", ref.has("referenceType"));
                assertTrue("reference has isCall flag", ref.has("isCall"));
                if (ref.path("isCall").asBoolean()) {
                    anyCall = true;
                }
            }
            assertTrue("at least one printf reference is a call", anyCall);
        });
    }

    @Test
    public void testListExports() throws Exception {
        String path = AnalyzedFixtureSupport.importAndAnalyze(this, "test_x86_64");
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult r = client.callTool(new CallToolRequest("list-exports",
                Map.of("programPath", path)));
            assertMcpResultNotError(r, "list-exports");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            // Real shape (ImportExportToolProvider#registerListExportsTool, ~line 156):
            // programPath, totalCount, startIndex, returnedCount, exports[].
            assertEquals("programPath echoed back", path, json.get("programPath").asText());
            assertTrue("list-exports reports a totalCount", json.has("totalCount"));
            assertEquals("startIndex defaults to 0", 0, json.get("startIndex").asInt());
            assertTrue("list-exports carries an exports array", json.get("exports").isArray());
            assertEquals("returnedCount matches exports array size",
                json.get("exports").size(), json.get("returnedCount").asInt());

            // This executable has entry points (e.g. main/_main), so expect at least one export.
            assertTrue("analyzed executable should expose at least one export entry",
                json.get("totalCount").asInt() > 0);
            for (JsonNode exp : json.get("exports")) {
                assertTrue("export entry has an address", exp.has("address"));
            }
        });
    }

    @Test
    public void testResolveThunkOnImportThunk() throws Exception {
        String path = AnalyzedFixtureSupport.importAndAnalyze(this, "test_x86_64");
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // An import's reported "address" is an EXTERNAL-space placeholder (e.g. 0x00000001),
            // which resolve-thunk cannot map to a real function. The resolvable thunk lives in the
            // program's code: surface it via a viaThunk reference from find-import-references.
            CallToolResult listResult = client.callTool(new CallToolRequest("list-imports",
                Map.of("programPath", path, "maxResults", 500, "groupByLibrary", false)));
            assertMcpResultNotError(listResult, "list-imports");
            JsonNode listJson = parseJsonContent(((TextContent) listResult.content().get(0)).text());
            JsonNode printfImport = findPrintfImport(listJson.get("imports"));
            assertNotNull("fixture must expose a printf import", printfImport);

            CallToolResult refResult = client.callTool(new CallToolRequest("find-import-references",
                Map.of("programPath", path, "importName", printfImport.get("name").asText())));
            assertMcpResultNotError(refResult, "find-import-references");
            JsonNode refJson = parseJsonContent(((TextContent) refResult.content().get(0)).text());

            String thunkAddress = null;
            for (JsonNode ref : refJson.get("references")) {
                if (ref.path("viaThunk").asBoolean() && ref.has("thunkAddress")) {
                    thunkAddress = ref.get("thunkAddress").asText();
                    break;
                }
            }
            assertNotNull("test_x86_64 should produce a viaThunk reference for printf after full analysis; "
                + "if the tool stopped emitting thunkAddress this must fail, not skip", thunkAddress);

            CallToolResult r = client.callTool(new CallToolRequest("resolve-thunk",
                Map.of("programPath", path, "address", thunkAddress)));
            assertMcpResultNotError(r, "resolve-thunk");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            assertEquals("programPath echoed back", path, json.get("programPath").asText());
            assertTrue("response carries a chain array", json.get("chain").isArray());
            assertTrue("chain is non-empty", json.get("chain").size() > 0);
            assertEquals("chainLength matches chain size",
                json.get("chain").size(), json.get("chainLength").asInt());
            assertTrue("response carries a finalTarget", json.has("finalTarget"));
            assertTrue("response carries an isResolved flag", json.has("isResolved"));
            assertTrue("finalTarget has a name", json.get("finalTarget").has("name"));
        });
    }

    @Test
    public void testListImportsMissingProgramIsError() throws Exception {
        // No fixture needed: the missing-program path errors before any program is touched.
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult r = client.callTool(new CallToolRequest("list-imports",
                Map.of("programPath", "/does-not-exist")));
            assertTrue("list-imports on a missing program should error", r.isError());
        });
    }
}
