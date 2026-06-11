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
package reva;

import java.io.File;
import java.util.Map;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

/**
 * Imports a binary from tests/fixtures/ via the import-file MCP tool and runs
 * analysis synchronously via analyze-program, returning the imported programPath.
 *
 * <p>Reusable harness for fixture-dependent integration tests that need a REAL
 * analyzed binary (imports, constants, dataflow, vtable) rather than the
 * synthetic ProgramBuilder program the base class provides.
 *
 * <p>Result-shape note (confirmed against {@code ProjectToolProvider}): the
 * {@code import-file} tool takes input parameter {@code path} (not
 * {@code filePath}) and returns {@code importedPrograms} (a list of project path
 * strings). There is no top-level {@code programPath} on the import result.
 */
public final class AnalyzedFixtureSupport {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AnalyzedFixtureSupport() {}

    public static String fixturePath(String name) {
        File dir = new File(System.getProperty("user.dir"), "tests/fixtures");
        return new File(dir, name).getAbsolutePath();
    }

    public static String importAndAnalyze(McpSyncClient client, String name) throws Exception {
        CallToolResult imported = client.callTool(new CallToolRequest("import-file",
            Map.of("path", fixturePath(name), "enableVersionControl", false)));
        if (imported.isError()) {
            throw new IllegalStateException("import-file failed for " + name + ": "
                + ((TextContent) imported.content().get(0)).text());
        }
        JsonNode importJson = MAPPER.readTree(((TextContent) imported.content().get(0)).text());
        String programPath = extractProgramPath(importJson);

        CallToolResult analyzed = client.callTool(new CallToolRequest("analyze-program",
            Map.of("programPath", programPath, "waitSeconds", 120, "forceFullAnalysis", true)));
        if (analyzed.isError()) {
            throw new IllegalStateException("analyze-program failed for " + programPath + ": "
                + ((TextContent) analyzed.content().get(0)).text());
        }
        JsonNode analyzeJson = MAPPER.readTree(((TextContent) analyzed.content().get(0)).text());
        String status = analyzeJson.path("status").asText();
        if (!"completed".equals(status)) {
            throw new IllegalStateException("analyze-program did not complete: status=" + status
                + " (full result: " + analyzeJson + ")");
        }
        return programPath;
    }

    private static String extractProgramPath(JsonNode importJson) {
        if (importJson.has("importedPrograms")
                && importJson.get("importedPrograms").isArray()
                && importJson.get("importedPrograms").size() > 0) {
            return importJson.get("importedPrograms").get(0).asText();
        }
        throw new IllegalStateException(
            "Could not find programPath in import-file result: " + importJson);
    }
}
