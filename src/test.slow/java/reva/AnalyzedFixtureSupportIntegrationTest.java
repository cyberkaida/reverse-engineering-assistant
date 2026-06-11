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

import static org.junit.Assert.*;
import java.util.Map;
import org.junit.Test;
import com.fasterxml.jackson.databind.JsonNode;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

/**
 * Proves that a fixture binary can be imported, analyzed, and then queried by a
 * downstream tool resolving it by the returned programPath. If this fails, the
 * fixture-dependent Phase 1 tests cannot work and the failure localizes here.
 */
public class AnalyzedFixtureSupportIntegrationTest extends RevaIntegrationTestBase {

    @Test
    public void testImportAndAnalyzeResolvesDownstream() throws Exception {
        String importedPath = withMcpClient(createMcpTransport(),
            (McpClientFunction<String>) client -> {
                client.initialize();
                return AnalyzedFixtureSupport.importAndAnalyze(client, "test_x86_64");
            });
        assertNotNull("import-and-analyze should return a programPath", importedPath);
        assertTrue("programPath should be a project path", importedPath.startsWith("/"));

        // Downstream resolution: a symbol-table tool must find the imported program.
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result = client.callTool(new CallToolRequest(
                "get-symbols-count", Map.of("programPath", importedPath)));
            assertMcpResultNotError(result, "get-symbols-count on imported fixture");
            JsonNode json = parseJsonContent(((TextContent) result.content().get(0)).text());
            assertTrue("Analyzed binary should have symbols", json.get("count").asInt() > 0);
        });
    }
}
