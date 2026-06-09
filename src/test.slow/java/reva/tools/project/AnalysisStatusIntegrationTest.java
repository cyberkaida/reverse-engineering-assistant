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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;
import reva.plugin.RevaProgramManager;

/**
 * Integration test for the {@code analysis-status} log-tailing long-poll tool.
 *
 * <p>Drives a real {@code analyze-program} background job (waitSeconds=0, so it returns a running
 * handle immediately), then loops on {@code analysis-status}, feeding back the {@code logCursor} as
 * {@code sinceLogSeq} until the job reaches a terminal state. Asserts that the cursor actually
 * paginates (no log seq is returned in two different calls), that log lines accumulate, and that the
 * terminal response carries a {@code result} payload. Finally asserts an unknown jobId errors.
 *
 * <p>The saveable-program technique mirrors {@code AnalyzeProgramAsyncIntegrationTest}.
 */
public class AnalysisStatusIntegrationTest extends RevaIntegrationTestBase {

    private final ObjectMapper mapper = new ObjectMapper();

    private Program createRegisteredSaveableProgram(String label, DomainFile[] fileOut)
            throws Exception {
        DomainFolder root = env.getProject().getProjectData().getRootFolder();
        String fileName = "reva-analysis-status-" + label + "-" + System.nanoTime();
        DomainFile file = root.createFile(fileName, program, TaskMonitor.DUMMY);
        fileOut[0] = file;

        Program saveable = (Program) file.getDomainObject(this, false, false, TaskMonitor.DUMMY);
        saveable.setTemporary(false);

        GhidraProgramUtilities.resetAnalysisFlags(saveable);
        assertFalse("Program should start un-analyzed after reset",
            GhidraProgramUtilities.isAnalyzed(saveable));

        RevaProgramManager.registerProgram(saveable);
        if (serverManager != null) {
            serverManager.programOpened(saveable, tool);
        }
        return saveable;
    }

    private void cleanup(Program saveable, DomainFile file) {
        if (saveable != null) {
            RevaProgramManager.unregisterProgram(saveable);
            if (serverManager != null) {
                serverManager.programClosed(saveable, tool);
            }
            saveable.release(this);
        }
        if (file != null) {
            try {
                file.delete();
            } catch (Exception ignore) {
                // best-effort cleanup of the temporary project file
            }
        }
    }

    private JsonNode callTool(String toolName, Map<String, Object> args) throws Exception {
        return withMcpClient(createMcpTransport(), (McpClientFunction<JsonNode>) client -> {
            client.initialize();
            CallToolResult result = client.callTool(new CallToolRequest(toolName, args));
            assertMcpResultNotError(result, toolName + " should succeed");
            String text = ((TextContent) result.content().get(0)).text();
            return mapper.readTree(text);
        });
    }

    private CallToolResult callToolRaw(String toolName, Map<String, Object> args) throws Exception {
        return withMcpClient(createMcpTransport(), (McpClientFunction<CallToolResult>) client -> {
            client.initialize();
            return client.callTool(new CallToolRequest(toolName, args));
        });
    }

    @Test
    public void testAnalysisStatusTailsJobUntilTerminal() throws Exception {
        DomainFile[] fileOut = new DomainFile[1];
        Program saveable = createRegisteredSaveableProgram("tail", fileOut);
        try {
            String programPath = saveable.getDomainFile().getPathname();

            // Kick off a background analysis that returns a running handle immediately.
            JsonNode analyze = callTool("analyze-program", Map.of(
                "programPath", programPath,
                "waitSeconds", 0,
                "forceFullAnalysis", true,
                "persist", "save"));
            assertEquals("waitSeconds=0 should return a running handle",
                "running", analyze.get("status").asText());
            String jobId = analyze.get("jobId").asText();
            assertFalse("jobId should be non-empty", jobId.isEmpty());

            Set<Long> seenSeqs = new HashSet<>();
            int totalLogEntries = 0;
            long cursor = 0;
            String status = "running";
            JsonNode terminalResponse = null;

            long deadline = System.currentTimeMillis() + 180_000L;
            while (true) {
                if (System.currentTimeMillis() > deadline) {
                    fail("analysis-status never reported a terminal status within 180s; last status="
                        + status);
                }

                JsonNode response = callTool("analysis-status", Map.of(
                    "jobId", jobId,
                    "sinceLogSeq", cursor,
                    "waitSeconds", 5,
                    "maxLogEntries", 50));

                assertEquals("Response jobId should echo the polled job",
                    jobId, response.get("jobId").asText());
                assertEquals("Response programPath should match",
                    programPath, response.get("programPath").asText());

                JsonNode log = response.get("log");
                assertNotNull("Response should carry a log array", log);
                for (JsonNode entry : log) {
                    long seq = entry.get("seq").asLong();
                    assertTrue("No log seq should be returned in two different calls (cursor leak): "
                        + seq, seenSeqs.add(seq));
                    totalLogEntries++;
                }

                cursor = response.get("logCursor").asLong();
                status = response.get("status").asText();

                if (status.equals("completed") || status.equals("failed")
                        || status.equals("cancelled") || status.equals("timed_out")) {
                    terminalResponse = response;
                    break;
                }
            }

            assertEquals("Job should reach completed", "completed", status);
            assertTrue("Should have accumulated at least one log entry", totalLogEntries > 0);
            assertNotNull("Terminal response should carry a result payload",
                terminalResponse.get("result"));
        } finally {
            cleanup(saveable, fileOut[0]);
        }
    }

    @Test
    public void testUnknownJobIdYieldsError() throws Exception {
        Map<String, Object> args = new HashMap<>();
        args.put("jobId", "analysis-999999");
        CallToolResult result = callToolRaw("analysis-status", args);
        assertTrue("Unknown jobId should yield an error result", result.isError());
        String text = ((TextContent) result.content().get(0)).text();
        assertTrue("Error text should mention the missing job",
            text.toLowerCase().contains("job") || text.contains("analysis-999999"));
    }
}
