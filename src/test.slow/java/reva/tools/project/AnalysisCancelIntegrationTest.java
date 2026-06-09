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
import java.util.List;
import java.util.Map;

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
import reva.services.AnalysisJob;
import reva.services.AnalysisJob.Status;
import reva.services.AnalysisJobManager;
import reva.services.AnalyzeRequest;
import reva.util.ProgramPersistenceUtil.PersistMode;
import reva.util.RevaInternalServiceRegistry;

/**
 * Integration test for the {@code analysis-cancel} tool.
 *
 * <p>Covers three deterministic paths (no reliance on racing a fast analysis):
 * an unknown jobId errors; an already-terminal job reports {@code alreadyTerminal:true}; and a
 * job pre-cancelled before submission (so the monitor is cancelled before {@code startAnalysis})
 * deterministically reaches {@link Status#CANCELLED}.
 *
 * <p>The saveable-program technique mirrors {@code AnalyzeProgramAsyncIntegrationTest}.
 */
public class AnalysisCancelIntegrationTest extends RevaIntegrationTestBase {

    private final ObjectMapper mapper = new ObjectMapper();

    private Program createRegisteredSaveableProgram(String label, DomainFile[] fileOut)
            throws Exception {
        DomainFolder root = env.getProject().getProjectData().getRootFolder();
        String fileName = "reva-analysis-cancel-" + label + "-" + System.nanoTime();
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
    public void testUnknownJobIdYieldsError() throws Exception {
        Map<String, Object> args = new HashMap<>();
        args.put("jobId", "analysis-999999");
        CallToolResult result = callToolRaw("analysis-cancel", args);
        assertTrue("Unknown jobId should yield an error result", result.isError());
        String text = ((TextContent) result.content().get(0)).text();
        assertTrue("Error text should mention the missing job",
            text.toLowerCase().contains("job") || text.contains("analysis-999999"));
    }

    @Test
    public void testCancelAlreadyTerminalJob() throws Exception {
        DomainFile[] fileOut = new DomainFile[1];
        Program saveable = createRegisteredSaveableProgram("terminal", fileOut);
        try {
            String programPath = saveable.getDomainFile().getPathname();

            // Large waitSeconds so the job completes inline; the tiny program finishes well under.
            JsonNode analyze = callTool("analyze-program", Map.of(
                "programPath", programPath,
                "waitSeconds", 60,
                "forceFullAnalysis", true,
                "persist", "save"));
            assertEquals("Inline completion should report completed",
                "completed", analyze.get("status").asText());
            String jobId = analyze.get("jobId").asText();
            assertFalse("jobId should be non-empty", jobId.isEmpty());

            JsonNode cancel = callTool("analysis-cancel", Map.of("jobId", jobId));
            assertTrue("Cancel of a finished job should report success",
                cancel.get("success").asBoolean());
            assertEquals("Echoed jobId should match", jobId, cancel.get("jobId").asText());
            assertTrue("A finished job should report alreadyTerminal",
                cancel.get("alreadyTerminal").asBoolean());
            assertEquals("Status should be completed", "completed", cancel.get("status").asText());
        } finally {
            cleanup(saveable, fileOut[0]);
        }
    }

    @Test
    public void testCancelRunningJobRequestsCancellation() throws Exception {
        AnalysisJobManager mgr =
            RevaInternalServiceRegistry.getService(AnalysisJobManager.class);
        assertNotNull("AnalysisJobManager service must be registered", mgr);

        // A created-but-never-submitted job stays RUNNING (no worker, no monitor), giving a
        // deterministic non-terminal target for the tool's request-cancellation path.
        AnalysisJob job = mgr.create("/reva-analysis-cancel-running-" + System.nanoTime());
        String jobId = job.getJobId();

        JsonNode cancel = callTool("analysis-cancel", Map.of("jobId", jobId));
        assertTrue("Cancel of a running job should report success",
            cancel.get("success").asBoolean());
        assertEquals("Echoed jobId should match", jobId, cancel.get("jobId").asText());
        assertFalse("A running job should not report alreadyTerminal",
            cancel.get("alreadyTerminal").asBoolean());
        assertEquals("Status should still read running (cancellation is async)",
            "running", cancel.get("status").asText());
        assertTrue("requestCancel should have set the cancel flag", job.isCancelRequested());
    }

    @Test
    public void testPreCancelledJobReachesCancelled() throws Exception {
        DomainFile[] fileOut = new DomainFile[1];
        Program saveable = createRegisteredSaveableProgram("cancelled", fileOut);
        try {
            String programPath = saveable.getDomainFile().getPathname();

            AnalysisJobManager mgr =
                RevaInternalServiceRegistry.getService(AnalysisJobManager.class);
            assertNotNull("AnalysisJobManager service must be registered", mgr);

            // Pre-cancel before submit: the runner cancels the monitor before startAnalysis, so
            // the terminal status is deterministically CANCELLED (no racing the worker).
            AnalysisJob job = mgr.create(programPath);
            job.requestCancel();
            mgr.submit(job, new AnalyzeRequest(
                saveable, List.of(), List.of(), true, 60, PersistMode.AUTO));

            long deadline = System.currentTimeMillis() + 60_000L;
            while (!job.getStatus().isTerminal()) {
                if (System.currentTimeMillis() > deadline) {
                    fail("Pre-cancelled job did not reach a terminal status within 60s; status="
                        + job.getStatus());
                }
                Thread.sleep(250L);
            }

            assertEquals("Pre-cancelled job should end CANCELLED",
                Status.CANCELLED, job.getStatus());
        } finally {
            cleanup(saveable, fileOut[0]);
        }
    }
}
