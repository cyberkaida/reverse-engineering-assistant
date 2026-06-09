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

import java.util.List;
import java.util.Map;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
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
import reva.util.RevaInternalServiceRegistry;

/**
 * End-to-end durability/async regression test for the {@code analyze-program} tool after it was
 * converted from a synchronous run into a background job with an inline long-poll.
 *
 * <p>Test 1 (the headline durability fix) drives a real auto-analysis through the MCP tool against
 * a saveable, project-backed, non-temporary program and asserts that completing inline actually
 * SAVED the program ({@code persisted="save"}, {@code saved=true}, {@code isChanged()==false}).
 * Test 2 exercises the long-poll fallthrough with {@code waitSeconds=0}, which must return a
 * {@code status:"running"} job handle that subsequently reaches COMPLETED.
 *
 * <p>The saveable-program technique mirrors {@code AnalysisJobRunnerIntegrationTest}: the base
 * class's shared {@code program} is a temporary ProgramBuilder program ({@code isChanged()} pinned
 * to false). We copy it into the project, re-open the resulting {@link DomainFile} to get a
 * change-tracking instance, clear its {@code temporary} flag, and register that exact instance with
 * the server so {@code getProgramByPath} resolves the tool to it.
 */
public class AnalyzeProgramAsyncIntegrationTest extends RevaIntegrationTestBase {

    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Copy the shared (temporary) program into the project, re-open it as a saveable,
     * change-tracking instance, clear its temporary flag, reset analysis flags, and register it
     * with the shared server so the tool can resolve it by path.
     */
    private Program createRegisteredSaveableProgram(String label, DomainFile[] fileOut)
            throws Exception {
        DomainFolder root = env.getProject().getProjectData().getRootFolder();
        String fileName = "reva-analyze-async-" + label + "-" + System.nanoTime();
        DomainFile file = root.createFile(fileName, program, TaskMonitor.DUMMY);
        fileOut[0] = file;

        Program saveable = (Program) file.getDomainObject(this, false, false, TaskMonitor.DUMMY);
        // TestEnv programs default to temporary, which pins isChanged() to false. Clear it so the
        // save path is exercised exactly as in headless/CLI mode.
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

    private JsonNode callAnalyze(Map<String, Object> args) throws Exception {
        return withMcpClient(createMcpTransport(), (McpClientFunction<JsonNode>) client -> {
            client.initialize();
            CallToolResult result = client.callTool(new CallToolRequest("analyze-program", args));
            assertMcpResultNotError(result, "analyze-program should succeed");
            String text = ((TextContent) result.content().get(0)).text();
            return mapper.readTree(text);
        });
    }

    /**
     * Headline durability regression: completing inline must actually persist the program.
     */
    @Test
    public void testInlineCompletionSavesProgram() throws Exception {
        DomainFile[] fileOut = new DomainFile[1];
        Program saveable = createRegisteredSaveableProgram("inline", fileOut);
        try {
            String programPath = saveable.getDomainFile().getPathname();
            assertTrue("Project-backed program should be saveable",
                saveable.getDomainFile().canSave());

            // Deliberately dirty the program so the persist step has something real to save.
            // (Analysis of this tiny zero-filled block nets no DB change on its own.)
            int tx = saveable.startTransaction("Dirty for persist");
            try {
                saveable.getSymbolTable().createLabel(
                    saveable.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000),
                    "reva_test_marker", SourceType.USER_DEFINED);
                saveable.endTransaction(tx, true);
            } catch (Exception e) {
                saveable.endTransaction(tx, false);
                throw e;
            }
            saveable.flushEvents();
            assertTrue("Program should be dirty before analyze", saveable.isChanged());

            JsonNode response = callAnalyze(Map.of(
                "programPath", programPath,
                "waitSeconds", 120,
                "forceFullAnalysis", true,
                "persist", "save"));

            assertEquals("Inline completion should report completed",
                "completed", response.get("status").asText());
            assertNotNull("Response should carry a jobId", response.get("jobId"));
            assertFalse("jobId should be non-empty", response.get("jobId").asText().isEmpty());
            assertTrue("Response should report success", response.get("success").asBoolean());

            assertEquals("Project-backed non-versioned program should take the SAVE path",
                "save", response.get("persisted").asText());
            assertTrue("Persist should report a successful save",
                response.get("saved").asBoolean());

            // The durability guarantee: the tool's job actually saved the dirty program.
            saveable.flushEvents();
            assertFalse("Saving should clear the dirty flag", saveable.isChanged());
            assertTrue("Program should be marked analyzed",
                GhidraProgramUtilities.isAnalyzed(saveable));
        } finally {
            cleanup(saveable, fileOut[0]);
        }
    }

    /**
     * Long-poll fallthrough: waitSeconds=0 returns a running job handle that later completes.
     */
    @Test
    public void testLongPollFallthrough() throws Exception {
        DomainFile[] fileOut = new DomainFile[1];
        Program saveable = createRegisteredSaveableProgram("longpoll", fileOut);
        try {
            String programPath = saveable.getDomainFile().getPathname();

            JsonNode response = callAnalyze(Map.of(
                "programPath", programPath,
                "waitSeconds", 0,
                "forceFullAnalysis", true,
                "persist", "save"));

            assertEquals("waitSeconds=0 should return a running handle",
                "running", response.get("status").asText());
            assertNotNull("Response should carry a jobId", response.get("jobId"));
            String jobId = response.get("jobId").asText();
            assertFalse("jobId should be non-empty", jobId.isEmpty());

            AnalysisJobManager mgr =
                RevaInternalServiceRegistry.getService(AnalysisJobManager.class);
            assertNotNull("AnalysisJobManager service must be registered", mgr);
            AnalysisJob job = mgr.get(jobId);
            assertNotNull("Job should be retrievable by id", job);

            long deadline = System.currentTimeMillis() + 180_000L;
            while (!job.getStatus().isTerminal()) {
                if (System.currentTimeMillis() > deadline) {
                    fail("Analysis job did not reach a terminal status within 180s; status="
                        + job.getStatus());
                }
                Thread.sleep(250L);
            }

            assertEquals("Job should complete successfully", Status.COMPLETED, job.getStatus());
        } finally {
            cleanup(saveable, fileOut[0]);
        }
    }
}
