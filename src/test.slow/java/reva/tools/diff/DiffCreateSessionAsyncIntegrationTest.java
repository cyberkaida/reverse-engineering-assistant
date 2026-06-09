package reva.tools.diff;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.Program;

import reva.RevaIntegrationTestBase;

public class DiffCreateSessionAsyncIntegrationTest extends RevaIntegrationTestBase {

    /**
     * Verify that diff-create-session returns an inline summary when the correlation finishes
     * within the default waitSeconds=10. The tiny synthetic pair always correlates in well under
     * a second, so this is the fast-path / backward-compat proof: the result must carry the
     * standard summary fields (matched, unmatchedInSource, …) PLUS the new jobId/status fields.
     */
    @Test
    public void testInlineCompletionReturnsSummary() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ProgramManager pm = tool.getService(ProgramManager.class);
        env.open(src);
        env.open(dst);
        pm.openProgram(src);
        pm.openProgram(dst);
        serverManager.programOpened(src, tool);
        serverManager.programOpened(dst, tool);
        try {
            Map<String, Object> args = new HashMap<>();
            args.put("sourceProgramPath", src.getDomainFile().getPathname());
            args.put("destinationProgramPath", dst.getDomainFile().getPathname());
            // default waitSeconds=10 → tiny synthetic pair finishes inline

            JsonNode r = parseJsonContent(callMcpTool("diff-create-session", args));

            assertEquals("completed", r.get("status").asText());
            assertTrue("jobId present", r.has("jobId"));
            assertTrue("jobId is non-empty", !r.get("jobId").asText().isEmpty());

            // The summarize() map must be present: backward-compat with the pre-async response.
            assertTrue("inline result carries the summary 'matched' field", r.has("matched"));
            assertTrue("at least one identical match",
                r.get("matched").get("identical").asInt() >= 1);
            assertTrue("success flag present", r.get("success").asBoolean());
            assertTrue("sourceProgramPath present", r.has("sourceProgramPath"));
            assertTrue("destinationProgramPath present", r.has("destinationProgramPath"));

            // The essential side effect: the session is cached and therefore usable by the read funnel.
            assertNotNull("session cached after create-session",
                DiffSessionManager.get(
                    src.getDomainFile().getPathname(), dst.getDomainFile().getPathname()));
            assertTrue("summary reports the correlators that ran", r.has("correlatorsRun"));
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    /**
     * When waitSeconds=0, the session may return status="running" with a jobId. If so, we
     * immediately poll diff-status with waitSeconds=10 and expect it to drain to "completed"
     * with the summary "matched" field. If the tiny fixture races past the 0s deadline check
     * and returns "completed" inline, that is also acceptable.
     */
    @Test
    public void testWaitZeroReturnsRunningThenStatusDrains() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ProgramManager pm = tool.getService(ProgramManager.class);
        env.open(src);
        env.open(dst);
        pm.openProgram(src);
        pm.openProgram(dst);
        serverManager.programOpened(src, tool);
        serverManager.programOpened(dst, tool);
        try {
            String srcPath = src.getDomainFile().getPathname();
            String dstPath = dst.getDomainFile().getPathname();

            Map<String, Object> args = new HashMap<>();
            args.put("sourceProgramPath", srcPath);
            args.put("destinationProgramPath", dstPath);
            args.put("waitSeconds", 0);
            JsonNode running = parseJsonContent(callMcpTool("diff-create-session", args));

            if ("running".equals(running.get("status").asText())) {
                // Job is still in flight: poll diff-status until it drains.
                assertTrue("jobId present in running response", running.has("jobId"));
                Map<String, Object> statusArgs = new HashMap<>();
                statusArgs.put("jobId", running.get("jobId").asText());
                statusArgs.put("waitSeconds", 10);
                JsonNode done = parseJsonContent(callMcpTool("diff-status", statusArgs));
                assertEquals("completed", done.get("status").asText());
                assertTrue("summary 'matched' field present after draining", done.has("matched"));
            } else {
                // Tiny fixture finished before the 0s deadline check — that is fine.
                assertEquals("completed", running.get("status").asText());
            }
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }
}
