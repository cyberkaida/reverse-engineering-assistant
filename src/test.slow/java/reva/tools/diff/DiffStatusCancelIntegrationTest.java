package reva.tools.diff;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.Program;

import reva.RevaIntegrationTestBase;

/**
 * Integration tests for the diff-status and diff-cancel tools.
 */
public class DiffStatusCancelIntegrationTest extends RevaIntegrationTestBase {

    /**
     * Build and open the synthetic pair, returning [srcPath, dstPath] in the array.
     * The caller is responsible for tearing down via clearAll + programClosed + release.
     */
    private Program[] buildAndOpenPair() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ProgramManager pm = tool.getService(ProgramManager.class);
        env.open(src);
        env.open(dst);
        pm.openProgram(src);
        pm.openProgram(dst);
        serverManager.programOpened(src, tool);
        serverManager.programOpened(dst, tool);
        return new Program[]{src, dst};
    }

    private void tearDownPair(Program src, Program dst) throws Exception {
        DiffSessionManager.clearAll();
        serverManager.programClosed(src, tool);
        serverManager.programClosed(dst, tool);
        src.release(this);
        dst.release(this);
    }

    /**
     * Poll diff-status by source+destination pair after create-session has completed.
     * The tiny synthetic pair completes inline, so the status poll must report "completed"
     * and carry the summary "matched" field from the correlate result.
     */
    @Test
    public void testStatusByPairReachesTerminal() throws Exception {
        Program[] pair = buildAndOpenPair();
        Program src = pair[0];
        Program dst = pair[1];
        String srcPath = src.getDomainFile().getPathname();
        String dstPath = dst.getDomainFile().getPathname();
        try {
            // Correlate the pair first (inline completes for the tiny synthetic pair).
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("sourceProgramPath", srcPath);
            createArgs.put("destinationProgramPath", dstPath);
            callMcpTool("diff-create-session", createArgs);

            // Now poll diff-status by pair (no jobId).
            Map<String, Object> statusArgs = new HashMap<>();
            statusArgs.put("sourceProgramPath", srcPath);
            statusArgs.put("destinationProgramPath", dstPath);
            JsonNode s = parseJsonContent(callMcpTool("diff-status", statusArgs));

            assertEquals("correlate", s.get("kind").asText());
            assertEquals("completed", s.get("status").asText());
            assertTrue("matched field present in terminal result", s.has("matched"));
            assertTrue("jobId present", s.has("jobId"));
        } finally {
            tearDownPair(src, dst);
        }
    }

    /**
     * diff-status must reject maxLogEntries < 1 with a structured error (otherwise logSince
     * returns empty-but-truncated and a draining agent loops forever). Deterministic guard,
     * unlike the FAILED/CANCELLED job shape which the fast synthetic fixture can't reliably
     * produce.
     *
     * Note: the FAILED/CANCELLED {@code success:false} shape from Fix 1 is verified by code
     * review and consistency with awaitDiffJob, but is NOT covered by an integration test
     * because the synthetic pair completes too fast to deterministically observe a
     * cancelled/failed diff job. That residual gap is accepted.
     */
    @Test
    public void testStatusRejectsBadMaxLogEntries() throws Exception {
        Program[] pair = buildAndOpenPair();
        Program src = pair[0];
        Program dst = pair[1];
        String srcPath = src.getDomainFile().getPathname();
        String dstPath = dst.getDomainFile().getPathname();
        try {
            // A session must exist so the call gets past job resolution to the validation guards.
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("sourceProgramPath", srcPath);
            createArgs.put("destinationProgramPath", dstPath);
            callMcpTool("diff-create-session", createArgs);

            Map<String, Object> args = new HashMap<>();
            args.put("sourceProgramPath", srcPath);
            args.put("destinationProgramPath", dstPath);
            args.put("maxLogEntries", 0);
            try {
                String raw = callMcpTool("diff-status", args);
                assertTrue("response should reject maxLogEntries",
                    raw.toLowerCase().contains("maxlogentries"));
            } catch (RuntimeException e) {
                // Tool signalled isError=true; the validation message is in the exception.
                assertTrue("error should mention maxLogEntries",
                    e.getMessage().toLowerCase().contains("maxlogentries"));
            }
        } finally {
            tearDownPair(src, dst);
        }
    }

    /**
     * diff-cancel with an unknown jobId should return a structured error (not a tool-level
     * exception), and the raw response must contain "no diff job" (case-insensitive).
     */
    @Test
    public void testCancelUnknownJobErrors() throws Exception {
        // No pair setup needed; we just call cancel with a bogus ID.
        // callMcpTool throws on isError()==true, so the error text ends up in the exception msg.
        try {
            Map<String, Object> args = new HashMap<>();
            args.put("jobId", "diff-999999");
            String raw = callMcpTool("diff-cancel", args);
            // If it returned content without isError, check the body for the error phrase.
            assertTrue("response should contain 'no diff job'", raw.toLowerCase().contains("no diff job"));
        } catch (RuntimeException e) {
            // Tool signalled isError=true; the exception carries the content.
            assertTrue("error should mention 'no diff job'",
                e.getMessage().toLowerCase().contains("no diff job"));
        }
    }

    /**
     * Cancelling a job that already completed should be a no-op: alreadyTerminal=true,
     * success=true, and a status that is not "running".
     */
    @Test
    public void testCancelAlreadyTerminalIsNoOp() throws Exception {
        Program[] pair = buildAndOpenPair();
        Program src = pair[0];
        Program dst = pair[1];
        String srcPath = src.getDomainFile().getPathname();
        String dstPath = dst.getDomainFile().getPathname();
        try {
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("sourceProgramPath", srcPath);
            createArgs.put("destinationProgramPath", dstPath);
            JsonNode created = parseJsonContent(callMcpTool("diff-create-session", createArgs));
            String jobId = created.get("jobId").asText();

            // Cancel the already-completed job.
            Map<String, Object> cancelArgs = new HashMap<>();
            cancelArgs.put("jobId", jobId);
            JsonNode r = parseJsonContent(callMcpTool("diff-cancel", cancelArgs));

            assertTrue("success flag", r.get("success").asBoolean());
            assertTrue("alreadyTerminal must be true for a completed job",
                r.get("alreadyTerminal").asBoolean());
            assertNotEquals("status should not be 'running'", "running", r.get("status").asText());
        } finally {
            tearDownPair(src, dst);
        }
    }
}
