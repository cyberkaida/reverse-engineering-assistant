package reva.tools.diff;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import reva.RevaIntegrationTestBase;

/**
 * Integration tests for the async/background-job path of diff-transfer-markup.
 *
 * The tiny synthetic fixture always finishes well within the default waitSeconds=10, so
 * the "inline completion" path is exercised (status == "completed") — this is the
 * backward-compat proof that small match sets return the same fields as before, plus
 * the new jobId/status envelope.
 */
public class DiffTransferMarkupAsyncIntegrationTest extends RevaIntegrationTestBase {

    /**
     * Verify that diff-transfer-markup:
     * 1. Returns status="completed" and jobId when the transfer finishes inline.
     * 2. Still carries all the pre-async response fields (appliedCount, etc.).
     * 3. Actually renames the destination function in Ghidra program state.
     */
    @Test
    public void testTransferMarkupInlineRenamesDestination() throws Exception {
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

            // First create the session (the transfer tool requires one).
            Map<String, Object> sessionArgs = new HashMap<>();
            sessionArgs.put("sourceProgramPath", srcPath);
            sessionArgs.put("destinationProgramPath", dstPath);
            JsonNode sess = parseJsonContent(callMcpTool("diff-create-session", sessionArgs));
            assertEquals("session correlated inline before transfer", "completed",
                sess.get("status").asText());

            // Verify the destination function is NOT yet named "identical_fn" (starts as FUN_*).
            Address destIdentical = dst.getAddressFactory().getAddress(DiffTestPrograms.IDENTICAL_FN);
            String before = dst.getFunctionManager().getFunctionAt(destIdentical).getName();
            assertNotEquals("destination function should not yet be named identical_fn", "identical_fn", before);

            // Call diff-transfer-markup (uses default waitSeconds=10).
            Map<String, Object> args = new HashMap<>();
            args.put("sourceProgramPath", srcPath);
            args.put("destinationProgramPath", dstPath);
            JsonNode r = parseJsonContent(callMcpTool("diff-transfer-markup", args));

            // Async envelope: tiny synthetic pair finishes inline → status="completed".
            assertEquals("completed", r.get("status").asText());
            assertTrue("jobId present", r.has("jobId"));
            assertTrue("jobId is non-empty", !r.get("jobId").asText().isEmpty());

            // Pre-async fields must still be present (backward-compat).
            assertTrue("success flag present", r.get("success").asBoolean());
            assertTrue("appliedCount present", r.has("appliedCount"));
            assertTrue("skippedCount present", r.has("skippedCount"));
            assertTrue("proposedCount present", r.has("proposedCount"));
            assertTrue("applied array present", r.has("applied"));
            assertTrue("skipped array present", r.has("skipped"));
            assertTrue("proposed array present", r.has("proposed"));
            assertTrue("at least one match applied", r.get("appliedCount").asInt() >= 1);

            // ACTUAL Ghidra program state validation: the destination function now carries
            // the source name "identical_fn".
            String after = dst.getFunctionManager().getFunctionAt(destIdentical).getName();
            assertEquals("identical_fn", after);
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }
}
