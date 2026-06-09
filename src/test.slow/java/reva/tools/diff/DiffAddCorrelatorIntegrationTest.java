package reva.tools.diff;

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.After;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.app.services.ProgramManager;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import reva.RevaIntegrationTestBase;

/**
 * Integration tests for {@code diff-add-correlator}: incremental VT correlator refinement over
 * a persisted diff session's residual.
 *
 * <p>Fixture: two-function pair (alpha_fn / beta_fn) where source functions are named but
 * destination functions carry Ghidra default names (FUN_*). A symbol-name-only baseline
 * leaves both in the residual (no name match); exact-bytes then closes them.
 */
public class DiffAddCorrelatorIntegrationTest extends RevaIntegrationTestBase {

    private static final AtomicInteger SEQ = new AtomicInteger();

    private static String unique(String base) {
        return base + "_addcor_" + SEQ.incrementAndGet();
    }

    // alpha_fn body: xor eax,eax ; ret  (31 C0 C3) — distinct from beta
    private static final byte[] ALPHA_BODY = {0x31, (byte) 0xC0, (byte) 0xC3};
    // beta_fn body:  inc eax ; ret  (40 C3) — distinct from alpha
    private static final byte[] BETA_BODY  = {0x40, (byte) 0xC3};

    private static final String ALPHA_ADDR = "0x02001000";
    private static final String BETA_ADDR  = "0x02002000";

    /** Source: alpha_fn and beta_fn, both named. */
    private Program buildSource() throws Exception {
        ProgramBuilder b = new ProgramBuilder(unique("addcor_src"), ProgramBuilder._X86, this);
        b.createMemory("text", "0x02001000", 0x2000);
        b.setBytes(ALPHA_ADDR, ALPHA_BODY);
        b.disassemble(ALPHA_ADDR, ALPHA_BODY.length);
        b.createEmptyFunction("alpha_fn", ALPHA_ADDR, ALPHA_BODY.length, null);
        b.setBytes(BETA_ADDR, BETA_BODY);
        b.disassemble(BETA_ADDR, BETA_BODY.length);
        b.createEmptyFunction("beta_fn", BETA_ADDR, BETA_BODY.length, null);
        return b.getProgram();
    }

    /**
     * Destination: same bytes at the same addresses, but NO named functions (default FUN_* names).
     * Symbol-name correlator cannot match them; exact-bytes correlator can.
     */
    private Program buildDest() throws Exception {
        ProgramBuilder b = new ProgramBuilder(unique("addcor_dst"), ProgramBuilder._X86, this);
        b.createMemory("text", "0x02001000", 0x2000);
        b.setBytes(ALPHA_ADDR, ALPHA_BODY);
        b.disassemble(ALPHA_ADDR, ALPHA_BODY.length);
        b.createEmptyFunction(null, ALPHA_ADDR, ALPHA_BODY.length, null);  // no name → FUN_*
        b.setBytes(BETA_ADDR, BETA_BODY);
        b.disassemble(BETA_ADDR, BETA_BODY.length);
        b.createEmptyFunction(null, BETA_ADDR, BETA_BODY.length, null);    // no name → FUN_*
        return b.getProgram();
    }

    /** Persist to project (VTSessionDB needs real file IDs) and register with MCP server. */
    private Program[] buildPersistAndRegister() throws Exception {
        Program src = buildSource();
        Program dst = buildDest();
        DomainFolder root = AppInfo.getActiveProject().getProjectData().getRootFolder();
        root.createFile(src.getName(), src, TaskMonitor.DUMMY);
        root.createFile(dst.getName(), dst, TaskMonitor.DUMMY);
        ProgramManager pm = tool.getService(ProgramManager.class);
        env.open(src);
        env.open(dst);
        pm.openProgram(src);
        pm.openProgram(dst);
        serverManager.programOpened(src, tool);
        serverManager.programOpened(dst, tool);
        return new Program[]{src, dst};
    }

    @After
    public void tearDownDiffSessions() {
        DiffSessionManager.clearAll();
    }

    /**
     * After a symbol-name-only baseline (which cannot match unnamed dest functions),
     * diff-add-correlator with exact-bytes must grow matched.identical and shrink unmatchedInSource.
     */
    @Test
    public void testAddCorrelatorShrinksResidual() throws Exception {
        Program[] pair = buildPersistAndRegister();
        Program src = pair[0];
        Program dst = pair[1];
        try {
            String srcPath = src.getDomainFile().getPathname();
            String dstPath = dst.getDomainFile().getPathname();

            // 1) Baseline: symbol-name only — dest functions are unnamed, so nothing matches.
            Map<String, Object> baseArgs = new HashMap<>();
            baseArgs.put("sourceProgramPath", srcPath);
            baseArgs.put("destinationProgramPath", dstPath);
            baseArgs.put("correlators", List.of("symbol-name"));
            JsonNode baseline = parseJsonContent(callMcpTool("diff-create-session", baseArgs));
            assertEquals("completed", baseline.get("status").asText());
            assertTrue("baseline success", baseline.get("success").asBoolean());
            int baselineIdentical = baseline.get("matched").get("identical").asInt();
            int baselineUnmatched = baseline.get("unmatchedInSource").asInt();
            // Symbol-name alone should match 0 functions (dest is unnamed).
            assertEquals("symbol-name baseline: 0 identical matches expected", 0, baselineIdentical);
            assertTrue("symbol-name baseline: at least 1 unmatched in source",
                baselineUnmatched >= 1);

            // 2) Add exact-bytes correlator over the residual.
            Map<String, Object> addArgs = new HashMap<>();
            addArgs.put("sourceProgramPath", srcPath);
            addArgs.put("destinationProgramPath", dstPath);
            addArgs.put("correlator", "exact-bytes");
            JsonNode refined = parseJsonContent(callMcpTool("diff-add-correlator", addArgs));
            assertEquals("completed", refined.get("status").asText());
            assertTrue("refined success", refined.get("success").asBoolean());

            int refinedIdentical = refined.get("matched").get("identical").asInt();
            int refinedUnmatched = refined.get("unmatchedInSource").asInt();

            // Exact-bytes must have matched the byte-identical functions.
            assertTrue("exact-bytes must increase identical matches: " + baselineIdentical
                + " -> " + refinedIdentical, refinedIdentical > baselineIdentical);
            assertTrue("unmatchedInSource must decrease after refinement: " + baselineUnmatched
                + " -> " + refinedUnmatched, refinedUnmatched < baselineUnmatched);
        } finally {
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    /**
     * When sourceScope names only alpha_fn (and destinationScope its address), the correlator
     * must only match alpha — beta_fn stays in the residual.
     */
    @Test
    public void testScopedAddCorrelatorOnlyConsidersScope() throws Exception {
        Program[] pair = buildPersistAndRegister();
        Program src = pair[0];
        Program dst = pair[1];
        try {
            String srcPath = src.getDomainFile().getPathname();
            String dstPath = dst.getDomainFile().getPathname();

            // Baseline: symbol-name only → 0 matches, both in residual.
            Map<String, Object> baseArgs = new HashMap<>();
            baseArgs.put("sourceProgramPath", srcPath);
            baseArgs.put("destinationProgramPath", dstPath);
            baseArgs.put("correlators", List.of("symbol-name"));
            JsonNode baseline = parseJsonContent(callMcpTool("diff-create-session", baseArgs));
            assertEquals("completed", baseline.get("status").asText());
            assertEquals("symbol-name: 0 identical", 0,
                baseline.get("matched").get("identical").asInt());

            // Scoped add: only alpha_fn on source side; dest alpha is at ALPHA_ADDR.
            Map<String, Object> addArgs = new HashMap<>();
            addArgs.put("sourceProgramPath", srcPath);
            addArgs.put("destinationProgramPath", dstPath);
            addArgs.put("correlator", "exact-bytes");
            addArgs.put("sourceScope", List.of("alpha_fn"));
            addArgs.put("destinationScope", List.of(ALPHA_ADDR));
            JsonNode refined = parseJsonContent(callMcpTool("diff-add-correlator", addArgs));
            assertEquals("completed", refined.get("status").asText());
            assertTrue("refined success", refined.get("success").asBoolean());

            int refinedIdentical = refined.get("matched").get("identical").asInt();
            // Only alpha matched; beta is still unmatched.
            assertEquals("scoped refinement: exactly 1 identical (alpha only)", 1, refinedIdentical);

            // beta_fn must remain unmatched on the source side.
            int unmatchedSrc = refined.get("unmatchedInSource").asInt();
            assertTrue("beta_fn must remain unmatched in source (unmatchedInSource >= 1)",
                unmatchedSrc >= 1);
        } finally {
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    /**
     * A bad correlator key must produce a synchronous error response (not a job).
     * Note: a valid session must exist first, since requireSession() runs before correlatorForKey().
     */
    @Test
    public void testAddCorrelatorBadCorrelatorErrors() throws Exception {
        Program[] pair = buildPersistAndRegister();
        Program src = pair[0];
        Program dst = pair[1];
        try {
            String srcPath = src.getDomainFile().getPathname();
            String dstPath = dst.getDomainFile().getPathname();

            // Create a valid session first so requireSession() passes.
            Map<String, Object> baseArgs = new HashMap<>();
            baseArgs.put("sourceProgramPath", srcPath);
            baseArgs.put("destinationProgramPath", dstPath);
            baseArgs.put("correlators", List.of("symbol-name"));
            parseJsonContent(callMcpTool("diff-create-session", baseArgs));

            // Now try a bad correlator key — should error from correlatorForKey().
            Map<String, Object> addArgs = new HashMap<>();
            addArgs.put("sourceProgramPath", srcPath);
            addArgs.put("destinationProgramPath", dstPath);
            addArgs.put("correlator", "not-a-correlator");
            verifyMcpToolFailsWithError("diff-add-correlator", addArgs, "not-a-correlator");
        } finally {
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }
}
