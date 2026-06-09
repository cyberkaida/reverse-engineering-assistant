package reva.tools.diff;

import static org.junit.Assert.*;

import java.util.*;

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
 * Integration tests for the sourceScope/destinationScope parameters on diff-create-session.
 *
 * <p>Fixtures: a small (source, destination) program pair with two named functions that are
 * byte-identical to their respective destination counterparts but have distinct instruction bytes
 * from each other, so exact-bytes correlators can match each pair without cross-matching.
 */
public class DiffStagedCorrelationIntegrationTest extends RevaIntegrationTestBase {

    /** Unique sequence to avoid name collisions across forked JVMs. */
    private static final java.util.concurrent.atomic.AtomicInteger SEQ =
        new java.util.concurrent.atomic.AtomicInteger();

    private static String unique(String base) {
        return base + "_scope_" + SEQ.incrementAndGet();
    }

    // alpha_fn body: xor eax,eax ; ret  (31 C0 C3)
    private static final byte[] ALPHA_BODY = {0x31, (byte) 0xC0, (byte) 0xC3};
    // beta_fn body:  inc eax ; ret  (40 C3) — distinct from ALPHA
    private static final byte[] BETA_BODY  = {0x40, (byte) 0xC3};

    private static final String ALPHA_ADDR = "0x02001000";
    private static final String BETA_ADDR  = "0x02002000";

    /**
     * Build a source program with two named functions (alpha_fn, beta_fn) in their own memory.
     */
    private Program buildScopeSource() throws Exception {
        ProgramBuilder b = new ProgramBuilder(unique("scope_src"), ProgramBuilder._X86, this);
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
     * Build a destination program with two unnamed functions at the same addresses and with the
     * same instruction bytes as the source, so they can be exactly matched by content.
     */
    private Program buildScopeDest() throws Exception {
        ProgramBuilder b = new ProgramBuilder(unique("scope_dst"), ProgramBuilder._X86, this);
        b.createMemory("text", "0x02001000", 0x2000);
        b.setBytes(ALPHA_ADDR, ALPHA_BODY);
        b.disassemble(ALPHA_ADDR, ALPHA_BODY.length);
        b.createEmptyFunction(null, ALPHA_ADDR, ALPHA_BODY.length, null);
        b.setBytes(BETA_ADDR, BETA_BODY);
        b.disassemble(BETA_ADDR, BETA_BODY.length);
        b.createEmptyFunction(null, BETA_ADDR, BETA_BODY.length, null);
        return b.getProgram();
    }

    /**
     * Persist source and destination into the active project (VTSessionDB needs real file IDs).
     */
    private Program[] buildAndPersistScopePair() throws Exception {
        Program src = buildScopeSource();
        Program dst = buildScopeDest();
        DomainFolder root = AppInfo.getActiveProject().getProjectData().getRootFolder();
        root.createFile(src.getName(), src, TaskMonitor.DUMMY);
        root.createFile(dst.getName(), dst, TaskMonitor.DUMMY);
        return new Program[]{src, dst};
    }

    /** Register both programs with the MCP server so getValidatedProgram can find them. */
    private void register(Program src, Program dst) {
        ProgramManager pm = tool.getService(ProgramManager.class);
        env.open(src);
        env.open(dst);
        pm.openProgram(src);
        pm.openProgram(dst);
        serverManager.programOpened(src, tool);
        serverManager.programOpened(dst, tool);
    }

    @After
    public void tearDownDiffSessions() {
        DiffSessionManager.clearAll();
    }

    /**
     * Unscoped diff-create-session on the two-function fixture must return status="completed",
     * success=true, matched.identical >= 1, and a non-empty correlatorsRun.
     */
    @Test
    public void testStagedMatchesExpectedCounts() throws Exception {
        Program[] pair = buildAndPersistScopePair();
        Program src = pair[0];
        Program dst = pair[1];
        register(src, dst);
        try {
            Map<String, Object> args = new HashMap<>();
            args.put("sourceProgramPath", src.getDomainFile().getPathname());
            args.put("destinationProgramPath", dst.getDomainFile().getPathname());

            JsonNode r = parseJsonContent(callMcpTool("diff-create-session", args));

            assertEquals("completed", r.get("status").asText());
            assertTrue("success flag must be true", r.get("success").asBoolean());
            assertTrue("at least one identical match",
                r.get("matched").get("identical").asInt() >= 1);
            assertTrue("correlatorsRun must be non-empty", r.get("correlatorsRun").size() > 0);
        } finally {
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    /**
     * When sourceScope names only alpha_fn, the scoped correlation must match fewer source
     * functions than an unscoped run. Specifically, alpha_fn should be matched but beta_fn
     * should be unmatched (it is outside the scope and therefore not offered to the correlators).
     *
     * <p>Assertion: matched.identical with scope < matched.identical without scope.
     */
    @Test
    public void testSourceScopeRestrictsCorrelation() throws Exception {
        Program[] pair = buildAndPersistScopePair();
        Program src = pair[0];
        Program dst = pair[1];
        register(src, dst);
        try {
            String srcPath = src.getDomainFile().getPathname();
            String dstPath = dst.getDomainFile().getPathname();

            // 1) Unscoped run: both alpha_fn and beta_fn should match → identical >= 2.
            Map<String, Object> unscopedArgs = new HashMap<>();
            unscopedArgs.put("sourceProgramPath", srcPath);
            unscopedArgs.put("destinationProgramPath", dstPath);
            JsonNode unscoped = parseJsonContent(callMcpTool("diff-create-session", unscopedArgs));
            assertEquals("completed", unscoped.get("status").asText());
            int unscopedIdentical = unscoped.get("matched").get("identical").asInt();
            assertTrue("unscoped run should match both functions (>= 2)", unscopedIdentical >= 2);

            // Delete the session so the next create-session re-correlates from scratch.
            callMcpTool("diff-delete-session", unscopedArgs);

            // 2) Scoped run: only alpha_fn in sourceScope → fewer matches.
            Map<String, Object> scopedArgs = new HashMap<>(unscopedArgs);
            scopedArgs.put("force", true);
            scopedArgs.put("sourceScope", List.of("alpha_fn"));
            JsonNode scoped = parseJsonContent(callMcpTool("diff-create-session", scopedArgs));
            assertEquals("completed", scoped.get("status").asText());
            int scopedIdentical = scoped.get("matched").get("identical").asInt();

            assertTrue("scoped run must match fewer functions than unscoped",
                scopedIdentical < unscopedIdentical);
            // beta_fn is outside the scope and must not be matched.
            assertEquals("only alpha_fn should match (1 identical)", 1, scopedIdentical);
        } finally {
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    /**
     * Supplying an unresolvable identifier in sourceScope must produce a synchronous error
     * response (before any job is started) that names the bad identifier.
     */
    @Test
    public void testBadScopeIdentifierErrors() throws Exception {
        Program[] pair = buildAndPersistScopePair();
        Program src = pair[0];
        Program dst = pair[1];
        register(src, dst);
        try {
            String srcPath = src.getDomainFile().getPathname();
            String dstPath = dst.getDomainFile().getPathname();

            Map<String, Object> args = new HashMap<>();
            args.put("sourceProgramPath", srcPath);
            args.put("destinationProgramPath", dstPath);
            args.put("sourceScope", List.of("no_such_function_xyz"));

            verifyMcpToolFailsWithError("diff-create-session", args, "no_such_function_xyz");
        } finally {
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }
}
