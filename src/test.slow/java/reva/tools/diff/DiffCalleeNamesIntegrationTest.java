package reva.tools.diff;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.app.services.ProgramManager;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import reva.RevaIntegrationTestBase;
import reva.util.VersionTrackingUtil;

/**
 * Regression test: {@link VersionTrackingUtil#calleeNames} must silently skip callees whose name
 * is a Ghidra auto-generated placeholder ({@code FUN_<addr>}). On fully-linked images the same
 * caller function can reference an unnamed callee at two DIFFERENT addresses across two builds;
 * including those address-derived names would fire the callee-change lens on pure relocation noise.
 *
 * <p>Fixture layout (X86 programs):
 * <ul>
 *   <li>{@code anchor_fn} at 0x01001000 — same bytes+name in both → symbol-name correlator pairs
 *       it, confirming the VT session is non-degenerate.</li>
 *   <li>{@code caller_fn} at 0x01001100 in both programs — calls an UNNAMED callee, but at
 *       different addresses per program (0x01001110 in source, 0x01001120 in dest). The call
 *       displacement therefore differs between programs, so body bytes differ; however the callee
 *       name in each case is a default FUN_* placeholder and must be filtered.
 *       <ul>
 *         <li>Size lens: both caller_fn bodies are 6 bytes (E8 rel32 + C3) → no fire.</li>
 *         <li>Callee lens: calleeNames returns empty on both sides → no delta → no fire.</li>
 *         <li>Body-bytes lens: bytes differ, but that lens is OPT-IN (off by default) → no fire.</li>
 *       </ul>
 *       With the filter in place caller_fn must NOT appear in the default "changed" category.</li>
 * </ul>
 */
public class DiffCalleeNamesIntegrationTest extends RevaIntegrationTestBase {

    // --- address constants ---
    private static final String ANCHOR_ADDR    = "0x01001000"; // named anchor, same both sides
    private static final String CALLER_ADDR    = "0x01001100"; // caller_fn, same address both sides
    // Unnamed callee addresses — DIFFERENT per program so FUN_ names differ.
    private static final String CALLEE_SRC     = "0x01001110";
    private static final String CALLEE_DST     = "0x01001120";

    // anchor_fn body: xor eax,eax ; ret  (3 bytes — unique mnemonics, exact-match bait)
    private static final byte[] ANCHOR_BODY = {0x31, (byte) 0xC0, (byte) 0xC3};

    // caller_fn body: call rel32 ; ret  (6 bytes each, displacement differs per program)
    // Source: callee at 0x01001110, caller at 0x01001100 → rel32 = 0x01001110 − 0x01001105 = 0x0B
    private static final byte[] CALLER_BODY_SRC = {
        (byte) 0xE8, 0x0B, 0x00, 0x00, 0x00, (byte) 0xC3
    };
    // Dest: callee at 0x01001120, caller at 0x01001100 → rel32 = 0x01001120 − 0x01001105 = 0x1B
    private static final byte[] CALLER_BODY_DST = {
        (byte) 0xE8, 0x1B, 0x00, 0x00, 0x00, (byte) 0xC3
    };

    // unnamed callee body: ret (1 byte)
    private static final byte[] CALLEE_BODY = {(byte) 0xC3};

    /** Build the source program. */
    private Program buildSource() throws Exception {
        ProgramBuilder b = new ProgramBuilder("callee_filter_src", ProgramBuilder._X86, this);
        b.createMemory("text", "0x01001000", 0x200);
        // anchor: named, exact-match bait for the symbol-name correlator
        b.setBytes(ANCHOR_ADDR, ANCHOR_BODY);
        b.disassemble(ANCHOR_ADDR, ANCHOR_BODY.length);
        b.createEmptyFunction("anchor_fn", ANCHOR_ADDR, ANCHOR_BODY.length, null);
        // Set up the UNNAMED callee FIRST (bytes + function entry), THEN disassemble the
        // caller. This ordering prevents ProgramBuilder's disassembler from following the
        // call target and auto-creating a conflicting namespace entry at the callee address.
        b.setBytes(CALLEE_SRC, CALLEE_BODY);
        b.disassemble(CALLEE_SRC, CALLEE_BODY.length);
        b.createEmptyFunction(null, CALLEE_SRC, CALLEE_BODY.length, null);
        // caller_fn: calls the unnamed callee — displaced bytes differ from dest
        b.setBytes(CALLER_ADDR, CALLER_BODY_SRC);
        b.disassemble(CALLER_ADDR, CALLER_BODY_SRC.length);
        b.createEmptyFunction("caller_fn", CALLER_ADDR, CALLER_BODY_SRC.length, null);
        b.createMemoryCallReference(CALLER_ADDR, CALLEE_SRC);
        return b.getProgram();
    }

    /** Build the destination program. */
    private Program buildDest() throws Exception {
        ProgramBuilder b = new ProgramBuilder("callee_filter_dst", ProgramBuilder._X86, this);
        b.createMemory("text", "0x01001000", 0x200);
        // anchor: same name+bytes as source → symbol-name correlator pairs it
        b.setBytes(ANCHOR_ADDR, ANCHOR_BODY);
        b.disassemble(ANCHOR_ADDR, ANCHOR_BODY.length);
        b.createEmptyFunction("anchor_fn", ANCHOR_ADDR, ANCHOR_BODY.length, null);
        // Unnamed callee at a DIFFERENT address → different FUN_* name than source's callee.
        // Created before caller disassembly (same reason as buildSource).
        b.setBytes(CALLEE_DST, CALLEE_BODY);
        b.disassemble(CALLEE_DST, CALLEE_BODY.length);
        b.createEmptyFunction(null, CALLEE_DST, CALLEE_BODY.length, null);
        // caller_fn: SAME name, DIFFERENT displacement (callee moved), SAME size as source
        b.setBytes(CALLER_ADDR, CALLER_BODY_DST);
        b.disassemble(CALLER_ADDR, CALLER_BODY_DST.length);
        b.createEmptyFunction("caller_fn", CALLER_ADDR, CALLER_BODY_DST.length, null);
        b.createMemoryCallReference(CALLER_ADDR, CALLEE_DST);
        return b.getProgram();
    }

    /**
     * Direct assertion: calleeNames for a function whose only callee is unnamed must return
     * an empty set. This is the narrow proof that the filter is responsible.
     */
    @Test
    public void testCalleeNamesFiltersDefaultNamedCallee() throws Exception {
        Program src = buildSource();
        try {
            Address callerAddr = src.getAddressFactory().getAddress(CALLER_ADDR);
            Set<String> names = VersionTrackingUtil.calleeNames(src, callerAddr, TaskMonitor.DUMMY);
            assertTrue(
                "calleeNames must return empty when the only callee is default-named (FUN_*); got: " + names,
                names.isEmpty());
        } finally {
            src.release(this);
        }
    }

    /**
     * End-to-end via MCP: caller_fn (only default-named callee, body-bytes differ) must NOT
     * appear in the default "changed" category. The callee lens fires only on *named* callee
     * swaps; the body-bytes lens is off by default. Assertions also guard against the vacuous
     * case where caller_fn was never matched at all.
     */
    @Test
    public void testDefaultNamedCalleeDoesNotTriggerCalleeLens() throws Exception {
        Program src = buildSource();
        Program dst = buildDest();
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
            // Use symbol-name + exact-bytes correlators: symbol-name pairs anchor_fn and
            // caller_fn by name; exact-bytes pairs anchor_fn by content.
            args.put("correlators", List.of("symbol-name", "exact-bytes"));
            callMcpTool("diff-create-session", args);

            // 1. Positive match guard: caller_fn must have been matched (not listed as removed).
            //    diff-list-functions does not accept `correlators` — strip it from the inherited
            //    map so MCP SDK 2.0 schema validation (additionalProperties=false) doesn't reject.
            Map<String, Object> removedArgs = new HashMap<>(args);
            removedArgs.remove("correlators");
            removedArgs.put("category", "removed");
            JsonNode removed = parseJsonContent(callMcpTool("diff-list-functions", removedArgs));
            for (JsonNode row : removed.get("functions")) {
                assertNotEquals(
                    "caller_fn must be matched (not listed as removed — VT symbol-name pairing)",
                    "caller_fn", row.path("name").asText());
            }

            // 2. Core assertion: caller_fn must NOT be in the default changed category.
            //    The only difference across programs is (a) a shifted FUN_* callee (now filtered)
            //    and (b) a different call displacement (body-bytes, opt-in off by default).
            Map<String, Object> changedArgs = new HashMap<>(args);
            changedArgs.remove("correlators");
            changedArgs.put("category", "changed");
            JsonNode changed = parseJsonContent(callMcpTool("diff-list-functions", changedArgs));
            for (JsonNode row : changed.get("functions")) {
                assertNotEquals(
                    "caller_fn must NOT appear in changed when its only callee difference is a "
                        + "default-named (FUN_*) callee at a shifted address",
                    "caller_fn", row.path("sourceName").asText());
            }
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    // -------------------------------------------------------------------------
    // Thunk-resolution tests — addresses outside the existing 0x01001000–0x01001120 range
    // -------------------------------------------------------------------------

    // Layout (addresses chosen to avoid collision with existing fixtures):
    //   0x01001200 — unnamed target function (DEFAULT name → FUN_01001200)
    //   0x01001210 — thunk function pointing at target (DEFAULT name → thunk_FUN_01001200)
    //   0x01001220 — thunk_caller_fn: calls the thunk at 0x01001210

    private static final String THUNK_TARGET_ADDR  = "0x01001200";
    private static final String THUNK_FN_ADDR      = "0x01001210";
    private static final String THUNK_CALLER_ADDR  = "0x01001220";

    // thunk body: jmp rel32 (FF 25 is indirect; use E9 rel32 for a direct jmp thunk — 5 bytes)
    // rel32 from 0x01001210+5 → 0x01001200: delta = -0x11 → 0xFFFFFFEF
    // Actually simpler: just use "ret" — ProgramBuilder sets up the thunk record via API,
    // so the bytes don't need to be architecturally correct for the thunk property to work.
    private static final byte[] THUNK_TARGET_BODY = {(byte) 0xC3}; // ret
    private static final byte[] THUNK_FN_BODY     = {(byte) 0xC3}; // ret (thunk marked via API)
    // thunk_caller body: call rel32 → thunk at 0x01001210, then ret
    // caller at 0x01001220+5 → 0x01001210: rel32 = 0x01001210 − 0x01001225 = -0x15 → 0xFFFFFFEB
    private static final byte[] THUNK_CALLER_BODY = {
        (byte) 0xE8, (byte) 0xEB, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xC3
    };

    /**
     * Build a program with an unnamed target, a thunk pointing at it, and a caller that calls
     * the thunk. Uses addresses in the 0x01001200–0x0100122F range (no overlap with existing
     * fixtures). The memory block must be large enough (0x300 bytes) to cover these addresses.
     *
     * @param programName name for ProgramBuilder
     * @param calleeIsNamed if true, rename the target to "real_target" before returning
     */
    private Program buildThunkProgram(String programName, boolean calleeIsNamed) throws Exception {
        ProgramBuilder b = new ProgramBuilder(programName, ProgramBuilder._X86, this);
        b.createMemory("text", "0x01001000", 0x300);

        // Unnamed target function
        b.setBytes(THUNK_TARGET_ADDR, THUNK_TARGET_BODY);
        b.disassemble(THUNK_TARGET_ADDR, THUNK_TARGET_BODY.length);
        b.createEmptyFunction(null, THUNK_TARGET_ADDR, THUNK_TARGET_BODY.length, null);

        // Thunk function — created with null name so Ghidra auto-generates "thunk_FUN_*"
        b.setBytes(THUNK_FN_ADDR, THUNK_FN_BODY);
        b.disassemble(THUNK_FN_ADDR, THUNK_FN_BODY.length);
        b.createEmptyFunction(null, THUNK_FN_ADDR, THUNK_FN_BODY.length, null);

        Program prog = b.getProgram();
        Address targetAddr = prog.getAddressFactory().getAddress(THUNK_TARGET_ADDR);
        Address thunkAddr  = prog.getAddressFactory().getAddress(THUNK_FN_ADDR);
        Function targetFn  = prog.getFunctionManager().getFunctionAt(targetAddr);
        Function thunkFn   = prog.getFunctionManager().getFunctionAt(thunkAddr);

        // Wire up the thunk record so isThunk() returns true
        int tx = prog.startTransaction("make thunk");
        try {
            thunkFn.setThunkedFunction(targetFn);
            if (calleeIsNamed) {
                targetFn.setName("real_target", SourceType.USER_DEFINED);
            }
        } finally {
            prog.endTransaction(tx, true);
        }

        // Verify the thunk was set up correctly before the test assertions
        assertTrue("thunkFn.isThunk() must be true after setThunkedFunction",
            thunkFn.isThunk());

        if (calleeIsNamed) {
            // When target has a user name, Ghidra returns the target name directly (not "thunk_real_target")
            assertEquals("thunk pointing at a named target must report target's name",
                "real_target", thunkFn.getName());
        } else {
            // Unnamed target → thunk name must be "thunk_FUN_<addr>"
            String thunkName = thunkFn.getName();
            assertTrue("thunk pointing at unnamed target must be named thunk_FUN_*; got: " + thunkName,
                thunkName.startsWith("thunk_FUN_"));
        }

        // Caller function that calls the thunk
        b.setBytes(THUNK_CALLER_ADDR, THUNK_CALLER_BODY);
        b.disassemble(THUNK_CALLER_ADDR, THUNK_CALLER_BODY.length);
        b.createEmptyFunction("thunk_caller_fn", THUNK_CALLER_ADDR, THUNK_CALLER_BODY.length, null);
        b.createMemoryCallReference(THUNK_CALLER_ADDR, THUNK_FN_ADDR);

        return prog;
    }

    /**
     * Negative case: a thunk-to-unnamed-function must be filtered from calleeNames.
     * Without the fix, calleeNames returns {"thunk_FUN_01001200"} because
     * {@code isDefaultSymbolName} does not recognise the "thunk_" prefix. With the fix,
     * the thunk is resolved to its target (FUN_01001200) which IS default-named, so the
     * result is empty.
     *
     * <p>This test MUST be RED on the unfixed code (calleeNames contains "thunk_FUN_*")
     * and GREEN after the fix.
     */
    @Test
    public void testCalleeNamesFiltersThunkToUnnamedFunction() throws Exception {
        Program prog = buildThunkProgram("thunk_unnamed_test", false);
        try {
            Address callerAddr = prog.getAddressFactory().getAddress(THUNK_CALLER_ADDR);
            Set<String> names = VersionTrackingUtil.calleeNames(prog, callerAddr, TaskMonitor.DUMMY);
            assertTrue(
                "calleeNames must return empty when the only callee is a thunk to an unnamed "
                    + "(FUN_*) function; got: " + names,
                names.isEmpty());
        } finally {
            prog.release(this);
        }
    }

    /**
     * Positive case: a thunk-to-named-function must contribute the target's real name to
     * calleeNames (not the thunk's own name, which Ghidra already sets to the target name
     * for DEFAULT thunks pointing at explicitly-named functions).
     *
     * <p>This test verifies the resolved-target name ("real_target") is present, rather than
     * whatever the thunk function's own reported name happens to be — confirming the fix
     * uses the resolved target and not the intermediate thunk.
     */
    @Test
    public void testCalleeNamesResolvesThunkToNamedTarget() throws Exception {
        Program prog = buildThunkProgram("thunk_named_test", true);
        try {
            Address callerAddr = prog.getAddressFactory().getAddress(THUNK_CALLER_ADDR);
            Set<String> names = VersionTrackingUtil.calleeNames(prog, callerAddr, TaskMonitor.DUMMY);
            assertTrue(
                "calleeNames must contain 'real_target' (the thunk's resolved target name); got: " + names,
                names.contains("real_target"));
            assertEquals(
                "calleeNames must contain exactly one name ('real_target'); got: " + names,
                1, names.size());
        } finally {
            prog.release(this);
        }
    }
}
