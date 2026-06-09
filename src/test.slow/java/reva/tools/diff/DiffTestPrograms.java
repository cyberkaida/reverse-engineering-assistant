package reva.tools.diff;

import java.nio.charset.StandardCharsets;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.Program;

/**
 * Builds a (source, destination) program pair with known, injected differences
 * for binary-diff integration tests. Both programs share identical bytes for
 * {@code identical_fn} so exact correlators match it; {@code changed_fn} differs.
 */
public class DiffTestPrograms {

    // Integration tests run in one JVM (forkEvery forks per class), and the shared
    // DiffSessionManager cache + RevaProgramManager path lookup key on the program
    // pathname. Give every built program a unique name so concurrent test methods
    // never collide on "/diff_source" / "/diff_dest".
    private static final java.util.concurrent.atomic.AtomicInteger SEQ =
        new java.util.concurrent.atomic.AtomicInteger();

    private static String unique(String base) {
        return base + "_" + SEQ.incrementAndGet();
    }

    // Function entry points (kept identical across both programs so exact-byte
    // / exact-instruction correlators can match by content, not address).
    public static final String IDENTICAL_FN = "0x01001000";
    public static final String CHANGED_FN   = "0x01002000";
    public static final String REMOVED_FN   = "0x01003000"; // source only
    public static final String ADDED_FN     = "0x01004000"; // destination only
    // Relocation-only patch reproduction: caller_fn has BYTE-IDENTICAL bodies in both
    // programs (same call instruction) but the callee at CALLEE_TARGET is named
    // differently per program — modelling a relocation-only patch where the callee is
    // renamed across versions. VT scores caller_fn 1.0 (identical), so only a callee-name
    // comparison reveals the change. See VersionTrackingUtil.calleeNames.
    public static final String CALLER_FN     = "0x01005000";
    public static final String CALLEE_TARGET = "0x01006000";
    public static final String CALLEE_NAME_SOURCE = "sync_stop";
    public static final String CALLEE_NAME_DEST   = "async_stop";
    // tweaked_fn: same name + same size + same (no) callees in both, but ONE operand byte
    // differs (add eax,5 vs add eax,6). VT scores it 1.0 (name match); only the opt-in
    // body-bytes recall signal surfaces it. Models an operand-only patch class.
    public static final String TWEAKED_FN = "0x01008000";
    // resized_fn: same name in both, but the body grew (size signal, default-on).
    public static final String RESIZED_FN = "0x01008100";
    // Fan-out fixtures for the 1:1-assignment invariant. All UNNAMED (FUN_*) so symbol-name
    // never pairs them; exact-bytes drives the fan-out. Group X (dec eax;ret = [DEC,RET]) has
    // ONE source byte-identical to TWO destinations → tests no-duplicate-SOURCE. Group Y
    // (neg eax;ret = [NEG,RET]) has TWO sources byte-identical to ONE destination → tests
    // no-duplicate-DEST. Mnemonic sequences are unique among the fixture so no cross-match.
    public static final String FANX_SRC   = "0x01008200"; // 1 source
    public static final String FANX_DST_A = "0x01008300"; // 2 destinations, byte-identical to FANX_SRC
    public static final String FANX_DST_B = "0x01008400";
    public static final String FANY_SRC_A = "0x01008500"; // 2 sources, byte-identical to FANY_DST
    public static final String FANY_SRC_B = "0x01008600";
    public static final String FANY_DST   = "0x01008700"; // 1 destination

    // identical_fn — same in BOTH programs, unique within each: xor eax,eax ; ret  (31 C0 C3)
    private static final byte[] IDENTICAL_BODY = {0x31, (byte) 0xC0, (byte) 0xC3};
    // removed_fn (source only): nop ; nop ; ret  (90 90 C3) — distinct mnemonics [NOP,NOP,RET]
    // so no correlator (bytes/instructions/mnemonics) can pair it with a destination function.
    private static final byte[] REMOVED_BODY   = {(byte) 0x90, (byte) 0x90, (byte) 0xC3};
    // added_fn (destination only): inc eax ; ret  (40 C3) — distinct mnemonics [INC,RET]
    // so no correlator can pair it with a source function.
    private static final byte[] ADDED_BODY     = {(byte) 0x40, (byte) 0xC3};
    // changed_fn in SOURCE: mov eax,2 ; ret  (B8 02 00 00 00 C3)
    private static final byte[] CHANGED_BODY_A = {(byte) 0xB8, 0x02, 0x00, 0x00, 0x00, (byte) 0xC3};
    // changed_fn in DEST: mov eax,1 ; ret  (B8 01 00 00 00 C3) — differs from source
    private static final byte[] CHANGED_BODY_B = {(byte) 0xB8, 0x01, 0x00, 0x00, 0x00, (byte) 0xC3};
    // caller_fn: call CALLEE_TARGET ; ret — identical bytes in BOTH programs.
    // E8 rel32 where rel32 = 0x01006000 - 0x01005005 = 0x0FFB, then C3.
    private static final byte[] CALLER_BODY   = {(byte) 0xE8, (byte) 0xFB, 0x0F, 0x00, 0x00, (byte) 0xC3};
    // callee target body: ret. Same bytes both programs; only the symbol NAME differs.
    private static final byte[] CALLEE_BODY    = {(byte) 0xC3};
    // tweaked_fn: add eax,5 ; ret (05 05 00 00 00 C3) vs add eax,6 ; ret (05 06 00 00 00 C3).
    // Same size, same mnemonics [ADD,RET] (unique among the fixture so no cross-match), one
    // operand byte differs. VT cannot see the difference; body-bytes recall can.
    private static final byte[] TWEAKED_BODY_A = {0x05, 0x05, 0x00, 0x00, 0x00, (byte) 0xC3};
    private static final byte[] TWEAKED_BODY_B = {0x05, 0x06, 0x00, 0x00, 0x00, (byte) 0xC3};
    // resized_fn: push eax;pop eax;ret (50 58 C3) vs push;push;pop;pop;ret (50 50 58 58 C3).
    // Distinct mnemonics from everything else; body grew by 2 bytes.
    private static final byte[] RESIZED_BODY_A = {0x50, 0x58, (byte) 0xC3};
    private static final byte[] RESIZED_BODY_B = {0x50, 0x50, 0x58, 0x58, (byte) 0xC3};
    // Fan group X: dec eax ; ret (48 C3) — mnemonics [DEC,RET], unique in the fixture.
    private static final byte[] FANX_BODY = {0x48, (byte) 0xC3};
    // Fan group Y: neg eax ; ret (F7 D8 C3) — mnemonics [NEG,RET], unique in the fixture.
    private static final byte[] FANY_BODY = {(byte) 0xF7, (byte) 0xD8, (byte) 0xC3};

    public static Program buildSource(Object consumer) throws Exception {
        ProgramBuilder b = new ProgramBuilder(unique("diff_source"), ProgramBuilder._X86, consumer);
        b.createMemory("text", "0x01001000", 0x8000);
        addFn(b, IDENTICAL_FN, IDENTICAL_BODY, "identical_fn");
        addFn(b, CHANGED_FN,   CHANGED_BODY_A, "changed_fn");
        addFn(b, REMOVED_FN,   REMOVED_BODY,   "removed_fn");
        addFn(b, CALLEE_TARGET, CALLEE_BODY,   CALLEE_NAME_SOURCE);
        addFn(b, CALLER_FN,     CALLER_BODY,   "caller_fn");
        b.createMemoryCallReference(CALLER_FN, CALLEE_TARGET);
        addFn(b, TWEAKED_FN,    TWEAKED_BODY_A, "tweaked_fn");
        addFn(b, RESIZED_FN,    RESIZED_BODY_A, "resized_fn");
        // Fan-out: 1 X-source (fans to 2 dests), 2 Y-sources (fan to 1 dest). All unnamed.
        addFn(b, FANX_SRC,   FANX_BODY, null);
        addFn(b, FANY_SRC_A, FANY_BODY, null);
        addFn(b, FANY_SRC_B, FANY_BODY, null);
        b.createString("0x01007000", "C2: old.example.com", StandardCharsets.US_ASCII, true,
            TerminatedStringDataType.dataType);
        return b.getProgram();
    }

    public static Program buildDestination(Object consumer) throws Exception {
        ProgramBuilder b = new ProgramBuilder(unique("diff_dest"), ProgramBuilder._X86, consumer);
        b.createMemory("text", "0x01001000", 0x8000);
        // identical_fn: same bytes, default (stripped) name FUN_* so markup transfer is observable
        addFn(b, IDENTICAL_FN, IDENTICAL_BODY, null);
        addFn(b, CHANGED_FN,   CHANGED_BODY_B, null);
        addFn(b, ADDED_FN,     ADDED_BODY,     "added_fn");
        // caller_fn: byte-identical to source's; callee renamed → relocation-only patch.
        addFn(b, CALLEE_TARGET, CALLEE_BODY,   CALLEE_NAME_DEST);
        addFn(b, CALLER_FN,     CALLER_BODY,   "caller_fn");
        b.createMemoryCallReference(CALLER_FN, CALLEE_TARGET);
        addFn(b, TWEAKED_FN,    TWEAKED_BODY_B, "tweaked_fn");
        addFn(b, RESIZED_FN,    RESIZED_BODY_B, "resized_fn");
        // Fan-out: 2 X-dests (fanned from 1 source), 1 Y-dest (fanned from 2 sources). All unnamed.
        addFn(b, FANX_DST_A, FANX_BODY, null);
        addFn(b, FANX_DST_B, FANX_BODY, null);
        addFn(b, FANY_DST,   FANY_BODY, null);
        b.createString("0x01007000", "C2: new.example.org", StandardCharsets.US_ASCII, true,
            TerminatedStringDataType.dataType);
        return b.getProgram();
    }

    private static void addFn(ProgramBuilder b, String entry, byte[] body, String name)
            throws Exception {
        b.setBytes(entry, body);
        b.disassemble(entry, body.length);
        b.createEmptyFunction(name, entry, body.length, null);
    }
}
