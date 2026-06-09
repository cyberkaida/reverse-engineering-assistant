package reva.tools.diff;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.app.services.ProgramManager;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import reva.RevaIntegrationTestBase;
import reva.util.VersionTrackingUtil;
import reva.util.VersionTrackingUtil.MatchInfo;

public class DiffToolProviderIntegrationTest extends RevaIntegrationTestBase {

    @Test
    public void testCorrelationMatchesIdenticalFunctionAndDetectsRemovedFunction() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        try {
            VTSession session = new VTSessionDB("test", src, dst, this);
            try {
                VersionTrackingUtil.runCorrelators(session, src, dst,
                    VersionTrackingUtil.defaultCorrelatorSequence(), TaskMonitor.DUMMY);

                List<MatchInfo> matches = VersionTrackingUtil.collectFunctionMatches(session);
                Set<Address> matchedSrc = new HashSet<>();
                for (MatchInfo mi : matches) matchedSrc.add(mi.sourceAddress);

                // identical_fn must match by exact bytes
                Address identicalSrc = src.getAddressFactory().getAddress(DiffTestPrograms.IDENTICAL_FN);
                assertTrue("identical_fn should be matched", matchedSrc.contains(identicalSrc));

                // removed_fn (source only) must be unmatched in source
                List<ghidra.program.model.listing.Function> removed =
                    VersionTrackingUtil.unmatchedFunctions(src, matchedSrc);
                boolean sawRemoved = removed.stream()
                    .anyMatch(f -> f.getName().equals("removed_fn"));
                assertTrue("removed_fn should be unmatched in source", sawRemoved);
            } finally {
                session.release(this);
            }
        } finally {
            src.release(this);
            dst.release(this);
        }
    }

    /**
     * 1:1 assignment invariant. The fan-out fixtures inject a source function byte-identical
     * to TWO destinations (group X) and a destination byte-identical to TWO sources (group Y).
     * {@code collectFunctionMatches} must collapse the fan-out: no source address and no
     * destination address may appear more than once across the (changed+identical) matched
     * rows, and the duplicated functions must yield exactly one matched row each.
     */
    @Test
    public void testCollectFunctionMatchesIsOneToOne() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        try {
            VTSession session = new VTSessionDB("test", src, dst, this);
            try {
                VersionTrackingUtil.runCorrelators(session, src, dst,
                    VersionTrackingUtil.defaultCorrelatorSequence(), TaskMonitor.DUMMY);

                // Guard against a vacuous test: the fixture must ACTUALLY fan out at the raw
                // (pre-dedup) VT level, or the "== 1" assertions below would hold trivially.
                Address fanxSrcRaw = src.getAddressFactory().getAddress(DiffTestPrograms.FANX_SRC);
                Address fanyDstRaw = dst.getAddressFactory().getAddress(DiffTestPrograms.FANY_DST);
                int rawFanxSrc = 0, rawFanyDst = 0;
                for (ghidra.feature.vt.api.main.VTMatchSet ms : session.getMatchSets())
                    for (ghidra.feature.vt.api.main.VTMatch m : ms.getMatches()) {
                        if (m.getAssociation().getType()
                                != ghidra.feature.vt.api.main.VTAssociationType.FUNCTION) continue;
                        if (m.getAssociation().getSourceAddress().equals(fanxSrcRaw)) rawFanxSrc++;
                        if (m.getAssociation().getDestinationAddress().equals(fanyDstRaw)) rawFanyDst++;
                    }
                assertTrue("fixture must actually fan out: source has >= 2 raw candidates",
                    rawFanxSrc >= 2);
                assertTrue("fixture must actually fan out: dest has >= 2 raw candidates",
                    rawFanyDst >= 2);

                List<MatchInfo> matches = VersionTrackingUtil.collectFunctionMatches(session);

                // No source or destination address may be used twice (the core 1:1 invariant).
                Set<Address> seenSrc = new HashSet<>();
                Set<Address> seenDst = new HashSet<>();
                for (MatchInfo mi : matches) {
                    assertTrue("source address " + mi.sourceAddress + " used more than once",
                        seenSrc.add(mi.sourceAddress));
                    assertTrue("destination address " + mi.destinationAddress + " used more than once",
                        seenDst.add(mi.destinationAddress));
                }

                // Group X: the single source byte-identical to two dests yields exactly ONE row.
                Address fanxSrc = src.getAddressFactory().getAddress(DiffTestPrograms.FANX_SRC);
                long fanxSrcRows = matches.stream().filter(m -> m.sourceAddress.equals(fanxSrc)).count();
                assertEquals("fan-out source must match exactly one destination", 1, fanxSrcRows);

                // Group Y: the single dest byte-identical to two sources yields exactly ONE row.
                Address fanyDst = dst.getAddressFactory().getAddress(DiffTestPrograms.FANY_DST);
                long fanyDstRows = matches.stream().filter(m -> m.destinationAddress.equals(fanyDst)).count();
                assertEquals("fan-out destination must be matched by exactly one source", 1, fanyDstRows);
            } finally {
                session.release(this);
            }
        } finally {
            src.release(this);
            dst.release(this);
        }
    }

    @Test
    public void testSessionManagerCachesByPathPair() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        try {
            DiffSession a = DiffSessionManager.getOrCreate(src, dst,
                VersionTrackingUtil.defaultCorrelatorSequence(), false, TaskMonitor.DUMMY);
            DiffSession b = DiffSessionManager.getOrCreate(src, dst,
                VersionTrackingUtil.defaultCorrelatorSequence(), false, TaskMonitor.DUMMY);
            assertSame("second getOrCreate should return cached instance", a, b);
            assertFalse("correlators should have run", a.correlatorsRun.isEmpty());
        } finally {
            DiffSessionManager.clearAll();
            src.release(this);
            dst.release(this);
        }
    }

    @Test
    public void testCreateSessionReturnsCounts() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ProgramManager pm = tool.getService(ProgramManager.class);
        // Make both programs resolvable by getValidatedProgram (path lookup via RevaProgramManager)
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

            String content = callMcpTool("diff-create-session", args);
            JsonNode json = parseJsonContent(content);

            assertTrue(json.get("success").asBoolean());
            assertTrue("at least one identical match",
                json.get("matched").get("identical").asInt() >= 1);
            assertTrue("at least one removed function",
                json.get("unmatchedInSource").asInt() >= 1);
            assertTrue("at least one added function",
                json.get("unmatchedInDestination").asInt() >= 1);
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    @Test
    public void testListFunctionsRemovedCategory() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ghidra.app.services.ProgramManager pm = tool.getService(ghidra.app.services.ProgramManager.class);
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
            callMcpTool("diff-create-session", args);

            args.put("category", "removed");
            com.fasterxml.jackson.databind.JsonNode json =
                parseJsonContent(callMcpTool("diff-list-functions", args));
            boolean sawRemoved = false;
            for (com.fasterxml.jackson.databind.JsonNode row : json.get("functions"))
                if ("removed_fn".equals(row.path("name").asText())) sawRemoved = true;
            assertTrue("removed_fn should appear in removed category", sawRemoved);
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    @Test
    public void testFunctionDiffOnMatchedPair() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ghidra.app.services.ProgramManager pm = tool.getService(ghidra.app.services.ProgramManager.class);
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
            callMcpTool("diff-create-session", args);

            args.put("function", "identical_fn");
            com.fasterxml.jackson.databind.JsonNode json =
                parseJsonContent(callMcpTool("diff-function", args));
            assertTrue("diff-function should succeed", json.get("success").asBoolean());
            assertEquals("identical_fn", json.get("sourceName").asText());
            assertTrue("diff structure present", json.get("diff").has("hasChanges"));
            // Source fn is named identical_fn, dest is FUN_* (unnamed) → decompiled signatures
            // differ, so a change IS detected.
            assertTrue("decompiler diff detects the signature difference",
                json.get("diff").get("hasChanges").asBoolean());
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    @Test
    public void testFunctionDiffOnUnmatchedFunctionErrors() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ghidra.app.services.ProgramManager pm = tool.getService(ghidra.app.services.ProgramManager.class);
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
            callMcpTool("diff-create-session", args);

            // added_fn exists only in the destination → no matched pair → tool must error.
            args.put("function", "added_fn");
            verifyMcpToolFailsWithError("diff-function", args, "No matched function pair");
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    @Test
    public void testSummaryReturnsCountsAndMostChangedArray() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ghidra.app.services.ProgramManager pm = tool.getService(ghidra.app.services.ProgramManager.class);
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
            callMcpTool("diff-create-session", args);

            com.fasterxml.jackson.databind.JsonNode json =
                parseJsonContent(callMcpTool("diff-summary", args));
            assertTrue(json.get("success").asBoolean());
            assertTrue("mostChanged present and array", json.get("mostChanged").isArray());
            // identical_fn matched at similarity 1.0 → at least one identical match
            assertTrue(json.get("matched").get("identical").asInt() >= 1);
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    @Test
    public void testTransferMarkupRenamesDestinationFunction() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ghidra.app.services.ProgramManager pm = tool.getService(ghidra.app.services.ProgramManager.class);
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
            callMcpTool("diff-create-session", args);

            ghidra.program.model.address.Address destIdentical =
                dst.getAddressFactory().getAddress(DiffTestPrograms.IDENTICAL_FN);
            String before = dst.getFunctionManager().getFunctionAt(destIdentical).getName();
            assertNotEquals("identical_fn", before); // dest starts as FUN_*

            com.fasterxml.jackson.databind.JsonNode json =
                parseJsonContent(callMcpTool("diff-transfer-markup", args));
            assertTrue(json.get("success").asBoolean());
            assertTrue("at least one match applied", json.get("appliedCount").asInt() >= 1);

            // ACTUAL program state change: dest identical_fn now carries the source name.
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

    @Test
    public void testApplyMatchAppliesExactlyOne() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ghidra.app.services.ProgramManager pm = tool.getService(ghidra.app.services.ProgramManager.class);
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
            callMcpTool("diff-create-session", args);

            Map<String, Object> applyArgs = new HashMap<>(args);
            applyArgs.put("sourceAddress", DiffTestPrograms.IDENTICAL_FN);
            applyArgs.put("destinationAddress", DiffTestPrograms.IDENTICAL_FN);
            com.fasterxml.jackson.databind.JsonNode json =
                parseJsonContent(callMcpTool("diff-apply-match", applyArgs));
            assertTrue(json.get("success").asBoolean());

            ghidra.program.model.address.Address destIdentical =
                dst.getAddressFactory().getAddress(DiffTestPrograms.IDENTICAL_FN);
            assertEquals("identical_fn",
                dst.getFunctionManager().getFunctionAt(destIdentical).getName());
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    @Test
    public void testListAndDeleteSession() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ghidra.app.services.ProgramManager pm = tool.getService(ghidra.app.services.ProgramManager.class);
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
            callMcpTool("diff-create-session", args);

            JsonNode listed = parseJsonContent(callMcpTool("diff-list-sessions", new HashMap<>()));
            assertTrue(listed.get("sessions").size() >= 1);

            JsonNode del = parseJsonContent(callMcpTool("diff-delete-session", args));
            assertTrue(del.get("deleted").asBoolean());
            // Do NOT assert the list is exactly 0 afterward — other tests share the static
            // cache in this single JVM. Instead assert this specific pair is gone:
            JsonNode after = parseJsonContent(callMcpTool("diff-list-sessions", new HashMap<>()));
            boolean stillPresent = false;
            for (JsonNode s : after.get("sessions")) {
                if (s.get("sourceProgramPath").asText().equals(src.getDomainFile().getPathname())
                    && s.get("destinationProgramPath").asText().equals(dst.getDomainFile().getPathname())) {
                    stillPresent = true;
                }
            }
            assertFalse(stillPresent);
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    @Test
    public void testStringsDiffShowsChangedC2() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ghidra.app.services.ProgramManager pm = tool.getService(ghidra.app.services.ProgramManager.class);
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
            callMcpTool("diff-create-session", args);

            com.fasterxml.jackson.databind.JsonNode json =
                parseJsonContent(callMcpTool("diff-strings", args));
            boolean addedNew = false, removedOld = false;
            for (com.fasterxml.jackson.databind.JsonNode n : json.get("added"))
                if (n.get("value").asText().contains("new.example.org")) addedNew = true;
            for (com.fasterxml.jackson.databind.JsonNode n : json.get("removed"))
                if (n.get("value").asText().contains("old.example.com")) removedOld = true;
            assertTrue("new C2 string should be added", addedNew);
            assertTrue("old C2 string should be removed", removedOld);
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    /**
     * Regression for the relocation-only patch class (identical instruction
     * bytes, one swapped call target).
     * caller_fn is byte-identical across both programs so VT scores it 1.0, but its
     * callee was renamed sync_stop -> async_stop. It MUST surface as changed (not hide
     * in identical), and the row must name the callee swap.
     */
    @Test
    public void testCalleeNameChangeFlagsRelocationOnlyPatchAsChanged() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ghidra.app.services.ProgramManager pm = tool.getService(ghidra.app.services.ProgramManager.class);
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
            callMcpTool("diff-create-session", args);

            Map<String, Object> changedArgs = new HashMap<>(args);
            changedArgs.put("category", "changed");
            JsonNode changed = parseJsonContent(callMcpTool("diff-list-functions", changedArgs));
            JsonNode callerRow = null;
            for (JsonNode row : changed.get("functions")) {
                if ("caller_fn".equals(row.path("sourceName").asText())) callerRow = row;
            }
            assertNotNull("caller_fn (relocation-only change) must be in the changed category", callerRow);
            // VT still scores it identical — the reclassification is purely from the callee delta.
            assertEquals(1.0, callerRow.get("similarity").asDouble(), 0.0);
            JsonNode cc = callerRow.get("calleeChanges");
            assertTrue("callee swap to async_stop reported", cc.get("added").toString().contains("async_stop"));
            assertTrue("callee swap from sync_stop reported", cc.get("removed").toString().contains("sync_stop"));

            // It must NOT also appear in the identical category.
            Map<String, Object> identicalArgs = new HashMap<>(args);
            identicalArgs.put("category", "identical");
            JsonNode identical = parseJsonContent(callMcpTool("diff-list-functions", identicalArgs));
            for (JsonNode row : identical.get("functions"))
                assertNotEquals("caller_fn must not be classified identical",
                    "caller_fn", row.path("sourceName").asText());

            // And summary's changed count must include it (was 0 before this fix).
            JsonNode summary = parseJsonContent(callMcpTool("diff-summary", args));
            assertTrue("summary changed count includes the relocation-only patch",
                summary.get("matched").get("changed").asInt() >= 1);
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    /**
     * The agent can choose which VT correlators run (e.g. drop symbol-name to match by
     * structure). An explicit selection limits the correlators run, and changing the
     * selection re-correlates the pair rather than returning the cached session.
     */
    @Test
    public void testCorrelatorSelectionLimitsAndRerunsCorrelators() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ghidra.app.services.ProgramManager pm = tool.getService(ghidra.app.services.ProgramManager.class);
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

            // Only the exact-bytes correlator runs when explicitly selected.
            Map<String, Object> sel = new HashMap<>(args);
            sel.put("correlators", List.of("exact-bytes"));
            JsonNode one = parseJsonContent(callMcpTool("diff-create-session", sel));
            JsonNode ran = one.get("correlatorsRun");
            assertEquals(1, ran.size());
            assertEquals("Exact Function Bytes Match", ran.get(0).asText());

            // A different selection re-correlates (not the cached single-correlator session).
            Map<String, Object> sel2 = new HashMap<>(args);
            sel2.put("correlators", List.of("symbol-name", "function-reference"));
            JsonNode two = parseJsonContent(callMcpTool("diff-create-session", sel2));
            JsonNode ran2 = two.get("correlatorsRun");
            assertEquals(2, ran2.size());
            assertEquals("Exact Symbol Name Match", ran2.get(0).asText());
            assertEquals("Function Reference Match", ran2.get(1).asText());
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    /**
     * Size-delta is a default-on, address-independent signal: a name-matched function whose
     * body grew/shrank (resized_fn: 3 -> 5 bytes) is classified changed with changeType 'size'
     * and the reported sizeDelta, even though VT scores it 1.0 by symbol name.
     */
    @Test
    public void testSizeDeltaSurfacesResizedFunction() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ghidra.app.services.ProgramManager pm = tool.getService(ghidra.app.services.ProgramManager.class);
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
            callMcpTool("diff-create-session", args);

            Map<String, Object> changedArgs = new HashMap<>(args);
            changedArgs.put("category", "changed");
            JsonNode changed = parseJsonContent(callMcpTool("diff-list-functions", changedArgs));
            JsonNode row = null;
            for (JsonNode r : changed.get("functions"))
                if ("resized_fn".equals(r.path("sourceName").asText())) row = r;
            assertNotNull("resized_fn must be classified changed via the size signal", row);
            assertEquals(2, row.get("sizeDelta").asInt());
            assertTrue("changeTypes includes 'size'",
                row.get("changeTypes").toString().contains("size"));
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    /**
     * Operand-only change (tweaked_fn: add eax,5 -> add eax,6) is invisible to VT (same name,
     * size, mnemonics, callees -> similarity 1.0). It stays out of the DEFAULT changed set but
     * surfaces with changeType 'body-bytes' the moment the agent enables the recall knob. This
     * is the precision-by-default / agent-controlled-recall contract.
     */
    @Test
    public void testBodyBytesRecallToggleSurfacesOperandChange() throws Exception {
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ghidra.app.services.ProgramManager pm = tool.getService(ghidra.app.services.ProgramManager.class);
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
            callMcpTool("diff-create-session", args);

            // Default: tweaked_fn is NOT in the changed set (precision-first).
            Map<String, Object> def = new HashMap<>(args);
            def.put("category", "changed");
            JsonNode defChanged = parseJsonContent(callMcpTool("diff-list-functions", def));
            for (JsonNode r : defChanged.get("functions"))
                assertNotEquals("tweaked_fn must not be changed by default",
                    "tweaked_fn", r.path("sourceName").asText());

            // Recall knob ON: tweaked_fn surfaces with changeType 'body-bytes'.
            Map<String, Object> recall = new HashMap<>(args);
            recall.put("category", "changed");
            recall.put("includeBodyByteChanges", true);
            JsonNode recallChanged = parseJsonContent(callMcpTool("diff-list-functions", recall));
            JsonNode row = null;
            for (JsonNode r : recallChanged.get("functions"))
                if ("tweaked_fn".equals(r.path("sourceName").asText())) row = r;
            assertNotNull("tweaked_fn must surface under the body-bytes recall knob", row);
            assertEquals(0, row.get("sizeDelta").asInt());
            assertTrue("changeTypes includes 'body-bytes'",
                row.get("changeTypes").toString().contains("body-bytes"));
            assertTrue("bodyBytesChanged flag set", row.get("bodyBytesChanged").asBoolean());
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }

    /**
     * When the precision lenses find nothing changed and the body-bytes recall knob is off,
     * diff-summary must surface a 'hint' field pointing at includeBodyByteChanges so the agent
     * doesn't conclude "no changes." The hint must be absent when the knob is on, and absent
     * when there actually are changes. We diff two identical builds of the source program to
     * get changed==0 under the default lenses.
     */
    @Test
    public void testSummaryHintAppearsOnlyWhenChangedZeroAndRecallOff() throws Exception {
        // Two independently-built copies of the SAME source program: unique paths, identical
        // content, so every function matches 1:1 identical under the default lenses (changed==0).
        Program a = DiffTestPrograms.buildSource(this);
        Program b = DiffTestPrograms.buildSource(this);
        // And the genuine source/dest pair, which has real changes (changed>0).
        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ghidra.app.services.ProgramManager pm = tool.getService(ghidra.app.services.ProgramManager.class);
        for (Program p : new Program[]{a, b, src, dst}) {
            env.open(p);
            pm.openProgram(p);
            serverManager.programOpened(p, tool);
        }
        try {
            Map<String, Object> identicalArgs = new HashMap<>();
            identicalArgs.put("sourceProgramPath", a.getDomainFile().getPathname());
            identicalArgs.put("destinationProgramPath", b.getDomainFile().getPathname());
            callMcpTool("diff-create-session", identicalArgs);

            // (a) Identical pair, recall OFF → changed==0 → hint present.
            JsonNode noKnob = parseJsonContent(callMcpTool("diff-summary", identicalArgs));
            assertEquals("identical pair has 0 changed", 0,
                noKnob.get("matched").get("changed").asInt());
            assertTrue("hint present when changed==0 and recall off", noKnob.has("hint"));
            assertTrue("hint mentions includeBodyByteChanges",
                noKnob.get("hint").asText().contains("includeBodyByteChanges"));

            // (b) Identical pair, recall ON → hint absent (the knob is already engaged).
            Map<String, Object> withKnob = new HashMap<>(identicalArgs);
            withKnob.put("includeBodyByteChanges", true);
            JsonNode knobOn = parseJsonContent(callMcpTool("diff-summary", withKnob));
            assertFalse("hint absent when recall knob is on", knobOn.has("hint"));

            // (c) Real source/dest pair (changed>0), recall OFF → hint absent.
            Map<String, Object> changedArgs = new HashMap<>();
            changedArgs.put("sourceProgramPath", src.getDomainFile().getPathname());
            changedArgs.put("destinationProgramPath", dst.getDomainFile().getPathname());
            callMcpTool("diff-create-session", changedArgs);
            JsonNode changedSummary = parseJsonContent(callMcpTool("diff-summary", changedArgs));
            assertTrue("real pair has changes", changedSummary.get("matched").get("changed").asInt() > 0);
            assertFalse("hint absent when changed>0", changedSummary.has("hint"));
        } finally {
            DiffSessionManager.clearAll();
            for (Program p : new Program[]{a, b, src, dst}) {
                serverManager.programClosed(p, tool);
                p.release(this);
            }
        }
    }

    /**
     * The opt-in 'combined-reference' correlator is selectable (but not default). It must
     * resolve to a non-null factory, and a session created with it in the selection must run it
     * and report it in correlatorsRun.
     */
    @Test
    public void testCombinedReferenceCorrelatorIsSelectable() throws Exception {
        // Pure factory resolution: non-null, no throw.
        assertNotNull("combined-reference must resolve to a factory",
            VersionTrackingUtil.correlatorForKey("combined-reference"));

        Program src = DiffTestPrograms.buildSource(this);
        Program dst = DiffTestPrograms.buildDestination(this);
        ghidra.app.services.ProgramManager pm = tool.getService(ghidra.app.services.ProgramManager.class);
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
            args.put("correlators", List.of("symbol-name", "combined-reference"));

            JsonNode json = parseJsonContent(callMcpTool("diff-create-session", args));
            assertTrue(json.get("success").asBoolean());
            JsonNode ran = json.get("correlatorsRun");
            assertEquals(2, ran.size());
            boolean sawCombined = false;
            for (JsonNode n : ran)
                if ("Combined Function and Data Reference Match".equals(n.asText())) sawCombined = true;
            assertTrue("combined-reference must appear in correlatorsRun", sawCombined);
        } finally {
            DiffSessionManager.clearAll();
            serverManager.programClosed(src, tool);
            serverManager.programClosed(dst, tool);
            src.release(this);
            dst.release(this);
        }
    }
}
