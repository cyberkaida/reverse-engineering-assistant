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
package reva.util;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Test;

import reva.util.DecompilationDiffUtil.DiffResult;

/**
 * Unit tests for {@link DecompilationDiffUtil}, focused on the address-shift
 * normalization used by per-function diffs of relocated (linked) images, where
 * the decompiler renames {@code LAB_<hex>}/{@code DAT_<hex>}/etc. on every load
 * address even though the underlying statement is unchanged.
 */
public class DecompilationDiffUtilTest {

    // ---- normalizeAddressTokens ----------------------------------------

    @Test
    public void testNormalizeCollapsesLabelRenames() {
        String a = "  if (param_1 == 0) goto LAB_00104a3c;";
        String b = "  if (param_1 == 0) goto LAB_00205b7d;";
        // Different addresses, identical logic -> normalized forms equal.
        assertEquals(DecompilationDiffUtil.normalizeAddressTokens(a),
                     DecompilationDiffUtil.normalizeAddressTokens(b));
    }

    @Test
    public void testNormalizeCollapsesDataAndFunRenames() {
        String a = "  iVar1 = FUN_00101230(DAT_00104000);";
        String b = "  iVar1 = FUN_00202340(DAT_00205000);";
        assertEquals(DecompilationDiffUtil.normalizeAddressTokens(a),
                     DecompilationDiffUtil.normalizeAddressTokens(b));
    }

    @Test
    public void testNormalizeMasksStringLabelAddressSuffix() {
        // s_<text>_<hex>: text preserved, trailing address masked.
        String a = "  puts(s_failed_00104abc);";
        String b = "  puts(s_failed_00205def);";
        assertEquals(DecompilationDiffUtil.normalizeAddressTokens(a),
                     DecompilationDiffUtil.normalizeAddressTokens(b));
    }

    @Test
    public void testNormalizeLeavesGenuineDifferenceIntact() {
        String a = "  iVar1 = FUN_00101230(DAT_00104000);";
        String b = "  iVar1 = FUN_00101230(DAT_00104000) + 1;";
        assertNotEquals(DecompilationDiffUtil.normalizeAddressTokens(a),
                        DecompilationDiffUtil.normalizeAddressTokens(b));
    }

    @Test
    public void testNormalizeMasksBareHexInWarningComment() {
        // Decompiler WARNING annotations carry shifting absolute addresses — masked.
        String a = "  /* WARNING: Removing unreachable block (ram,0x00113988) */";
        String b = "  /* WARNING: Removing unreachable block (ram,0x001139a8) */";
        assertEquals(DecompilationDiffUtil.normalizeAddressTokens(a),
                     DecompilationDiffUtil.normalizeAddressTokens(b));
    }

    @Test
    public void testNormalizeLeavesBareHexInCodeUntouched() {
        // CRITICAL: a real hex constant in code (e.g. a real bound check) must NOT be masked.
        String l = "  if ((uVar1 < 0x801) && (uVar2 < 0x801)) {";
        assertEquals(l, DecompilationDiffUtil.normalizeAddressTokens(l));
    }

    @Test
    public void testStructuralDiffIgnoresWarningCommentAddressShift() {
        String before = "/* WARNING: Removing unreachable block (ram,0x00113988) */\nvoid f(void)\n{\n  return;\n}";
        String after  = "/* WARNING: Removing unreachable block (ram,0x001139a8) */\nvoid f(void)\n{\n  return;\n}";
        DiffResult d = DecompilationDiffUtil.createDiff(before, after, 2, true, false);
        assertFalse("a WARNING-comment-only address shift is not a real change", d.hasChanges());
    }

    @Test
    public void testNormalizeDoesNotTouchStableStackVars() {
        // Frame-offset names like local_18 / auStack_28 are stable across loads
        // (short, non-address) and must NOT be masked.
        String line = "  local_18 = auStack_28 + 4;";
        assertEquals(line, DecompilationDiffUtil.normalizeAddressTokens(line));
    }

    // ---- createDiff with normalization ---------------------------------

    private static final String BEFORE =
        "void caller(void)\n" +
        "{\n" +
        "  if (cond == 0) goto LAB_00104a3c;\n" +
        "  log(DAT_00104100);\n" +
        "  result = compute(x);\n" +
        "  return;\n" +
        "}";

    // Same function relocated: every LAB_/DAT_ address shifts, AND one real
    // edit (compute(x) -> compute(x, y)). Only the real edit should survive.
    private static final String AFTER =
        "void caller(void)\n" +
        "{\n" +
        "  if (cond == 0) goto LAB_00205b7d;\n" +
        "  log(DAT_00205200);\n" +
        "  result = compute(x, y);\n" +
        "  return;\n" +
        "}";

    @Test
    public void testNormalizedDiffHidesRelocationKeepsRealEdit() {
        DiffResult diff = DecompilationDiffUtil.createDiff(BEFORE, AFTER, 2, true);
        assertTrue("real edit must register as a change", diff.hasChanges());
        assertEquals("only the genuine edit should remain after masking shifts",
                     1, diff.getChangedLines().size());
        String changed = diff.getChangedLines().get(0).getAfterContent();
        assertTrue("the surviving change must be the real edit, not a relocation",
                   changed.contains("compute(x, y)"));
    }

    @Test
    public void testUnnormalizedDiffCountsEveryRelocation() {
        // Default (flag off) behavior is unchanged: every shifted line counts.
        DiffResult diff = DecompilationDiffUtil.createDiff(BEFORE, AFTER, 2, false);
        assertEquals("LAB_ line + DAT_ line + real edit all count when not normalizing",
                     3, diff.getChangedLines().size());
    }

    @Test
    public void testDefaultOverloadDoesNotNormalize() {
        // The 2-arg overload (used by get-decompilation) must stay byte-for-byte
        // behavior: no normalization.
        DiffResult flagged = DecompilationDiffUtil.createDiff(BEFORE, AFTER, 2, false);
        DiffResult dflt = DecompilationDiffUtil.createDiff(BEFORE, AFTER);
        assertEquals(flagged.getChangedLines().size(), dflt.getChangedLines().size());
    }

    @Test
    public void testNormalizedSnippetShowsOriginalText() {
        DiffResult diff = DecompilationDiffUtil.createDiff(BEFORE, AFTER, 2, true);
        Map<String, Object> map = DecompilationDiffUtil.toMap(diff);
        @SuppressWarnings("unchecked")
        java.util.List<Map<String, Object>> snippets =
            (java.util.List<Map<String, Object>>) map.get("snippets");
        assertFalse(snippets.isEmpty());
        // Snippets must display the ORIGINAL identifiers (masking is equality-only).
        String all = snippets.toString();
        assertTrue("snippet should contain real post-edit text",
                   all.contains("compute(x, y)"));
        assertFalse("snippet must not leak the normalization placeholder",
                    all.contains("_@"));
    }

    // ---- structural (LCS) alignment: mid-body insertion ----------------
    //
    // The canonical security-patch shape: a single guard line inserted mid-body.
    // The index-based differ misaligns every following line (cascade); the
    // structural aligner must report exactly ONE added line and no modifications.

    private static final String BEFORE_INS =
        "void f(void)\n{\n  a();\n  b();\n  c();\n  d();\n  e();\n  return;\n}";

    private static final String AFTER_INS =
        "void f(void)\n{\n  a();\n  b();\n  guard();\n  c();\n  d();\n  e();\n  return;\n}";

    @Test
    public void testStructuralDiffInsertionDoesNotCascade() {
        DiffResult diff = DecompilationDiffUtil.createDiff(BEFORE_INS, AFTER_INS, 2, true);
        assertTrue(diff.hasChanges());
        assertEquals("a single mid-body insertion must not cascade",
                     1, diff.getChangedLines().size());
        DecompilationDiffUtil.ChangedLine cl = diff.getChangedLines().get(0);
        assertEquals(DecompilationDiffUtil.ChangeType.ADDED, cl.getChangeType());
        assertTrue(cl.getAfterContent().contains("guard()"));
    }

    @Test
    public void testIndexBasedInsertionStillCascades() {
        // Flag OFF keeps today's behavior: the inserted line shifts c/d/e/return,
        // so every following line counts as changed. This documents WHY the flag exists.
        DiffResult diff = DecompilationDiffUtil.createDiff(BEFORE_INS, AFTER_INS, 2, false);
        assertTrue("index-based diff cascades a mid-body insertion",
                   diff.getChangedLines().size() > 1);
    }

    @Test
    public void testStructuralDiffCombinesInsertionAndTokenRename() {
        // A LAB_ rename (relocation noise) AND a real inserted guard line. Only the
        // guard should survive: the rename normalizes away, the insertion aligns.
        String before = "void f(void)\n{\n  if (x) goto LAB_00100100;\n  b();\n  c();\n}";
        String after  = "void f(void)\n{\n  if (x) goto LAB_00200200;\n  b();\n  guard();\n  c();\n}";
        DiffResult diff = DecompilationDiffUtil.createDiff(before, after, 2, true);
        assertEquals(1, diff.getChangedLines().size());
        assertEquals(DecompilationDiffUtil.ChangeType.ADDED,
                     diff.getChangedLines().get(0).getChangeType());
        assertTrue(diff.getChangedLines().get(0).getAfterContent().contains("guard()"));
    }

    @Test
    public void testStructuralHunkCarriesSeparateBeforeAfterRanges() {
        DiffResult diff = DecompilationDiffUtil.createDiff(BEFORE_INS, AFTER_INS, 2, true);
        Map<String, Object> map = DecompilationDiffUtil.toMap(diff);
        @SuppressWarnings("unchecked")
        java.util.List<Map<String, Object>> snippets =
            (java.util.List<Map<String, Object>>) map.get("snippets");
        assertFalse(snippets.isEmpty());
        Map<String, Object> hunk = snippets.get(0);
        // Unified-diff hunk shape: separate before/after ranges, plus back-compat keys.
        assertTrue("hunk must carry before-side range", hunk.containsKey("beforeStartLine"));
        assertTrue("hunk must carry after-side range", hunk.containsKey("afterStartLine"));
        assertTrue("back-compat startLine retained", hunk.containsKey("startLine"));
    }

    // ---- canonicalizeAutoVars (Task 1) ---------------------------------

    @Test
    public void testCanonicalizeCollapsesRenumber() {
        assertEquals(DecompilationDiffUtil.canonicalizeAutoVars("  uVar9 = uVar9 >> 0x18;"),
                     DecompilationDiffUtil.canonicalizeAutoVars("  uVar7 = uVar7 >> 0x18;"));
    }

    @Test
    public void testCanonicalizePreservesDistinctVarPattern() {
        // the original uses two distinct vars; patch reuses one — a real swap must NOT collapse.
        assertNotEquals(DecompilationDiffUtil.canonicalizeAutoVars("  uVar8 = uVar9 + uVar5;"),
                        DecompilationDiffUtil.canonicalizeAutoVars("  uVar7 = uVar7 + uVar5;"));
    }

    @Test
    public void testCanonicalizeLeavesParamsRegsConstants() {
        String l = "  param_1 = in_GS_OFFSET + 0x28;";
        assertEquals(l, DecompilationDiffUtil.canonicalizeAutoVars(l));
    }

    @Test
    public void testCanonicalizeHandlesPointerAndStackVars() {
        assertEquals(DecompilationDiffUtil.canonicalizeAutoVars("  puVar7 = local_80;"),
                     DecompilationDiffUtil.canonicalizeAutoVars("  puVar8 = local_80;"));
    }

    // ---- maskStringLabel (Task 2) --------------------------------------

    @Test
    public void testMaskStringLabelCollapsesBuildPath() {
        String a = "      (&PTR_s__build_linux_okuiIE_linux_5_15_0_001048a0,uVar1);";
        String b = "      (&PTR_s__build_linux_tciFHc_linux_5_15_0_001048a0,uVar1);";
        assertEquals(DecompilationDiffUtil.maskStringLabel(a),
                     DecompilationDiffUtil.maskStringLabel(b));
    }

    @Test
    public void testMaskStringLabelLeavesCodeIntact() {
        String l = "  iVar1 = func(param_1);";
        assertEquals(l, DecompilationDiffUtil.maskStringLabel(l));
    }

    // ---- hunk classification & collapse (Task 3) -----------------------

    @Test
    public void testVarRenumberHunkCollapsedByDefault() {
        String before = "void f(void)\n{\n  uVar9 = a;\n  bar(uVar9);\n  return;\n}";
        String after  = "void f(void)\n{\n  uVar7 = a;\n  bar(uVar7);\n  return;\n}";
        DiffResult d = DecompilationDiffUtil.createDiff(before, after, 2, true, false);
        Map<String, Object> map = DecompilationDiffUtil.toMap(d);
        @SuppressWarnings("unchecked")
        Map<String, Integer> sup = (Map<String, Integer>) map.get("suppressedHunks");
        assertEquals(Integer.valueOf(1), sup.get("var-renumber"));
        @SuppressWarnings("unchecked")
        java.util.List<Map<String, Object>> snips =
            (java.util.List<Map<String, Object>>) map.get("snippets");
        assertEquals(1, snips.size());
        assertEquals("var-renumber", snips.get(0).get("classification"));
        assertEquals(Boolean.TRUE, snips.get(0).get("collapsed"));
        assertFalse("collapsed hunk must not carry content", snips.get(0).containsKey("afterContent"));
    }

    @Test
    public void testVarRenumberHunkExpandedWhenRequested() {
        String before = "void f(void)\n{\n  uVar9 = a;\n  bar(uVar9);\n  return;\n}";
        String after  = "void f(void)\n{\n  uVar7 = a;\n  bar(uVar7);\n  return;\n}";
        DiffResult d = DecompilationDiffUtil.createDiff(before, after, 2, true, true);
        Map<String, Object> map = DecompilationDiffUtil.toMap(d);
        @SuppressWarnings("unchecked")
        java.util.List<Map<String, Object>> snips =
            (java.util.List<Map<String, Object>>) map.get("snippets");
        assertEquals("var-renumber", snips.get(0).get("classification"));
        assertTrue("expanded hunk carries content", snips.get(0).containsKey("afterContent"));
    }

    @Test
    public void testMixedHunkStaysCode() {
        String before = "void f(void)\n{\n  uVar9 = a + 1;\n  return;\n}";
        String after  = "void f(void)\n{\n  uVar7 = a + 2;\n  return;\n}";  // constant changed
        DiffResult d = DecompilationDiffUtil.createDiff(before, after, 2, true, false);
        Map<String, Object> map = DecompilationDiffUtil.toMap(d);
        @SuppressWarnings("unchecked")
        java.util.List<Map<String, Object>> snips =
            (java.util.List<Map<String, Object>>) map.get("snippets");
        assertEquals("code", snips.get(0).get("classification"));
        assertTrue(snips.get(0).containsKey("afterContent"));
        assertEquals(1, d.getChangedLines().size());
    }

    @Test
    public void testStringLabelHunkClassified() {
        // Mid-content build token differs (suffix hex is already address-masked in equality).
        String b2 = "void f(void)\n{\n  g(s__build_okuiIE_00104000);\n  return;\n}";
        String a2 = "void f(void)\n{\n  g(s__build_tciFHc_00104000);\n  return;\n}";
        DiffResult d = DecompilationDiffUtil.createDiff(b2, a2, 2, true, false);
        Map<String, Object> map = DecompilationDiffUtil.toMap(d);
        @SuppressWarnings("unchecked")
        Map<String, Integer> sup = (Map<String, Integer>) map.get("suppressedHunks");
        assertEquals(Integer.valueOf(1), sup.get("string-label"));
    }
}
