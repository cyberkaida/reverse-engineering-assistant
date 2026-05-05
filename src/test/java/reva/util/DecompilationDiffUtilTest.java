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

import java.util.List;
import java.util.Map;

import org.junit.Test;

import reva.util.DecompilationDiffUtil.ChangedLine;
import reva.util.DecompilationDiffUtil.ChangeType;
import reva.util.DecompilationDiffUtil.DiffResult;

/**
 * Unit tests for DecompilationDiffUtil.
 */
public class DecompilationDiffUtilTest {

    // ========== createDiff - identical content ==========

    @Test
    public void testCreateDiff_IdenticalContent() {
        String code = "void foo() {\n    int x = 1;\n}";
        DiffResult result = DecompilationDiffUtil.createDiff(code, code);

        assertFalse("Identical content should report no changes", result.hasChanges());
        assertTrue("Changed lines list should be empty", result.getChangedLines().isEmpty());
        assertEquals("No changes detected", result.getDiffSummary());
        assertTrue("Snippets should be empty", result.getSnippets().isEmpty());
    }

    // ========== createDiff - modified line ==========

    @Test
    public void testCreateDiff_SingleModifiedLine() {
        String before = "void foo() {\n    int x = 1;\n}";
        String after  = "void foo() {\n    int x = 42;\n}";
        DiffResult result = DecompilationDiffUtil.createDiff(before, after);

        assertTrue("Should detect changes", result.hasChanges());
        assertEquals("Should have exactly 1 changed line", 1, result.getChangedLines().size());

        ChangedLine change = result.getChangedLines().get(0);
        assertEquals(ChangeType.MODIFIED, change.getChangeType());
        assertEquals(2, change.getLineNumber());
        assertTrue(change.getBeforeContent().contains("int x = 1"));
        assertTrue(change.getAfterContent().contains("int x = 42"));
    }

    @Test
    public void testCreateDiff_MultipleModifiedLines() {
        String before = "int a = 1;\nint b = 2;\nint c = 3;";
        String after  = "int a = 10;\nint b = 2;\nint c = 30;";
        DiffResult result = DecompilationDiffUtil.createDiff(before, after);

        assertTrue(result.hasChanges());
        // lines 1 and 3 changed
        List<ChangedLine> changes = result.getChangedLines();
        assertEquals(2, changes.size());
        assertEquals(1, changes.get(0).getLineNumber());
        assertEquals(3, changes.get(1).getLineNumber());
    }

    // ========== createDiff - added lines ==========

    @Test
    public void testCreateDiff_AddedLines() {
        String before = "void foo() {}";
        String after  = "void foo() {}\nvoid bar() {}";
        DiffResult result = DecompilationDiffUtil.createDiff(before, after);

        assertTrue(result.hasChanges());
        List<ChangedLine> changes = result.getChangedLines();
        assertEquals(1, changes.size());
        assertEquals(ChangeType.ADDED, changes.get(0).getChangeType());
        assertEquals(2, changes.get(0).getLineNumber());
        assertTrue(changes.get(0).getAfterContent().contains("bar"));
        assertEquals("", changes.get(0).getBeforeContent());
    }

    // ========== createDiff - removed lines ==========

    @Test
    public void testCreateDiff_RemovedLines() {
        String before = "void foo() {}\nvoid bar() {}";
        String after  = "void foo() {}";
        DiffResult result = DecompilationDiffUtil.createDiff(before, after);

        assertTrue(result.hasChanges());
        List<ChangedLine> changes = result.getChangedLines();
        assertEquals(1, changes.size());
        assertEquals(ChangeType.REMOVED, changes.get(0).getChangeType());
        assertEquals(2, changes.get(0).getLineNumber());
        assertTrue(changes.get(0).getBeforeContent().contains("bar"));
        assertEquals("", changes.get(0).getAfterContent());
    }

    // ========== createDiff - null / empty inputs ==========

    @Test
    public void testCreateDiff_BothNull() {
        DiffResult result = DecompilationDiffUtil.createDiff(null, null);
        assertFalse("Null + null should be identical (both empty)", result.hasChanges());
    }

    @Test
    public void testCreateDiff_BeforeNull() {
        // null before is treated as empty string, so first line is "" vs "int x;" → MODIFIED
        DiffResult result = DecompilationDiffUtil.createDiff(null, "int x;");
        assertTrue("Null before + non-null after should have changes", result.hasChanges());
        assertFalse(result.getChangedLines().isEmpty());
        // Both arrays have one element; they differ → MODIFIED
        assertEquals(ChangeType.MODIFIED, result.getChangedLines().get(0).getChangeType());
    }

    @Test
    public void testCreateDiff_AfterNull() {
        // null after is treated as empty string, so first line is "int x;" vs "" → MODIFIED
        DiffResult result = DecompilationDiffUtil.createDiff("int x;", null);
        assertTrue("Non-null before + null after should have changes", result.hasChanges());
        assertFalse(result.getChangedLines().isEmpty());
        // Both arrays have one element; they differ → MODIFIED
        assertEquals(ChangeType.MODIFIED, result.getChangedLines().get(0).getChangeType());
    }

    @Test
    public void testCreateDiff_EmptyStrings() {
        DiffResult result = DecompilationDiffUtil.createDiff("", "");
        assertFalse(result.hasChanges());
    }

    // ========== createDiff - context lines ==========

    @Test
    public void testCreateDiff_CustomContextLines() {
        String before = "line1\nline2\nline3\nline4\nline5";
        String after  = "line1\nline2\nXXX\nline4\nline5";
        // Use 1 context line
        DiffResult result = DecompilationDiffUtil.createDiff(before, after, 1);

        assertTrue(result.hasChanges());
        assertFalse(result.getSnippets().isEmpty());

        Map<String, Object> snippet = result.getSnippets().get(0);
        int startLine = (int) snippet.get("startLine");
        int endLine = (int) snippet.get("endLine");
        // With 1 context line around line 3, expect start=2, end=4
        assertEquals(2, startLine);
        assertEquals(4, endLine);
    }

    @Test
    public void testCreateDiff_ZeroContextLines() {
        String before = "a\nb\nc";
        String after  = "a\nX\nc";
        DiffResult result = DecompilationDiffUtil.createDiff(before, after, 0);

        assertTrue(result.hasChanges());
        Map<String, Object> snippet = result.getSnippets().get(0);
        int startLine = (int) snippet.get("startLine");
        int endLine = (int) snippet.get("endLine");
        assertEquals(2, startLine);
        assertEquals(2, endLine);
    }

    @Test
    public void testCreateDiff_DefaultContextIs2() {
        String before = "a\nb\nc\nd\ne";
        String after  = "a\nb\nX\nd\ne";
        // default context = 2
        DiffResult result1 = DecompilationDiffUtil.createDiff(before, after);
        DiffResult result2 = DecompilationDiffUtil.createDiff(before, after, 2);

        assertEquals(result1.getSnippets().size(), result2.getSnippets().size());
        Map<String, Object> s1 = result1.getSnippets().get(0);
        Map<String, Object> s2 = result2.getSnippets().get(0);
        assertEquals(s1.get("startLine"), s2.get("startLine"));
        assertEquals(s1.get("endLine"), s2.get("endLine"));
    }

    // ========== summary string ==========

    @Test
    public void testSummary_ModifiedOnly() {
        String before = "int a = 1;\nint b = 2;";
        String after  = "int a = 9;\nint b = 8;";
        DiffResult result = DecompilationDiffUtil.createDiff(before, after);

        String summary = result.getDiffSummary();
        assertTrue("Summary should mention modified", summary.contains("modified"));
        assertFalse("Summary should not mention added", summary.contains("added"));
        assertFalse("Summary should not mention removed", summary.contains("removed"));
    }

    @Test
    public void testSummary_AddedOnly() {
        String before = "int a;";
        String after  = "int a;\nint b;";
        DiffResult result = DecompilationDiffUtil.createDiff(before, after);

        String summary = result.getDiffSummary();
        assertTrue(summary.contains("added"));
    }

    @Test
    public void testSummary_RemovedOnly() {
        String before = "int a;\nint b;";
        String after  = "int a;";
        DiffResult result = DecompilationDiffUtil.createDiff(before, after);

        String summary = result.getDiffSummary();
        assertTrue(summary.contains("removed"));
    }

    @Test
    public void testSummary_PluralAndSingular() {
        // 1 line changed -> "line", not "lines"
        DiffResult one = DecompilationDiffUtil.createDiff("int a = 1;", "int a = 2;");
        assertTrue(one.getDiffSummary().contains("1 line modified"));

        // 2 lines changed -> "lines"
        DiffResult two = DecompilationDiffUtil.createDiff("int a = 1;\nint b = 1;", "int a = 2;\nint b = 2;");
        assertTrue(two.getDiffSummary().contains("lines modified"));
    }

    // ========== snippets ==========

    @Test
    public void testSnippets_ContainBeforeAndAfterContent() {
        String before = "int x = 1;";
        String after  = "int x = 99;";
        DiffResult result = DecompilationDiffUtil.createDiff(before, after);

        assertFalse(result.getSnippets().isEmpty());
        Map<String, Object> snippet = result.getSnippets().get(0);
        assertTrue(snippet.containsKey("beforeContent"));
        assertTrue(snippet.containsKey("afterContent"));
        String beforeContent = (String) snippet.get("beforeContent");
        String afterContent  = (String) snippet.get("afterContent");
        assertTrue(beforeContent.contains("x = 1"));
        assertTrue(afterContent.contains("x = 99"));
    }

    @Test
    public void testSnippets_ContainChangedLineNumbers() {
        String before = "int x = 1;";
        String after  = "int x = 99;";
        DiffResult result = DecompilationDiffUtil.createDiff(before, after);

        Map<String, Object> snippet = result.getSnippets().get(0);
        assertTrue(snippet.containsKey("changedLines"));
        int[] changedLines = (int[]) snippet.get("changedLines");
        assertEquals(1, changedLines.length);
        assertEquals(1, changedLines[0]);
    }

    @Test
    public void testSnippets_NearbyChangesGrouped() {
        // Changes on lines 2 and 3 with contextLines=1 (maxGap=2): gap=1 <= 2 → grouped
        String before = "a\nB\nC\nd";
        String after  = "a\nb\nc\nd";
        DiffResult result = DecompilationDiffUtil.createDiff(before, after, 1);

        // With contextLines=1, maxGap=2; adjacent changes (gap=1) → 1 snippet
        assertEquals("Adjacent changes should produce one snippet", 1, result.getSnippets().size());
    }

    @Test
    public void testSnippets_DistantChangesNotGrouped() {
        // Build two changes that are far apart (more than 2*contextLines apart)
        StringBuilder before = new StringBuilder();
        StringBuilder after  = new StringBuilder();
        // Line 1: changed
        before.append("BEFORE_1\n");
        after.append("AFTER_1\n");
        // Lines 2-20: unchanged
        for (int i = 2; i <= 20; i++) {
            before.append("same_").append(i).append("\n");
            after.append("same_").append(i).append("\n");
        }
        // Line 21: changed
        before.append("BEFORE_21");
        after.append("AFTER_21");

        DiffResult result = DecompilationDiffUtil.createDiff(before.toString(), after.toString(), 2);
        assertTrue("Far-apart changes should produce multiple snippets", result.getSnippets().size() >= 2);
    }

    // ========== toMap ==========

    @Test
    public void testToMap_NoChanges() {
        DiffResult result = DecompilationDiffUtil.createDiff("same", "same");
        Map<String, Object> map = DecompilationDiffUtil.toMap(result);

        assertEquals(false, map.get("hasChanges"));
        assertEquals("No changes detected", map.get("summary"));
        assertEquals(0, map.get("changedLineCount"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> snippets = (List<Map<String, Object>>) map.get("snippets");
        assertTrue(snippets.isEmpty());
    }

    @Test
    public void testToMap_WithChanges() {
        DiffResult result = DecompilationDiffUtil.createDiff("int x = 1;", "int x = 2;");
        Map<String, Object> map = DecompilationDiffUtil.toMap(result);

        assertEquals(true, map.get("hasChanges"));
        assertEquals(1, map.get("changedLineCount"));
        assertNotNull(map.get("summary"));
        assertNotNull(map.get("snippets"));
    }

    // ========== ChangedLine accessors ==========

    @Test
    public void testChangedLineAccessors() {
        ChangedLine line = new ChangedLine(5, "before_content", "after_content", ChangeType.MODIFIED);
        assertEquals(5, line.getLineNumber());
        assertEquals("before_content", line.getBeforeContent());
        assertEquals("after_content", line.getAfterContent());
        assertEquals(ChangeType.MODIFIED, line.getChangeType());
    }

    @Test
    public void testDiffResultAccessors_NoChanges() {
        DiffResult result = DecompilationDiffUtil.createDiff("x", "x");
        assertFalse(result.hasChanges());
        assertNotNull(result.getChangedLines());
        assertNotNull(result.getDiffSummary());
        assertNotNull(result.getSnippets());
    }
}
