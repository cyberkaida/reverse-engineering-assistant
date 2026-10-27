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
package reva.tools.scripts;

import static org.junit.Assert.*;

import org.junit.Test;

import reva.tools.scripts.ScriptFileEditor.EditResult;
import reva.tools.scripts.ScriptFileEditor.RenderedView;

/**
 * Unit tests for {@link ScriptFileEditor}'s pure helpers:
 * <ul>
 *   <li>{@code renderWithLineNumbers} — Claude-Code-style {@code cat -n}
 *       formatting with chunked offset/limit and truncation flag</li>
 *   <li>{@code applyEdit} — exact {@code old_string}/{@code new_string}
 *       replacement with uniqueness check and {@code replace_all} mode</li>
 *   <li>{@code nearMissLines} — closest-line hints reported when an edit
 *       pattern is not found</li>
 * </ul>
 */
public class ScriptFileEditorTest {

    // -------- renderWithLineNumbers --------

    @Test
    public void rendersWithOneIndexedLineNumbers() {
        String content = "alpha\nbeta\ngamma\n";
        RenderedView view = ScriptFileEditor.renderWithLineNumbers(content, 1, 100);
        assertEquals("1\talpha\n2\tbeta\n3\tgamma\n", view.text());
        assertEquals(3, view.totalLines());
        assertEquals(1, view.startLine());
        assertEquals(3, view.endLine());
        assertFalse(view.truncated());
    }

    @Test
    public void handlesEmptyFile() {
        RenderedView view = ScriptFileEditor.renderWithLineNumbers("", 1, 100);
        assertEquals("", view.text());
        assertEquals(0, view.totalLines());
        assertEquals(0, view.endLine());
        assertFalse(view.truncated());
    }

    @Test
    public void renderHandlesNoTrailingNewline() {
        String content = "x\ny";
        RenderedView view = ScriptFileEditor.renderWithLineNumbers(content, 1, 100);
        assertEquals("1\tx\n2\ty\n", view.text());
        assertEquals(2, view.totalLines());
    }

    @Test
    public void offsetSkipsLeadingLines() {
        String content = "a\nb\nc\nd\n";
        RenderedView view = ScriptFileEditor.renderWithLineNumbers(content, 3, 100);
        assertEquals("3\tc\n4\td\n", view.text());
        assertEquals(4, view.totalLines());
        assertEquals(3, view.startLine());
        assertEquals(4, view.endLine());
        assertFalse(view.truncated());
    }

    @Test
    public void limitTruncatesRemainingLines() {
        String content = "a\nb\nc\nd\n";
        RenderedView view = ScriptFileEditor.renderWithLineNumbers(content, 1, 2);
        assertEquals("1\ta\n2\tb\n", view.text());
        assertEquals(4, view.totalLines());
        assertEquals(1, view.startLine());
        assertEquals(2, view.endLine());
        assertTrue("more lines remain past the slice", view.truncated());
    }

    @Test
    public void offsetPlusLimitInMiddleOfFile() {
        String content = "a\nb\nc\nd\ne\n";
        RenderedView view = ScriptFileEditor.renderWithLineNumbers(content, 2, 2);
        assertEquals("2\tb\n3\tc\n", view.text());
        assertEquals(5, view.totalLines());
        assertTrue(view.truncated());
    }

    @Test
    public void offsetPastEndYieldsEmptySlice() {
        String content = "a\nb\n";
        RenderedView view = ScriptFileEditor.renderWithLineNumbers(content, 10, 5);
        assertEquals("", view.text());
        assertEquals(2, view.totalLines());
        assertEquals(0, view.endLine());
        assertFalse(view.truncated());
    }

    @Test(expected = IllegalArgumentException.class)
    public void renderRejectsZeroOffset() {
        ScriptFileEditor.renderWithLineNumbers("a\n", 0, 10);
    }

    @Test(expected = IllegalArgumentException.class)
    public void renderRejectsNegativeOffset() {
        ScriptFileEditor.renderWithLineNumbers("a\n", -1, 10);
    }

    @Test(expected = IllegalArgumentException.class)
    public void renderRejectsZeroLimit() {
        ScriptFileEditor.renderWithLineNumbers("a\n", 1, 0);
    }

    // -------- applyEdit --------

    @Test
    public void replacesSingleUniqueOccurrence() {
        EditResult r = ScriptFileEditor.applyEdit(
            "foo\nbar\nbaz\n", "bar", "BAR", false);
        assertEquals("foo\nBAR\nbaz\n", r.newContent());
        assertEquals(1, r.replacements());
    }

    @Test
    public void replacesAcrossLinesWhenStringSpansThem() {
        EditResult r = ScriptFileEditor.applyEdit(
            "alpha\nbeta\ngamma\n", "alpha\nbeta", "X", false);
        assertEquals("X\ngamma\n", r.newContent());
        assertEquals(1, r.replacements());
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsOldStringNotFound() {
        ScriptFileEditor.applyEdit("nothing here", "missing", "X", false);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsAmbiguousMatchWithoutReplaceAll() {
        // "x" appears 3 times — must error without replace_all
        ScriptFileEditor.applyEdit("x y x z x", "x", "X", false);
    }

    @Test
    public void replaceAllReplacesEveryOccurrence() {
        EditResult r = ScriptFileEditor.applyEdit(
            "x y x z x", "x", "X", true);
        assertEquals("X y X z X", r.newContent());
        assertEquals(3, r.replacements());
    }

    @Test
    public void replaceAllStillErrorsWhenOldStringAbsent() {
        try {
            ScriptFileEditor.applyEdit("hello", "missing", "X", true);
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsSameOldAndNew() {
        ScriptFileEditor.applyEdit("foo", "foo", "foo", false);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsEmptyOldString() {
        ScriptFileEditor.applyEdit("foo", "", "X", false);
    }

    @Test
    public void allowsEmptyNewStringForDeletion() {
        EditResult r = ScriptFileEditor.applyEdit("foo bar baz", "bar ", "", false);
        assertEquals("foo baz", r.newContent());
        assertEquals(1, r.replacements());
    }

    // -------- near-miss reporting --------

    @Test
    public void missReportsNearMatchingLines() {
        try {
            ScriptFileEditor.applyEdit(
                "line one\nimport os\nline three\n", "import  os", "import os", false);
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            String message = expected.getMessage();
            assertTrue(message, message.contains("Pattern not found"));
            assertTrue(message, message.contains("2: import os"));
            assertTrue(message, message.contains("read-script"));
            assertTrue(message, message.contains("copy the exact text"));
        }
    }

    @Test
    public void nearMissPrefersSubstringHitsOverCloserDistances() {
        String content = "abc deg\nunrelated\nzzz abc def ghi\n";
        assertEquals("3: zzz abc def ghi",
            ScriptFileEditor.nearMissLines(content, "abc def"));
    }

    @Test
    public void nearMissUsesFirstNonBlankLineOfOldString() {
        String content = "line one\nimport os\nline three\n";
        assertEquals("2: import os",
            ScriptFileEditor.nearMissLines(content, "\n  \nimport  os"));
    }

    @Test
    public void nearMissReportsAtMostThreeLinesTiesGoToLowerNumbers() {
        String content = "abcdefgX\nabcdefXh\nabcdeXgh\nabcdXfgh\nabcXefgh\n";
        assertEquals("1: abcdefgX\n2: abcdefXh\n3: abcdeXgh",
            ScriptFileEditor.nearMissLines(content, "abcdefgh"));
    }

    @Test
    public void nearMissCapsSubstringHitsAtThreeLines() {
        String content = "import osA\nimport osB\nimport osC\nimport osD\n";
        assertEquals("1: import osA\n2: import osB\n3: import osC",
            ScriptFileEditor.nearMissLines(content, "import os"));
    }

    @Test
    public void nearMissIgnoresLinesPastHalfTheTargetLength() {
        assertEquals("", ScriptFileEditor.nearMissLines(
            "zzzzzzzz\nqqqqqqqq\n", "import os"));
    }

    @Test
    public void missWithoutCloseLinesKeepsOnlyThePreview() {
        try {
            ScriptFileEditor.applyEdit("zzzzzzzz\nqqqqqqqq\n", "import os", "X", false);
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("Pattern not found: import os", expected.getMessage());
        }
    }
}
