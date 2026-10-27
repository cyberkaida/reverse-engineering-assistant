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

/**
 * Unit tests for {@link PythonTracebacks}: PyGhidra reports a Python failure
 * only as traceback text in stderr, and the extracted exception line is what
 * the run-script result shows in its {@code error} field.
 */
public class PythonTracebacksTest {

    /**
     * Captured from a live session: Jython could not resolve an overload and
     * printed the candidates on a continuation line, indented with a tab.
     */
    private static final String OVERLOAD_STDERR =
        "Traceback (most recent call last):\n"
            + "  File \"<string>\", line 16, in <module>\n"
            + "  File \"/tmp/reva_12345.py\", line 8, in annotate\n"
            + "TypeError: No matching overloads found for "
            + "ghidra.program.flatapi.FlatProgramAPI.createBookmark("
            + "ghidra.program.model.address.GenericAddress,str,str,str), "
            + "options are:\n"
            + "\tpublic final ...createBookmark(...Address,String,String)\n"
            + "\n";

    @Test
    public void extractsTheExceptionLineAndItsContinuation() {
        String line = PythonTracebacks.summary(OVERLOAD_STDERR);

        assertTrue(line, line.startsWith(
            "TypeError: No matching overloads found for "
                + "ghidra.program.flatapi.FlatProgramAPI.createBookmark("));
        assertTrue("the continuation line is joined, not dropped: " + line,
            line.contains("options are: public final ...createBookmark("));
        assertFalse("a result line must not carry a newline: " + line,
            line.contains("\n"));
        assertFalse("a result line must not carry a tab: " + line,
            line.contains("\t"));
        assertEquals("the verbose message is capped at " + PythonTracebacks.MAX_CHARS,
            PythonTracebacks.MAX_CHARS, line.length());
    }

    @Test
    public void handlesAnExceptionWithoutAMessage() {
        String stderr = "Traceback (most recent call last):\n"
            + "  File \"<string>\", line 1, in <module>\n"
            + "RuntimeError\n";

        assertEquals("RuntimeError", PythonTracebacks.summary(stderr));
    }

    @Test
    public void joinsAMultiLineMessage() {
        String stderr = "Traceback (most recent call last):\n"
            + "  File \"<string>\", line 1, in <module>\n"
            + "ValueError: first line\n"
            + "of the message\n"
            + "\tand a third\n"
            + "\n";

        assertEquals("ValueError: first line of the message and a third",
            PythonTracebacks.summary(stderr));
    }

    @Test
    public void usesTheLastOfSeveralTracebacks() {
        String stderr = "Traceback (most recent call last):\n"
            + "  File \"<string>\", line 2, in <module>\n"
            + "ValueError: first failure\n"
            + "During handling of the above exception, another exception "
            + "occurred:\n"
            + "Traceback (most recent call last):\n"
            + "  File \"<string>\", line 5, in <module>\n"
            + "TypeError: second failure\n";

        assertEquals("TypeError: second failure", PythonTracebacks.summary(stderr));
    }

    @Test
    public void stopsAtABlankLineAfterTheException() {
        String stderr = "Traceback (most recent call last):\n"
            + "  File \"<string>\", line 1, in <module>\n"
            + "KeyError: 'missing'\n"
            + "\n"
            + "noise printed after the traceback\n";

        assertEquals("KeyError: 'missing'", PythonTracebacks.summary(stderr));
    }

    @Test
    public void fallsBackToTheLastNonEmptyLineWithoutATraceback() {
        assertEquals("last failure here",
            PythonTracebacks.summary("some noise\nlast failure here\n\n"));

        // even when a traceback header is there, but no exception line
        assertEquals("Traceback (most recent call last):",
            PythonTracebacks.summary("Traceback (most recent call last):\n"));
    }

    @Test
    public void capsTheFallbackLine() {
        String longLine = "x".repeat(PythonTracebacks.MAX_CHARS + 50);

        assertEquals(PythonTracebacks.MAX_CHARS,
            PythonTracebacks.summary("noise\n" + longLine + "\n").length());
    }

    @Test
    public void reportsNothingForEmptyStderr() {
        assertNull(PythonTracebacks.summary(null));
        assertNull(PythonTracebacks.summary(""));
        assertNull(PythonTracebacks.summary("\n  \n"));
    }
}
