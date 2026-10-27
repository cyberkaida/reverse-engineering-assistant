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

import java.util.regex.Pattern;

/**
 * Extracts the final exception line from captured stderr.
 * <p>
 * PyGhidra swallows a Python exception: it prints the traceback to the
 * script's error writer and returns normally, so that text is the only
 * description of the failure. A traceback ends with the exception line —
 * {@code TypeError: No matching overloads found for ...} — whose message may
 * wrap onto continuation lines (Ghidra's "options are:" overload list is the
 * real case). Reporting that line instead of the raw traceback gives the
 * caller "what failed and why" in the result's {@code error} field.
 * <p>
 * A chained traceback ("During handling of the above exception, another
 * exception occurred") is resolved to its last exception — the one that
 * actually escaped the script.
 */
final class PythonTracebacks {

    /**
     * Upper bound on the returned line, so one verbose message cannot flood
     * the result.
     */
    static final int MAX_CHARS = 200;

    private static final Pattern LINE_BREAK = Pattern.compile("\r?\n");
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    private PythonTracebacks() {
    }

    /**
     * The final exception line of the last traceback in {@code stderr}, with
     * its continuation lines joined by single spaces, whitespace collapsed
     * and capped at {@link #MAX_CHARS}. When stderr has no traceback (or the
     * traceback has no exception line), the last non-empty line is used
     * instead.
     *
     * @param stderr text captured from the script's error writer
     * @return the summary, or null when there is no non-empty line at all
     */
    static String summary(String stderr) {
        if (stderr == null) {
            return null;
        }
        int marker = stderr.lastIndexOf(PythonScriptExecutor.PYTHON_TRACEBACK_MARKER);
        String line = marker >= 0 ? exceptionLine(stderr.substring(marker)) : null;
        if (line == null) {
            line = lastNonEmptyLine(stderr);
        }
        return line == null ? null : cap(line);
    }

    /**
     * The exception line of the traceback the given text starts with, joined
     * with its continuation lines up to a blank line or the end.
     * <p>
     * Frames, source echoes and carets are indented, so the exception line is
     * the first non-indented line after the header. It is taken from the
     * last traceback only, so chained tracebacks resolve to the final
     * exception.
     */
    private static String exceptionLine(String traceback) {
        String[] lines = LINE_BREAK.split(traceback, -1);
        int start = -1;
        for (int i = 0; i < lines.length; i++) {
            if (isExceptionStart(lines[i])) {
                start = i;
                break;
            }
        }
        if (start < 0) {
            return null;
        }
        StringBuilder joined = new StringBuilder(lines[start].strip());
        for (int i = start + 1; i < lines.length; i++) {
            if (lines[i].isBlank()) {
                break;
            }
            joined.append(' ').append(lines[i].strip());
            if (joined.length() >= MAX_CHARS) {
                break;
            }
        }
        return WHITESPACE.matcher(joined).replaceAll(" ").strip();
    }

    private static boolean isExceptionStart(String line) {
        if (line.isBlank() || Character.isWhitespace(line.charAt(0))) {
            return false;
        }
        if (line.startsWith(PythonScriptExecutor.PYTHON_TRACEBACK_MARKER)) {
            return false;
        }
        // Chain notes are printed at column 0 between two tracebacks; the
        // search starts after the last header, so these are only seen when a
        // further traceback is missing its header.
        return !line.startsWith("During handling of the above exception")
            && !line.startsWith("The above exception was the direct cause");
    }

    private static String lastNonEmptyLine(String text) {
        String[] lines = LINE_BREAK.split(text, -1);
        for (int i = lines.length - 1; i >= 0; i--) {
            if (!lines[i].isBlank()) {
                return WHITESPACE.matcher(lines[i]).replaceAll(" ").strip();
            }
        }
        return null;
    }

    private static String cap(String line) {
        return line.length() <= MAX_CHARS ? line : line.substring(0, MAX_CHARS);
    }
}
