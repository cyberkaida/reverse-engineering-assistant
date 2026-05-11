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

/**
 * Pure helpers for the {@code read-script} and {@code edit-script} tools,
 * modeled after Claude Code's Read/Edit ergonomics. Kept stateless and free of
 * I/O so it can be unit-tested without filesystem fixtures — file I/O is done
 * by {@code ScriptToolProvider} once these helpers validate / transform.
 */
public final class ScriptFileEditor {

    private ScriptFileEditor() {}

    /**
     * The result of slicing a file for {@code read-script}.
     *
     * @param text        the rendered slice with {@code <line_no>\t} prefixes
     * @param totalLines  total lines in the underlying file
     * @param startLine   1-indexed line number of the first rendered line
     *                    (0 if the slice is empty)
     * @param endLine     1-indexed line number of the last rendered line
     *                    (0 if the slice is empty)
     * @param truncated   true if lines remain after {@code endLine}
     */
    public static record RenderedView(
        String text, int totalLines, int startLine, int endLine, boolean truncated) {}

    /**
     * @param newContent   the file content after applying the edit
     * @param replacements the number of replacements performed
     */
    public static record EditResult(String newContent, int replacements) {}

    /**
     * Slice the file content into a Claude-Code-style {@code cat -n} view,
     * honoring 1-indexed {@code offset} and {@code limit}.
     */
    public static RenderedView renderWithLineNumbers(
            String content, int offset, int limit) {
        if (offset < 1) {
            throw new IllegalArgumentException(
                "offset must be >= 1, got: " + offset);
        }
        if (limit < 1) {
            throw new IllegalArgumentException(
                "limit must be >= 1, got: " + limit);
        }

        if (content.isEmpty()) {
            return new RenderedView("", 0, 0, 0, false);
        }

        // Split preserving trailing empty fields so a file ending with \n
        // doesn't lose its final empty line — but then drop a single trailing
        // empty entry so we don't render a phantom line after the last \n.
        String[] all = content.split("\n", -1);
        int totalLines = all.length;
        if (totalLines > 0 && all[totalLines - 1].isEmpty()) {
            totalLines--;
        }

        if (offset > totalLines) {
            return new RenderedView("", totalLines, 0, 0, false);
        }

        int endExclusive = Math.min(totalLines, offset - 1 + limit);
        StringBuilder sb = new StringBuilder();
        for (int i = offset - 1; i < endExclusive; i++) {
            sb.append(i + 1).append('\t').append(all[i]).append('\n');
        }
        boolean truncated = endExclusive < totalLines;
        return new RenderedView(sb.toString(), totalLines, offset, endExclusive, truncated);
    }

    /**
     * Replace {@code oldString} with {@code newString} in {@code content}.
     * <ul>
     *   <li>{@code oldString} must occur at least once.</li>
     *   <li>When {@code replaceAll} is false it must occur exactly once.</li>
     *   <li>{@code oldString} may not be empty and may not equal {@code newString}.</li>
     * </ul>
     */
    public static EditResult applyEdit(
            String content, String oldString, String newString, boolean replaceAll) {
        if (oldString == null || oldString.isEmpty()) {
            throw new IllegalArgumentException("old_string must not be empty");
        }
        if (newString == null) {
            throw new IllegalArgumentException("new_string must not be null");
        }
        if (oldString.equals(newString)) {
            throw new IllegalArgumentException(
                "new_string must differ from old_string");
        }

        int count = countOccurrences(content, oldString);
        if (count == 0) {
            String preview = oldString.length() > 80
                ? oldString.substring(0, 80) + "..."
                : oldString;
            throw new IllegalArgumentException(
                "Pattern not found: " + preview);
        }
        if (count > 1 && !replaceAll) {
            throw new IllegalArgumentException(
                "Pattern matches " + count
                    + " locations; provide more context or set replace_all: true");
        }

        String newContent;
        int replacements;
        if (replaceAll) {
            newContent = content.replace(oldString, newString);
            replacements = count;
        } else {
            int idx = content.indexOf(oldString);
            newContent = content.substring(0, idx)
                + newString
                + content.substring(idx + oldString.length());
            replacements = 1;
        }
        return new EditResult(newContent, replacements);
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        int idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) != -1) {
            count++;
            idx += needle.length();
        }
        return count;
    }
}
