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

    private static final int MAX_NEAR_MISSES = 3;

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
            String nearMisses = nearMissLines(content, oldString);
            if (nearMisses.isEmpty()) {
                throw new IllegalArgumentException(
                    "Pattern not found: " + preview);
            }
            throw new IllegalArgumentException(
                "Pattern not found: " + preview
                    + "\nClosest lines in the script:\n" + nearMisses
                    + "\nNext: re-read the script with read-script and copy the exact text.");
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

    /**
     * Describe the file lines that most resemble the first non-blank line of a
     * missed {@code old_string}, for {@code edit-script} error messages.
     * <p>
     * Lines containing that text as a substring win; otherwise the lines with
     * the smallest Levenshtein distance are used, counting only lines within
     * half the target's length. At most {@value #MAX_NEAR_MISSES} lines are
     * reported, each as {@code <1-based line number>: <line text>}, separated
     * by newlines. Ties keep the lower line number first.
     *
     * @param content   the file content the edit was attempted against
     * @param oldString the {@code old_string} that did not match
     * @return the formatted near misses, or an empty string when none qualify
     */
    static String nearMissLines(String content, String oldString) {
        if (content == null || content.isEmpty() || oldString == null) {
            return "";
        }
        String target = firstNonBlankLine(oldString);
        if (target == null) {
            return "";
        }

        String[] lines = content.split("\n", -1);
        int lineCount = lines.length;
        if (lineCount > 0 && lines[lineCount - 1].isEmpty()) {
            lineCount--;
        }

        StringBuilder hits = new StringBuilder();
        int hitCount = 0;
        for (int i = 0; i < lineCount && hitCount < MAX_NEAR_MISSES; i++) {
            if (lines[i].contains(target)) {
                appendNearMiss(hits, i + 1, lines[i]);
                hitCount++;
            }
        }
        if (hitCount > 0) {
            return hits.toString();
        }

        int cutoff = target.length() / 2;
        if (cutoff == 0) {
            return "";
        }
        int maxLineLength = target.length();
        for (int i = 0; i < lineCount; i++) {
            maxLineLength = Math.max(maxLineLength, lines[i].length());
        }
        int[] prev = new int[maxLineLength + 1];
        int[] cur = new int[maxLineLength + 1];
        int[] bestDistances = new int[MAX_NEAR_MISSES];
        int[] bestLineNumbers = new int[MAX_NEAR_MISSES];
        int bestCount = 0;

        for (int i = 0; i < lineCount; i++) {
            String line = lines[i];
            if (Math.abs(line.length() - target.length()) > cutoff) {
                continue;
            }
            int distance = levenshtein(target, line, prev, cur);
            if (distance > cutoff) {
                continue;
            }
            if (bestCount == MAX_NEAR_MISSES
                    && distance >= bestDistances[MAX_NEAR_MISSES - 1]) {
                continue;
            }
            int pos = bestCount == MAX_NEAR_MISSES
                ? MAX_NEAR_MISSES - 1
                : bestCount;
            while (pos > 0 && distance < bestDistances[pos - 1]) {
                bestDistances[pos] = bestDistances[pos - 1];
                bestLineNumbers[pos] = bestLineNumbers[pos - 1];
                pos--;
            }
            bestDistances[pos] = distance;
            bestLineNumbers[pos] = i + 1;
            if (bestCount < MAX_NEAR_MISSES) {
                bestCount++;
            }
        }

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < bestCount; i++) {
            appendNearMiss(result, bestLineNumbers[i], lines[bestLineNumbers[i] - 1]);
        }
        return result.toString();
    }

    private static String firstNonBlankLine(String text) {
        int length = text.length();
        int lineStart = 0;
        while (lineStart <= length) {
            int lineEnd = text.indexOf('\n', lineStart);
            if (lineEnd < 0) {
                lineEnd = length;
            }
            boolean blank = true;
            for (int i = lineStart; i < lineEnd; i++) {
                if (!Character.isWhitespace(text.charAt(i))) {
                    blank = false;
                    break;
                }
            }
            if (!blank) {
                return text.substring(lineStart, lineEnd);
            }
            if (lineEnd == length) {
                return null;
            }
            lineStart = lineEnd + 1;
        }
        return null;
    }

    private static void appendNearMiss(StringBuilder sb, int lineNumber, String lineText) {
        if (sb.length() > 0) {
            sb.append('\n');
        }
        sb.append(lineNumber).append(": ").append(lineText);
    }

    private static int levenshtein(String a, String b, int[] prev, int[] cur) {
        int aLength = a.length();
        int bLength = b.length();
        for (int j = 0; j <= bLength; j++) {
            prev[j] = j;
        }
        for (int i = 1; i <= aLength; i++) {
            cur[0] = i;
            char aChar = a.charAt(i - 1);
            for (int j = 1; j <= bLength; j++) {
                int cost = aChar == b.charAt(j - 1) ? 0 : 1;
                int replace = prev[j - 1] + cost;
                int delete = prev[j] + 1;
                int insert = cur[j - 1] + 1;
                cur[j] = Math.min(replace, Math.min(delete, insert));
            }
            int[] swap = prev;
            prev = cur;
            cur = swap;
        }
        return prev[bLength];
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
