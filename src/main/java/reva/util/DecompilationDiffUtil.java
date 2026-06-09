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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Utility for comparing decompilation results and creating diffs/snippets of changed content
 */
public class DecompilationDiffUtil {

    /**
     * Ghidra default-name label tokens that carry a load address as their suffix
     * (FUN_/LAB_/SUB_/DAT_/EXT_/PTR_/ARRAY_/UNK_ + hex). On a relocated (linked)
     * image these are renamed on every load even when the statement is unchanged.
     * Mirrors {@link SymbolUtil}'s default-name prefixes, unanchored for in-line
     * matching. The hex run is at least 4 digits so short, stable frame-offset
     * names (local_18, auStack_28) are never touched.
     */
    private static final Pattern ADDRESS_LABEL_TOKEN = Pattern.compile(
        "\\b(FUN|LAB|SUB|DAT|EXT|PTR|ARRAY|UNK)_[0-9a-fA-F]{4,}");

    /**
     * String-data labels: {@code s_<text>_<hex>} (ASCII) / {@code u_<text>_<hex>}
     * (unicode). The text is informative and preserved; only the trailing load
     * address shifts, so just that suffix is masked.
     */
    private static final Pattern STRING_LABEL_TOKEN = Pattern.compile(
        "\\b([su]_[0-9A-Za-z_]+?)_[0-9a-fA-F]{4,}\\b");

    /** Canonical placeholder substituted for a shifting load address. */
    private static final String ADDR_PLACEHOLDER = "_@";

    /**
     * Bare {@code 0x<hex>} literal. Only masked inside decompiler WARNING comment
     * annotations (see {@link #normalizeAddressTokens}); NEVER in code, where a hex
     * literal can be a real constant (a bound, mask, or offset).
     */
    private static final Pattern BARE_HEX = Pattern.compile("0x[0-9a-fA-F]+");

    /**
     * Normalize a single decompiled line by masking the load-address suffix of
     * Ghidra default-name labels, so two relocations of the same statement compare
     * equal. Used only for the change-detection equality test — callers still
     * display the original, un-normalized text. Lines without such tokens are
     * returned unchanged. Bare {@code 0x<hex>} operands are intentionally NOT
     * masked (a genuine constant/offset change must still register).
     *
     * @param line a single line of decompiled C text
     * @return the line with shifting address suffixes replaced by a placeholder
     */
    static String normalizeAddressTokens(String line) {
        if (line == null || line.isEmpty()) {
            return line;
        }
        String result = ADDRESS_LABEL_TOKEN.matcher(line).replaceAll("$1" + ADDR_PLACEHOLDER);
        result = STRING_LABEL_TOKEN.matcher(result).replaceAll("$1" + ADDR_PLACEHOLDER);
        // Decompiler WARNING annotations embed absolute addresses that shift between
        // builds (e.g. "Removing unreachable block (ram,0x...)"). These are metadata,
        // never logic, so masking their bare hex is safe and stops the whole comment
        // line from registering as a spurious change. Scoped to WARNING lines ONLY so a
        // real hex constant in code (a bound/mask/offset) is never masked.
        if (result.contains("/* WARNING:")) {
            result = BARE_HEX.matcher(result).replaceAll("0x@");
        }
        return result;
    }

    /**
     * Ghidra auto-variable tokens the decompiler renumbers between builds:
     * type-prefixed register vars ({@code uVar1}/{@code puVar3}/{@code pcVar2}),
     * stack slots ({@code local_18}), and stack arrays ({@code auStack_28}).
     */
    private static final Pattern AUTO_VAR_TOKEN = Pattern.compile(
        "\\b(?:[a-z]{1,5}Var\\d+|local_[0-9a-fA-F]+|[a-z]+Stack_[0-9a-fA-F]+)\\b");

    /**
     * Canonicalize auto-variable names to positional tokens ({@code V1}, {@code V2},
     * ... in first-appearance order within the line), preserving which positions
     * refer to the SAME variable. {@code param_N}, register names ({@code in_GS_OFFSET}),
     * constants and operators are untouched. Used only to decide whether a hunk's
     * sole difference is variable renumbering; never alters displayed text.
     */
    static String canonicalizeAutoVars(String line) {
        if (line == null || line.isEmpty()) {
            return line;
        }
        java.util.Map<String, String> order = new java.util.HashMap<>();
        java.util.regex.Matcher m = AUTO_VAR_TOKEN.matcher(line);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String canon = order.computeIfAbsent(m.group(), k -> "V" + (order.size() + 1));
            m.appendReplacement(sb, canon);
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * String-data label tokens (optionally {@code PTR_}-wrapped): {@code s_<...>}/
     * {@code u_<...>}. Their content can embed a per-build path (sanitizer/{@code __FILE__}
     * descriptors) that differs between builds but is non-semantic.
     */
    private static final Pattern STRING_LABEL_FULL = Pattern.compile(
        "\\b(?:PTR_)?[su]_[0-9A-Za-z_]+");

    /**
     * Replace whole string-label tokens with a constant so a hunk that differs only
     * inside string-label content can be detected. Classification only; never alters
     * displayed text.
     */
    static String maskStringLabel(String line) {
        if (line == null || line.isEmpty()) {
            return line;
        }
        return STRING_LABEL_FULL.matcher(line).replaceAll("STRLABEL");
    }

    /**
     * Result of a decompilation diff operation
     */
    public static class DiffResult {
        private final boolean hasChanges;
        private final List<ChangedLine> changedLines;
        private final String diffSummary;
        private final List<Map<String, Object>> snippets;
        private final Map<String, Integer> suppressedHunks;

        public DiffResult(boolean hasChanges, List<ChangedLine> changedLines,
                         String diffSummary, List<Map<String, Object>> snippets) {
            this(hasChanges, changedLines, diffSummary, snippets, new HashMap<>());
        }

        public DiffResult(boolean hasChanges, List<ChangedLine> changedLines,
                         String diffSummary, List<Map<String, Object>> snippets,
                         Map<String, Integer> suppressedHunks) {
            this.hasChanges = hasChanges;
            this.changedLines = changedLines;
            this.diffSummary = diffSummary;
            this.snippets = snippets;
            this.suppressedHunks = suppressedHunks;
        }

        public boolean hasChanges() { return hasChanges; }
        public List<ChangedLine> getChangedLines() { return changedLines; }
        public String getDiffSummary() { return diffSummary; }
        public List<Map<String, Object>> getSnippets() { return snippets; }
        public Map<String, Integer> getSuppressedHunks() { return suppressedHunks; }
    }

    /**
     * Represents a line that has changed between before/after decompilation
     */
    public static class ChangedLine {
        private final int lineNumber;
        private final String beforeContent;
        private final String afterContent;
        private final ChangeType changeType;

        public ChangedLine(int lineNumber, String beforeContent, String afterContent, ChangeType changeType) {
            this.lineNumber = lineNumber;
            this.beforeContent = beforeContent;
            this.afterContent = afterContent;
            this.changeType = changeType;
        }

        public int getLineNumber() { return lineNumber; }
        public String getBeforeContent() { return beforeContent; }
        public String getAfterContent() { return afterContent; }
        public ChangeType getChangeType() { return changeType; }
    }

    /**
     * Types of changes between decompilation results
     */
    public enum ChangeType {
        MODIFIED, ADDED, REMOVED
    }

    /**
     * Compare two decompilation strings and return a diff result with changed snippets
     * @param beforeDecomp The decompilation before changes
     * @param afterDecomp The decompilation after changes
     * @param contextLines Number of context lines to include around changes (default 2)
     * @return DiffResult containing changed lines and snippets
     */
    public static DiffResult createDiff(String beforeDecomp, String afterDecomp, int contextLines) {
        return createDiff(beforeDecomp, afterDecomp, contextLines, false);
    }

    /**
     * Compare two decompilation strings, optionally masking shifting load-address
     * suffixes so a relocated (linked) image does not report every {@code LAB_}/
     * {@code DAT_} rename as a change.
     *
     * @param beforeDecomp The decompilation before changes
     * @param afterDecomp The decompilation after changes
     * @param contextLines Number of context lines to include around changes
     * @param normalizeAddressShifts When true, two lines that differ only by a
     *        Ghidra default-name label's load-address suffix are treated as equal
     *        (see {@link #normalizeAddressTokens}). Snippets still show the
     *        original text; only the change-detection equality test is affected.
     * @return DiffResult containing changed lines and snippets
     */
    public static DiffResult createDiff(String beforeDecomp, String afterDecomp, int contextLines,
                                        boolean normalizeAddressShifts) {
        return createDiff(beforeDecomp, afterDecomp, contextLines, normalizeAddressShifts, false);
    }

    /**
     * As {@link #createDiff(String, String, int, boolean)} but, in the structural
     * (normalized) path, optionally expands decompiler-artifact hunks. When
     * {@code includeArtifactHunks} is false (default), hunks whose only difference is
     * variable renumbering or string-label content are collapsed (tagged + counted
     * under {@code suppressedHunks}, content omitted) so the genuine change is not buried.
     */
    public static DiffResult createDiff(String beforeDecomp, String afterDecomp, int contextLines,
                                        boolean normalizeAddressShifts, boolean includeArtifactHunks) {
        if (beforeDecomp == null) beforeDecomp = "";
        if (afterDecomp == null) afterDecomp = "";

        String[] beforeLines = beforeDecomp.split("\n");
        String[] afterLines = afterDecomp.split("\n");

        if (normalizeAddressShifts) {
            // Structural path: LCS-align the line sequences (matching by normalized
            // form) so a mid-body insertion does not misalign every following line,
            // and relocation renames collapse. This is the only flag-on behavior.
            return structuralDiff(beforeLines, afterLines, contextLines, includeArtifactHunks);
        }

        // Legacy index-based path — kept byte-identical for get-decompilation's
        // same-function before/after diffs (no relocation, no insertions to align).
        List<ChangedLine> changedLines = findChangedLines(beforeLines, afterLines, false);

        if (changedLines.isEmpty()) {
            return new DiffResult(false, changedLines, "No changes detected", new ArrayList<>());
        }

        List<Map<String, Object>> snippets = createSnippets(beforeLines, afterLines, changedLines, contextLines);
        String summary = createSummary(changedLines);

        return new DiffResult(true, changedLines, summary, snippets);
    }

    /** Upper bound on the LCS DP table (cells = before*after lines). Past this a
     *  function is large enough that the O(n*m) table is wasteful; fall back to the
     *  cheap index-based diff (which may cascade but never blows up memory). */
    private static final long MAX_LCS_CELLS = 4_000_000L;

    /**
     * Diff two line sequences by LCS alignment, comparing lines by their
     * address-normalized form (see {@link #normalizeAddressTokens}). Unlike the
     * index-based path, a single inserted line is reported as one ADDED line
     * instead of cascading into "everything after it changed". Produces
     * unified-diff hunks carrying separate before/after line ranges; the snippet
     * text is the ORIGINAL (un-normalized) source.
     */
    private static DiffResult structuralDiff(String[] before, String[] after, int contextLines,
                                             boolean includeArtifactHunks) {
        int n = before.length;
        int m = after.length;

        if ((long) n * m > MAX_LCS_CELLS) {
            // Too large for the DP table — degrade to the index-based diff.
            List<ChangedLine> cl = findChangedLines(before, after, true);
            if (cl.isEmpty()) {
                return new DiffResult(false, cl, "No changes detected", new ArrayList<>());
            }
            return new DiffResult(true, cl, createSummary(cl),
                createSnippets(before, after, cl, contextLines));
        }

        String[] nb = new String[n];
        for (int i = 0; i < n; i++) nb[i] = normalizeAddressTokens(before[i]);
        String[] na = new String[m];
        for (int j = 0; j < m; j++) na[j] = normalizeAddressTokens(after[j]);

        // Suffix-form LCS length table so a forward walk yields matched pairs in order.
        int[][] dp = new int[n + 1][m + 1];
        for (int i = n - 1; i >= 0; i--) {
            for (int j = m - 1; j >= 0; j--) {
                dp[i][j] = nb[i].equals(na[j])
                    ? dp[i + 1][j + 1] + 1
                    : Math.max(dp[i + 1][j], dp[i][j + 1]);
            }
        }

        List<ChangedLine> changedLines = new ArrayList<>();
        List<Map<String, Object>> snippets = new ArrayList<>();
        Map<String, Integer> suppressed = new HashMap<>();
        List<Integer> dels = new ArrayList<>();
        List<Integer> adds = new ArrayList<>();

        int i = 0, j = 0;
        while (i < n || j < m) {
            if (i < n && j < m && nb[i].equals(na[j])) {
                if (!dels.isEmpty() || !adds.isEmpty()) {
                    flushHunk(before, after, dels, adds, i, j, contextLines, changedLines, snippets,
                        includeArtifactHunks, suppressed);
                    dels.clear();
                    adds.clear();
                }
                i++;
                j++;
            } else if (i < n && (j >= m || dp[i + 1][j] >= dp[i][j + 1])) {
                dels.add(i++);   // before-only line (deletion)
            } else {
                adds.add(j++);   // after-only line (insertion)
            }
        }
        if (!dels.isEmpty() || !adds.isEmpty()) {
            flushHunk(before, after, dels, adds, n, m, contextLines, changedLines, snippets,
                includeArtifactHunks, suppressed);
        }

        if (changedLines.isEmpty() && snippets.isEmpty()) {
            return new DiffResult(false, changedLines, "No changes detected", new ArrayList<>(), suppressed);
        }
        // Summary counts only genuine (code) changes; artifact hunks are summarized separately.
        String summary = changedLines.isEmpty()
            ? "No semantic change (" + summarizeSuppressed(suppressed) + ")"
            : createSummary(changedLines);
        return new DiffResult(true, changedLines, summary, snippets, suppressed);
    }

    /** Human phrase for an all-artifact diff, e.g. "14 var-renumber, 6 string-label hunks suppressed". */
    private static String summarizeSuppressed(Map<String, Integer> suppressed) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Integer> e : suppressed.entrySet()) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(e.getValue()).append(' ').append(e.getKey());
        }
        sb.append(sb.length() > 0 ? " hunks suppressed" : "no changes");
        return sb.toString();
    }

    /**
     * Classify a hunk by what genuinely differs. A hunk that inserts/deletes lines
     * (unequal counts) is always {@code code}. Otherwise each MODIFIED pair is tested
     * under successive masks; if all pairs collapse under a mask the hunk is that
     * artifact class. {@code code} is shown in full; artifacts are collapsed by default.
     */
    private static String classifyHunk(List<Integer> dels, List<Integer> adds,
            String[] before, String[] after) {
        if (dels.size() != adds.size() || dels.isEmpty()) {
            return "code";
        }
        boolean allVar = true, allStr = true, allBoth = true;
        for (int k = 0; k < dels.size(); k++) {
            String b = normalizeAddressTokens(before[dels.get(k)]);
            String a = normalizeAddressTokens(after[adds.get(k)]);
            if (b.equals(a)) continue;
            if (!canonicalizeAutoVars(b).equals(canonicalizeAutoVars(a))) allVar = false;
            if (!maskStringLabel(b).equals(maskStringLabel(a))) allStr = false;
            if (!maskStringLabel(canonicalizeAutoVars(b)).equals(maskStringLabel(canonicalizeAutoVars(a)))) {
                allBoth = false;
            }
        }
        if (allVar) return "var-renumber";
        if (allStr) return "string-label";
        if (allBoth) return "artifact";
        return "code";
    }

    /**
     * Emit one unified-diff hunk from a contiguous gap of deleted/inserted lines.
     * Adjacent deletes and inserts are paired positionally into MODIFIED lines
     * (an in-place edit), leftover deletes become REMOVED and leftover inserts
     * ADDED. {@code beforeResume}/{@code afterResume} are the indices of the
     * matched line that closed the gap (or n/m at end of input), used to anchor
     * context for a pure insertion/deletion that has no lines on the other side.
     */
    private static void flushHunk(String[] before, String[] after,
            List<Integer> dels, List<Integer> adds, int beforeResume, int afterResume,
            int context, List<ChangedLine> changedLines, List<Map<String, Object>> snippets,
            boolean includeArtifactHunks, Map<String, Integer> suppressed) {
        String classification = classifyHunk(dels, adds, before, after);
        boolean artifact = !classification.equals("code");

        int paired = Math.min(dels.size(), adds.size());
        List<Integer> changedAfterLines = new ArrayList<>();
        // ChangedLine entries are itemized for code hunks only; artifact hunks are
        // summarized via suppressedHunks, not counted in the line-level summary.
        for (int k = 0; k < paired; k++) {
            int bi = dels.get(k);
            int aj = adds.get(k);
            if (!artifact) changedLines.add(new ChangedLine(aj + 1, before[bi], after[aj], ChangeType.MODIFIED));
            changedAfterLines.add(aj + 1);
        }
        for (int k = paired; k < dels.size(); k++) {
            int bi = dels.get(k);
            if (!artifact) changedLines.add(new ChangedLine(bi + 1, before[bi], "", ChangeType.REMOVED));
        }
        for (int k = paired; k < adds.size(); k++) {
            int aj = adds.get(k);
            if (!artifact) changedLines.add(new ChangedLine(aj + 1, "", after[aj], ChangeType.ADDED));
            changedAfterLines.add(aj + 1);
        }

        // Change spans on each side (hi < lo means "empty" — a pure insert/delete).
        int bLo = dels.isEmpty() ? beforeResume : dels.get(0);
        int bHi = dels.isEmpty() ? beforeResume - 1 : dels.get(dels.size() - 1);
        int aLo = adds.isEmpty() ? afterResume : adds.get(0);
        int aHi = adds.isEmpty() ? afterResume - 1 : adds.get(adds.size() - 1);

        int bStart = Math.max(0, bLo - context);
        int bEnd = Math.min(before.length - 1, bHi + context);
        int aStart = Math.max(0, aLo - context);
        int aEnd = Math.min(after.length - 1, aHi + context);

        Map<String, Object> snippet = new HashMap<>();
        snippet.put("classification", classification);
        // Back-compat: startLine/endLine mirror the after side.
        snippet.put("startLine", aStart + 1);
        snippet.put("endLine", aEnd + 1);
        snippet.put("beforeStartLine", bStart + 1);
        snippet.put("beforeEndLine", bEnd + 1);
        snippet.put("afterStartLine", aStart + 1);
        snippet.put("afterEndLine", aEnd + 1);
        snippet.put("changedLines", changedAfterLines.stream().mapToInt(Integer::intValue).toArray());

        if (artifact) {
            suppressed.merge(classification, 1, Integer::sum);
        }
        if (artifact && !includeArtifactHunks) {
            // Collapsed: keep ranges + classification, omit content.
            snippet.put("collapsed", true);
        } else {
            snippet.put("beforeContent", extractLines(before, bStart + 1, bEnd + 1));
            snippet.put("afterContent", extractLines(after, aStart + 1, aEnd + 1));
        }
        snippets.add(snippet);
    }

    /**
     * Convenience method with default context lines (2)
     */
    public static DiffResult createDiff(String beforeDecomp, String afterDecomp) {
        return createDiff(beforeDecomp, afterDecomp, 2);
    }

    /**
     * Find lines that have changed between before and after versions. When
     * {@code normalize} is true the equality test runs over address-normalized
     * forms (so pure relocation renames are not counted), but the ChangedLine
     * always carries the ORIGINAL line text for display.
     */
    private static List<ChangedLine> findChangedLines(String[] beforeLines, String[] afterLines,
                                                      boolean normalize) {
        List<ChangedLine> changes = new ArrayList<>();

        int maxLines = Math.max(beforeLines.length, afterLines.length);

        for (int i = 0; i < maxLines; i++) {
            String beforeLine = i < beforeLines.length ? beforeLines[i] : null;
            String afterLine = i < afterLines.length ? afterLines[i] : null;

            if (beforeLine == null && afterLine != null) {
                changes.add(new ChangedLine(i + 1, "", afterLine, ChangeType.ADDED));
            } else if (beforeLine != null && afterLine == null) {
                changes.add(new ChangedLine(i + 1, beforeLine, "", ChangeType.REMOVED));
            } else if (beforeLine != null && afterLine != null && !linesEqual(beforeLine, afterLine, normalize)) {
                changes.add(new ChangedLine(i + 1, beforeLine, afterLine, ChangeType.MODIFIED));
            }
        }

        return changes;
    }

    /** Line equality, masking shifting address suffixes when {@code normalize} is set. */
    private static boolean linesEqual(String a, String b, boolean normalize) {
        if (a.equals(b)) {
            return true;
        }
        return normalize && normalizeAddressTokens(a).equals(normalizeAddressTokens(b));
    }

    /**
     * Create snippets showing changed regions with context
     */
    private static List<Map<String, Object>> createSnippets(String[] beforeLines, String[] afterLines, 
                                                           List<ChangedLine> changedLines, int contextLines) {
        List<Map<String, Object>> snippets = new ArrayList<>();
        
        if (changedLines.isEmpty()) {
            return snippets;
        }

        // Group nearby changes into snippets
        List<List<ChangedLine>> changeGroups = groupNearbyChanges(changedLines, contextLines * 2);
        
        for (List<ChangedLine> group : changeGroups) {
            int firstChangeLine = group.get(0).getLineNumber();
            int lastChangeLine = group.get(group.size() - 1).getLineNumber();
            
            int snippetStart = Math.max(1, firstChangeLine - contextLines);
            int snippetEnd = Math.min(Math.max(beforeLines.length, afterLines.length), lastChangeLine + contextLines);
            
            Map<String, Object> snippet = new HashMap<>();
            snippet.put("startLine", snippetStart);
            snippet.put("endLine", snippetEnd);
            snippet.put("beforeContent", extractLines(beforeLines, snippetStart, snippetEnd));
            snippet.put("afterContent", extractLines(afterLines, snippetStart, snippetEnd));
            snippet.put("changedLines", group.stream().mapToInt(ChangedLine::getLineNumber).toArray());
            
            snippets.add(snippet);
        }
        
        return snippets;
    }

    /**
     * Group nearby changes to avoid creating too many small snippets
     */
    private static List<List<ChangedLine>> groupNearbyChanges(List<ChangedLine> changedLines, int maxGap) {
        List<List<ChangedLine>> groups = new ArrayList<>();
        
        if (changedLines.isEmpty()) {
            return groups;
        }
        
        List<ChangedLine> currentGroup = new ArrayList<>();
        currentGroup.add(changedLines.get(0));
        
        for (int i = 1; i < changedLines.size(); i++) {
            ChangedLine current = changedLines.get(i);
            ChangedLine previous = changedLines.get(i - 1);
            
            if (current.getLineNumber() - previous.getLineNumber() <= maxGap) {
                currentGroup.add(current);
            } else {
                groups.add(new ArrayList<>(currentGroup));
                currentGroup.clear();
                currentGroup.add(current);
            }
        }
        
        if (!currentGroup.isEmpty()) {
            groups.add(currentGroup);
        }
        
        return groups;
    }

    /**
     * Extract lines from an array with line numbers
     */
    private static String extractLines(String[] lines, int startLine, int endLine) {
        StringBuilder result = new StringBuilder();
        
        for (int i = startLine - 1; i < endLine && i < lines.length; i++) {
            result.append(String.format("%4d\t%s\n", i + 1, lines[i]));
        }
        
        return result.toString();
    }

    /**
     * Create a summary of changes
     */
    private static String createSummary(List<ChangedLine> changedLines) {
        long modified = changedLines.stream().mapToLong(c -> c.getChangeType() == ChangeType.MODIFIED ? 1 : 0).sum();
        long added = changedLines.stream().mapToLong(c -> c.getChangeType() == ChangeType.ADDED ? 1 : 0).sum();
        long removed = changedLines.stream().mapToLong(c -> c.getChangeType() == ChangeType.REMOVED ? 1 : 0).sum();
        
        StringBuilder summary = new StringBuilder();
        if (modified > 0) {
            summary.append(modified).append(" line").append(modified != 1 ? "s" : "").append(" modified");
        }
        if (added > 0) {
            if (summary.length() > 0) summary.append(", ");
            summary.append(added).append(" line").append(added != 1 ? "s" : "").append(" added");
        }
        if (removed > 0) {
            if (summary.length() > 0) summary.append(", ");
            summary.append(removed).append(" line").append(removed != 1 ? "s" : "").append(" removed");
        }
        
        return summary.toString();
    }

    /**
     * Create a Map representation suitable for JSON serialization
     */
    public static Map<String, Object> toMap(DiffResult diffResult) {
        Map<String, Object> result = new HashMap<>();
        result.put("hasChanges", diffResult.hasChanges());
        result.put("summary", diffResult.getDiffSummary());
        result.put("changedLineCount", diffResult.getChangedLines().size());
        result.put("snippets", diffResult.getSnippets());
        result.put("suppressedHunks", diffResult.getSuppressedHunks());

        return result;
    }
}