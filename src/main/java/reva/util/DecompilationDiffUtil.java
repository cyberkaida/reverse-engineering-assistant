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

/**
 * Utility for comparing decompilation results and creating diffs/snippets of changed content
 */
public class DecompilationDiffUtil {

    /**
     * Result of a decompilation diff operation
     */
    public static class DiffResult {
        private final boolean hasChanges;
        private final List<ChangedLine> changedLines;
        private final String diffSummary;
        private final List<Map<String, Object>> snippets;

        public DiffResult(boolean hasChanges, List<ChangedLine> changedLines, 
                         String diffSummary, List<Map<String, Object>> snippets) {
            this.hasChanges = hasChanges;
            this.changedLines = changedLines;
            this.diffSummary = diffSummary;
            this.snippets = snippets;
        }

        public boolean hasChanges() { return hasChanges; }
        public List<ChangedLine> getChangedLines() { return changedLines; }
        public String getDiffSummary() { return diffSummary; }
        public List<Map<String, Object>> getSnippets() { return snippets; }
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
        if (beforeDecomp == null) beforeDecomp = "";
        if (afterDecomp == null) afterDecomp = "";

        String[] beforeLines = beforeDecomp.split("\n");
        String[] afterLines = afterDecomp.split("\n");

        List<ChangedLine> changedLines = findChangedLines(beforeLines, afterLines);
        
        if (changedLines.isEmpty()) {
            return new DiffResult(false, changedLines, "No changes detected", new ArrayList<>());
        }

        List<Map<String, Object>> snippets = createSnippets(beforeLines, afterLines, changedLines, contextLines);
        String summary = createSummary(changedLines);

        return new DiffResult(true, changedLines, summary, snippets);
    }

    /**
     * Convenience method with default context lines (2)
     */
    public static DiffResult createDiff(String beforeDecomp, String afterDecomp) {
        return createDiff(beforeDecomp, afterDecomp, 2);
    }

    /**
     * Find lines that have changed between before and after versions
     */
    private static List<ChangedLine> findChangedLines(String[] beforeLines, String[] afterLines) {
        List<ChangedLine> changes = new ArrayList<>();
        
        int maxLines = Math.max(beforeLines.length, afterLines.length);
        
        for (int i = 0; i < maxLines; i++) {
            String beforeLine = i < beforeLines.length ? beforeLines[i] : null;
            String afterLine = i < afterLines.length ? afterLines[i] : null;
            
            if (beforeLine == null && afterLine != null) {
                changes.add(new ChangedLine(i + 1, "", afterLine, ChangeType.ADDED));
            } else if (beforeLine != null && afterLine == null) {
                changes.add(new ChangedLine(i + 1, beforeLine, "", ChangeType.REMOVED));
            } else if (beforeLine != null && afterLine != null && !beforeLine.equals(afterLine)) {
                changes.add(new ChangedLine(i + 1, beforeLine, afterLine, ChangeType.MODIFIED));
            }
        }
        
        return changes;
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
        
        return result;
    }
}