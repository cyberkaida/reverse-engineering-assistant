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
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import reva.plugin.RevaProgramManager;
import reva.tools.ProgramValidationException;

/**
 * Utility class for consistent program lookup across all ReVa tools.
 * Provides helpful error messages with suggestions when programs cannot be found.
 */
public class ProgramLookupUtil {

    /**
     * Get a validated program by its path with helpful error messages.
     * This method first attempts to find the program using RevaProgramManager,
     * and if that fails, provides a helpful error message with available programs.
     * 
     * @param programPath The path to the program (e.g., "/Hatchery.exe")
     * @return A valid Program object
     * @throws ProgramValidationException if the program cannot be found or is invalid
     */
    public static Program getValidatedProgram(String programPath) throws ProgramValidationException {
        if (programPath == null || programPath.trim().isEmpty()) {
            return resolveSoleOpenProgram();
        }

        // A configured analysis snapshot is bookkeeping, never a program the
        // model may address; say so before the generic not-found suggestions,
        // which would only repeat the snapshot's own path.
        String snapshotFolder = ProjectSnapshots.configuredFolder();
        if (!snapshotFolder.isEmpty()
                && ProjectSnapshots.isSnapshotPath(programPath, snapshotFolder)) {
            throw new ProgramValidationException(
                "Invalid programPath: configured analysis snapshots are not addressable ("
                    + programPath + "). Use the program itself.");
        }

        // First try the standard lookup
        Program program = RevaProgramManager.getProgramByPath(programPath);
        if (program != null && !program.isClosed()) {
            return program;
        }

        // If not found, build a helpful error message with suggestions
        String errorMessage = buildErrorMessageWithSuggestions(programPath);
        throw new ProgramValidationException(errorMessage);
    }

    /**
     * Resolve the only program, for calls that omit programPath.
     * Programs ReVa knows to be open come first. When none is open (headless, right
     * after import-file saved a program without opening it, or after checkin-program
     * released it), the project's program files are used instead: exactly one is
     * opened (and cached) and returned. Never picks for the caller when several
     * exist: the error lists them instead.
     *
     * @return the single open, non-closed program
     * @throws ProgramValidationException if none or several programs are open or in the project
     */
    public static Program resolveSoleOpenProgram() throws ProgramValidationException {
        List<Program> known = RevaProgramManager.getAllKnownPrograms();
        if (!openOnly(known).isEmpty()) {
            return resolveSoleOpenProgram(known);
        }
        // Serialised so two concurrent calls do not both open the same file.
        synchronized (ProgramLookupUtil.class) {
            known = RevaProgramManager.getAllKnownPrograms();
            if (!openOnly(known).isEmpty()) {
                return resolveSoleOpenProgram(known);
            }
            List<String> projectPrograms = getProjectProgramPaths();
            if (projectPrograms.size() > 1) {
                throw severalPrograms(projectPrograms);
            }
            if (projectPrograms.size() == 1) {
                String path = projectPrograms.get(0);
                Program program = RevaProgramManager.getProgramByPath(path);
                if (program == null || program.isClosed()) {
                    throw new ProgramValidationException(
                        "Could not open " + path + ", the only program in the project.");
                }
                return program;
            }
        }
        return resolveSoleOpenProgram(known);
    }

    /**
     * Same as {@link #resolveSoleOpenProgram()} over an explicit list of open programs,
     * without the project fallback.
     */
    static Program resolveSoleOpenProgram(List<Program> openPrograms) throws ProgramValidationException {
        List<Program> open = openOnly(openPrograms);
        if (open.isEmpty()) {
            throw new ProgramValidationException("No program is open. Import one with import-file.");
        }
        if (open.size() == 1) {
            return open.get(0);
        }
        List<String> paths = new ArrayList<>();
        for (Program p : open) {
            paths.add(RevaProgramManager.getCanonicalProgramPath(p));
        }
        throw severalPrograms(paths);
    }

    private static List<Program> openOnly(List<Program> programs) {
        String snapshotFolder = ProjectSnapshots.configuredFolder();
        List<Program> open = new ArrayList<>();
        for (Program p : programs) {
            if (p != null && !p.isClosed() && isAddressable(p, snapshotFolder)) {
                open.add(p);
            }
        }
        return open;
    }

    /** A configured analysis snapshot is never a program the model may resolve or be offered. */
    private static boolean isAddressable(Program program, String snapshotFolder) {
        return snapshotFolder.isEmpty()
            || !ProjectSnapshots.isSnapshotPath(
                RevaProgramManager.getCanonicalProgramPath(program), snapshotFolder);
    }

    private static ProgramValidationException severalPrograms(List<String> paths) {
        StringBuilder message = new StringBuilder("programPath is required when several programs are open:");
        for (String path : paths) {
            message.append("\n  - ").append(path);
        }
        return new ProgramValidationException(message.toString());
    }

    /**
     * Program files in the active project, sorted by path; empty when there is no project.
     */
    private static List<String> getProjectProgramPaths() {
        List<String> paths = new ArrayList<>();
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            return paths;
        }
        try {
            collectProgramPaths(project.getProjectData().getRootFolder(), paths,
                ProjectSnapshots.configuredFolder());
        } catch (Exception e) {
            Msg.debug(ProgramLookupUtil.class, "Error collecting project programs: " + e.getMessage());
        }
        return paths.stream().distinct().sorted().collect(Collectors.toList());
    }

    /**
     * Build an error message that lists the closest programs first.
     *
     * @param requestedPath The path that was requested but not found
     * @return A helpful error message with suggestions
     */
    private static String buildErrorMessageWithSuggestions(String requestedPath) {
        return buildErrorMessageWithSuggestions(requestedPath, getAvailableProgramPaths());
    }

    static String buildErrorMessageWithSuggestions(String requestedPath, List<String> availablePrograms) {
        StringBuilder message = new StringBuilder();
        message.append("Program not found: ").append(requestedPath);

        if (availablePrograms.isEmpty()) {
            message.append("\n\nNo programs are currently available. ");
            message.append("Please open a program in Ghidra or check your project.");
            return message.toString();
        }

        List<String> ranked = rankBySimilarity(requestedPath, availablePrograms);
        message.append("\n\nDid you mean (closest first)?");
        for (String suggestion : ranked.subList(0, Math.min(MAX_SUGGESTIONS, ranked.size()))) {
            message.append("\n  - ").append(suggestion);
        }
        if (ranked.size() > MAX_SUGGESTIONS) {
            message.append("\n\nAll programs (").append(ranked.size()).append("):");
            for (String path : ranked) {
                message.append("\n  - ").append(path);
            }
        }
        return message.toString();
    }

    /**
     * Get a list of all available program paths.
     * This includes both open programs and programs in the project.
     * 
     * @return List of available program paths
     */
    private static List<String> getAvailableProgramPaths() {
        List<String> paths = new ArrayList<>();
        String snapshotFolder = ProjectSnapshots.configuredFolder();

        // First add all open programs
        List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
        for (Program prog : openPrograms) {
            if (prog != null && !prog.isClosed() && isAddressable(prog, snapshotFolder)) {
                paths.add(prog.getDomainFile().getPathname());
            }
        }

        // Then add programs from the project if available
        Project project = AppInfo.getActiveProject();
        if (project != null) {
            try {
                DomainFolder rootFolder = project.getProjectData().getRootFolder();
                collectProgramPaths(rootFolder, paths, snapshotFolder);
            } catch (Exception e) {
                Msg.debug(ProgramLookupUtil.class, "Error collecting project programs: " + e.getMessage());
            }
        }

        // Remove duplicates and sort
        return paths.stream()
            .distinct()
            .sorted()
            .collect(Collectors.toList());
    }

    /**
     * Recursively collect program paths from a domain folder.
     * 
     * @param folder The folder to search
     * @param paths The list to add paths to
     * @param snapshotFolder configured snapshot folder to skip, or {@code ""}
     */
    private static void collectProgramPaths(DomainFolder folder, List<String> paths,
            String snapshotFolder) {
        // Add programs in this folder
        for (DomainFile file : folder.getFiles()) {
            if ("Program".equals(file.getContentType())) {
                paths.add(file.getPathname());
            }
        }

        // Recurse into subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            if (!snapshotFolder.isEmpty()
                    && ProjectSnapshots.isSnapshotPath(subfolder.getPathname(), snapshotFolder)) {
                continue;
            }
            collectProgramPaths(subfolder, paths, snapshotFolder);
        }
    }

    private static final int MAX_SUGGESTIONS = 3;

    // Score tiers; a tier's score is tier + a fraction in [0, 1).
    private static final double TIER_EXACT = 5;
    private static final double TIER_ELLIPSIS = 4;
    private static final double TIER_PREFIX = 3;
    private static final double TIER_SUBSTRING = 2;

    /**
     * Sort every available path by how closely it matches the requested one, best first.
     * File names are compared (directories and a trailing extension are ignored), case-insensitively:
     * exact match, then "prefix...suffix" ellipsis match, then prefix match (longer common prefix
     * first), then substring either way, then normalised Levenshtein similarity. Ties fall back to
     * full-path similarity, then alphabetical order.
     */
    static List<String> rankBySimilarity(String requested, List<String> available) {
        String request = requested == null ? "" : requested.trim().toLowerCase().replace("\u2026", "...");
        List<String> requestNames = nameVariants(getFileName(request));
        List<String> ranked = new ArrayList<>(available);
        Map<String, double[]> scores = new HashMap<>();
        for (String path : ranked) {
            String lowerPath = path.toLowerCase();
            double primary = 0;
            for (String name : nameVariants(getFileName(lowerPath))) {
                for (String requestName : requestNames) {
                    primary = Math.max(primary, scoreName(requestName, name));
                }
            }
            if (!request.isEmpty() && lowerPath.equals(request)) {
                primary = Math.max(primary, TIER_EXACT);
            }
            scores.put(path, new double[] { primary, similarity(request, lowerPath) });
        }
        ranked.sort(Comparator
            .comparingDouble((String p) -> -scores.get(p)[0])
            .thenComparingDouble(p -> -scores.get(p)[1])
            .thenComparing(Comparator.naturalOrder()));
        return ranked;
    }

    private static double scoreName(String request, String candidate) {
        if (request.isEmpty() || candidate.isEmpty()) {
            return 0;
        }
        if (request.equals(candidate)) {
            return TIER_EXACT;
        }
        int ellipsis = request.indexOf("...");
        if (ellipsis >= 0) {
            String prefix = request.substring(0, ellipsis);
            String suffix = request.substring(ellipsis + 3);
            if (candidate.length() >= prefix.length() + suffix.length()
                && candidate.startsWith(prefix) && candidate.endsWith(suffix)) {
                return TIER_ELLIPSIS;
            }
            // pattern missed: keep scoring on the part the model most likely got right
            request = prefix;
            if (request.isEmpty()) {
                return 0;
            }
        }
        if (candidate.startsWith(request)) {
            return TIER_PREFIX + (double) request.length() / (candidate.length() + 1);
        }
        int common = commonPrefixLength(request, candidate);
        if (common > 0 && request.startsWith(candidate)) {
            return TIER_PREFIX + (double) common / (request.length() + 1);
        }
        if (candidate.contains(request) || request.contains(candidate)) {
            return TIER_SUBSTRING + (double) Math.min(request.length(), candidate.length())
                / (Math.max(request.length(), candidate.length()) + 1);
        }
        return similarity(request, candidate);
    }

    /** The name, plus the name without a short trailing extension when it has one. */
    private static List<String> nameVariants(String name) {
        int dot = name.lastIndexOf('.');
        if (dot > 0 && name.length() - dot - 1 <= 4 && name.charAt(dot - 1) != '.') {
            return List.of(name, name.substring(0, dot));
        }
        return List.of(name);
    }

    private static int commonPrefixLength(String a, String b) {
        int n = Math.min(a.length(), b.length());
        int i = 0;
        while (i < n && a.charAt(i) == b.charAt(i)) {
            i++;
        }
        return i;
    }

    /** 1 - Levenshtein distance / longer length; 1 for two empty strings. */
    private static double similarity(String a, String b) {
        int max = Math.max(a.length(), b.length());
        if (max == 0) {
            return 1;
        }
        int[] previous = new int[b.length() + 1];
        int[] current = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) {
            previous[j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            current[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                current[j] = Math.min(Math.min(current[j - 1] + 1, previous[j] + 1), previous[j - 1] + cost);
            }
            int[] swap = previous;
            previous = current;
            current = swap;
        }
        return 1.0 - (double) previous[b.length()] / max;
    }

    /**
     * Extract the file name from a path.
     *
     * @param path The full path
     * @return The file name portion
     */
    private static String getFileName(String path) {
        int lastSlash = path.lastIndexOf('/');
        if (lastSlash >= 0 && lastSlash < path.length() - 1) {
            return path.substring(lastSlash + 1);
        }
        return lastSlash >= 0 ? "" : path;
    }
}
