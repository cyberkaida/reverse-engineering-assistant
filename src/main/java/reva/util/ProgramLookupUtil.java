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
import java.util.List;
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
            throw new ProgramValidationException("Program path cannot be null or empty");
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
     * Build an error message with suggestions for available programs.
     * 
     * @param requestedPath The path that was requested but not found
     * @return A helpful error message with suggestions
     */
    private static String buildErrorMessageWithSuggestions(String requestedPath) {
        StringBuilder message = new StringBuilder();
        message.append("Program not found: ").append(requestedPath);

        // Get list of available programs
        List<String> availablePrograms = getAvailableProgramPaths();
        
        if (!availablePrograms.isEmpty()) {
            // Try to find similar programs
            List<String> suggestions = findSimilarPrograms(requestedPath, availablePrograms);
            
            if (!suggestions.isEmpty()) {
                message.append("\n\nDid you mean one of these?");
                for (String suggestion : suggestions) {
                    message.append("\n  - ").append(suggestion);
                }
            } else {
                message.append("\n\nAvailable programs:");
                for (String available : availablePrograms) {
                    message.append("\n  - ").append(available);
                }
            }
        } else {
            message.append("\n\nNo programs are currently available. ");
            message.append("Please open a program in Ghidra or check your project.");
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

        // First add all open programs
        List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
        for (Program prog : openPrograms) {
            if (prog != null && !prog.isClosed()) {
                paths.add(prog.getDomainFile().getPathname());
            }
        }

        // Then add programs from the project if available
        Project project = AppInfo.getActiveProject();
        if (project != null) {
            try {
                DomainFolder rootFolder = project.getProjectData().getRootFolder();
                collectProgramPaths(rootFolder, paths);
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
     */
    private static void collectProgramPaths(DomainFolder folder, List<String> paths) {
        // Add programs in this folder
        for (DomainFile file : folder.getFiles()) {
            if ("Program".equals(file.getContentType())) {
                paths.add(file.getPathname());
            }
        }

        // Recurse into subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            collectProgramPaths(subfolder, paths);
        }
    }

    /**
     * Find programs with similar names to the requested path.
     * 
     * @param requestedPath The path that was requested
     * @param availablePrograms List of available program paths
     * @return List of similar program paths (up to 3)
     */
    private static List<String> findSimilarPrograms(String requestedPath, List<String> availablePrograms) {
        List<String> suggestions = new ArrayList<>();
        
        // Normalize the requested path for comparison
        String normalizedRequest = requestedPath.toLowerCase();
        // Remove leading slash if present
        if (normalizedRequest.startsWith("/")) {
            normalizedRequest = normalizedRequest.substring(1);
        }
        
        // Look for programs that contain the requested name
        for (String available : availablePrograms) {
            String normalizedAvailable = available.toLowerCase();
            
            // Check if the available program contains the requested name
            if (normalizedAvailable.contains(normalizedRequest) || 
                normalizedRequest.contains(getFileName(normalizedAvailable))) {
                suggestions.add(available);
                if (suggestions.size() >= 3) {
                    break;
                }
            }
        }

        // If no contains matches, look for programs with similar file names
        if (suggestions.isEmpty()) {
            String requestedFileName = getFileName(normalizedRequest);
            for (String available : availablePrograms) {
                String availableFileName = getFileName(available.toLowerCase());
                if (availableFileName.contains(requestedFileName) || 
                    requestedFileName.contains(availableFileName)) {
                    suggestions.add(available);
                    if (suggestions.size() >= 3) {
                        break;
                    }
                }
            }
        }

        return suggestions;
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
        return path;
    }
}