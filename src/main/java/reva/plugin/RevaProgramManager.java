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
package reva.plugin;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.core.progmgr.ProgramLocator;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.task.ProgramOpener;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import reva.util.RevaInternalServiceRegistry;

/**
 * Manages access to open programs in Ghidra.
 * This is a singleton service that can be accessed throughout the application.
 */
public class RevaProgramManager {
    // Cache of opened programs by path to avoid repeatedly opening the same program
    private static final Map<String, Program> programCache = new HashMap<>();

    // Registry of directly opened programs (mainly for test environments)
    private static final Map<String, Program> registeredPrograms = new HashMap<>();

    /**
     * Get all currently open programs in any Ghidra tool
     * @return List of open programs
     */
    public static List<Program> getOpenPrograms() {
        List<Program> openPrograms = new ArrayList<>();

        // First try to get programs from the tool manager
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            Msg.debug(RevaProgramManager.class, "No active project found");
            return openPrograms;
        }

        ToolManager toolManager = project.getToolManager();
        if (toolManager != null) {
            PluginTool[] runningTools = toolManager.getRunningTools();
            Msg.debug(RevaProgramManager.class, "Found " + runningTools.length + " running tools");

            for (PluginTool tool : runningTools) {
                ProgramManager programManager = tool.getService(ProgramManager.class);
                if (programManager != null) {
                    Program[] programs = programManager.getAllOpenPrograms();
                    Msg.debug(RevaProgramManager.class, "Tool " + tool.getName() + " has " + programs.length + " open programs");
                    for (Program program : programs) {
                        if (!openPrograms.contains(program)) {
                            openPrograms.add(program);
                            Msg.debug(RevaProgramManager.class, "Added program: " + program.getName() + " with domain path: " + program.getDomainFile().getPathname());
                        }
                    }
                } else {
                    Msg.debug(RevaProgramManager.class, "Tool " + tool.getName() + " has no ProgramManager service");
                }
            }
        } else {
            Msg.debug(RevaProgramManager.class, "No tool manager found");
        }

        // If no tools were found (common in test environments),
        // try to get programs directly from the RevaPlugin's tool
        if (openPrograms.isEmpty()) {
            Msg.debug(RevaProgramManager.class, "No programs found via ToolManager, trying RevaPlugin tool");
            RevaPlugin revaPlugin = RevaInternalServiceRegistry.getService(RevaPlugin.class);
            if (revaPlugin != null && revaPlugin.getTool() != null) {
                PluginTool tool = revaPlugin.getTool();
                ProgramManager programManager = tool.getService(ProgramManager.class);
                if (programManager != null) {
                    Program[] programs = programManager.getAllOpenPrograms();
                    Msg.debug(RevaProgramManager.class, "RevaPlugin tool has " + programs.length + " open programs");
                    for (Program program : programs) {
                        if (!openPrograms.contains(program)) {
                            openPrograms.add(program);
                            Msg.debug(RevaProgramManager.class, "Added program from RevaPlugin: " + program.getName() + " with domain path: " + program.getDomainFile().getPathname());
                        }
                    }
                } else {
                    Msg.debug(RevaProgramManager.class, "RevaPlugin tool has no ProgramManager service");
                }
            } else {
                Msg.debug(RevaProgramManager.class, "RevaPlugin not found or has no tool");
            }
        }

        Msg.debug(RevaProgramManager.class, "Total open programs found: " + openPrograms.size());
        return openPrograms;
    }

    /**
     * Register a program directly with the manager. This is useful in test environments
     * or when programs are opened outside of the normal Ghidra tool system.
     * @param program The program to register
     */
    public static void registerProgram(Program program) {
        if (program != null && !program.isClosed()) {
            String programPath = program.getDomainFile().getPathname();
            registeredPrograms.put(programPath, program);
            Msg.debug(RevaProgramManager.class, "Registered program: " + programPath);
        }
    }

    /**
     * Unregister a program from the manager.
     * @param program The program to unregister
     */
    public static void unregisterProgram(Program program) {
        if (program != null) {
            String programPath = program.getDomainFile().getPathname();
            registeredPrograms.remove(programPath);
            programCache.remove(programPath);
            Msg.debug(RevaProgramManager.class, "Unregistered program: " + programPath);
        }
    }

    /**
     * Clear stale cache entries when a program is closed.
     * This should be called when a program is closed to prevent stale references.
     * @param program The program that was closed
     */
    public static void programClosed(Program program) {
        if (program != null) {
            String programPath = program.getDomainFile().getPathname();
            registeredPrograms.remove(programPath);
            programCache.remove(programPath);
            Msg.debug(RevaProgramManager.class, "Program closed, cleared cache: " + programPath);
        }
    }

    /**
     * Handle when a program is opened.
     * This ensures proper cache management and can be used to refresh stale entries.
     * @param program The program that was opened
     */
    public static void programOpened(Program program) {
        if (program != null && !program.isClosed()) {
            String programPath = program.getDomainFile().getPathname();
            // Clear any stale cache entry and let normal lookup repopulate
            programCache.remove(programPath);
            Msg.debug(RevaProgramManager.class, "Program opened, cleared stale cache: " + programPath);
        }
    }

    /**
     * Get the canonical domain path for a program
     * @param program The program to get the canonical path for
     * @return The canonical domain path
     */
    public static String getCanonicalProgramPath(Program program) {
        return program.getDomainFile().getPathname();
    }

    /**
     * Ensure a program is checked out if it's under version control.
     * This prevents the "Versioned File not Checked Out" dialog when making changes.
     * @param program The program to check out
     * @param programPath The path of the program (for logging)
     */
    private static void ensureCheckedOut(Program program, String programPath) {
        if (program == null) {
            return;
        }

        DomainFile domainFile = program.getDomainFile();
        Msg.debug(RevaProgramManager.class,
            "Program state - versioned: " + domainFile.isVersioned() +
            ", checked out: " + domainFile.isCheckedOut() +
            ", read-only: " + domainFile.isReadOnly());

        if (domainFile.isVersioned() && !domainFile.isCheckedOut()) {
            try {
                // Attempt non-exclusive checkout
                Msg.debug(RevaProgramManager.class,
                    "Attempting auto-checkout for: " + programPath);
                boolean success = domainFile.checkout(false, TaskMonitor.DUMMY);
                if (success) {
                    Msg.info(RevaProgramManager.class,
                        "Auto-checked out versioned program: " + programPath);
                } else {
                    Msg.warn(RevaProgramManager.class,
                        "Failed to auto-checkout versioned program: " + programPath +
                        " (may be checked out exclusively by another user)");
                }
            } catch (Exception e) {
                Msg.error(RevaProgramManager.class,
                    "Could not auto-checkout program " + programPath + ": " + e.getMessage(), e);
                // Continue anyway - program is still usable in read-only mode
            }
        }
    }

    /**
     * Get a program by its path
     * @param programPath Path to the program
     * @return Program object or null if not found
     */
    public static Program getProgramByPath(String programPath) {
        if (programPath == null) {
            return null;
        }

        Msg.debug(RevaProgramManager.class, "Looking for program with path: " + programPath);

        // Check registered programs first (for test environments)
        if (registeredPrograms.containsKey(programPath)) {
            Program registeredProgram = registeredPrograms.get(programPath);
            if (!registeredProgram.isClosed()) {
                Msg.debug(RevaProgramManager.class, "Found program in registry: " + programPath);
                ensureCheckedOut(registeredProgram, programPath);
                return registeredProgram;
            } else {
                // Remove invalid programs from registry
                registeredPrograms.remove(programPath);
            }
        }

        // Check cache next
        if (programCache.containsKey(programPath)) {
            Program cachedProgram = programCache.get(programPath);
            // Ensure the program is still valid
            if (!cachedProgram.isClosed()) {
                Msg.debug(RevaProgramManager.class, "Found program in cache: " + programPath);
                ensureCheckedOut(cachedProgram, programPath);
                return cachedProgram;
            } else {
                // Remove invalid programs from cache
                programCache.remove(programPath);
            }
        }

        // First try to find among open programs
        List<Program> openPrograms = getOpenPrograms();
        Msg.debug(RevaProgramManager.class, "Checking " + openPrograms.size() + " open programs");

        for (Program program : openPrograms) {
            // Check the Ghidra project path first (most common case)
            String domainPath = program.getDomainFile().getPathname();
            Msg.debug(RevaProgramManager.class, "Comparing '" + programPath + "' with domain path '" + domainPath + "'");
            if (domainPath.equals(programPath)) {
                // Use canonical domain path as cache key for consistency
                String canonicalPath = getCanonicalProgramPath(program);
                programCache.put(canonicalPath, program);
                Msg.debug(RevaProgramManager.class, "Found program by domain path: " + programPath);
                ensureCheckedOut(program, programPath);
                return program;
            }

            // Also check executable path and name for backward compatibility
            String executablePath = program.getExecutablePath();
            String programName = program.getName();
            Msg.debug(RevaProgramManager.class, "Also checking executable path '" + executablePath + "' and name '" + programName + "'");
            if (executablePath.equals(programPath) || programName.equals(programPath)) {
                // Use canonical domain path as cache key for consistency
                String canonicalPath = getCanonicalProgramPath(program);
                programCache.put(canonicalPath, program);
                Msg.debug(RevaProgramManager.class, "Found program by executable path or name: " + programPath);
                ensureCheckedOut(program, programPath);
                return program;
            }
        }

        // Get the DomainFile for the program path
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            Msg.warn(RevaProgramManager.class, "No active project");
            return null;
        }

        // Handle paths that may include folders (e.g., "/imported/program.exe")
        DomainFile domainFile = null;
        
        if (programPath.startsWith("/")) {
            // Remove leading slash for processing
            String relativePath = programPath.substring(1);
            int lastSlash = relativePath.lastIndexOf('/');
            
            if (lastSlash > 0) {
                // Path contains folders - need to get the folder first, then the file
                String folderPath = "/" + relativePath.substring(0, lastSlash);
                String fileName = relativePath.substring(lastSlash + 1);
                
                DomainFolder folder = project.getProjectData().getFolder(folderPath);
                if (folder != null) {
                    domainFile = folder.getFile(fileName);
                }
            } else {
                // No folders, file is directly in root
                domainFile = project.getProjectData().getRootFolder().getFile(relativePath);
            }
        } else {
            // Handle paths without leading slash
            domainFile = project.getProjectData().getRootFolder().getFile(programPath);
        }

        if (domainFile == null) {
            Msg.warn(RevaProgramManager.class, "Could not find program: " + programPath);
            return null;
        }

        // Open the program
        ProgramOpener programOpener = new ProgramOpener(programCache);
        ProgramLocator locator = new ProgramLocator(domainFile);
        Program program = programOpener.openProgram(locator, TaskMonitor.DUMMY);

        if (program != null) {
            // Ensure the program is checked out if versioned
            ensureCheckedOut(program, programPath);

            // Use canonical domain path as cache key for consistency
            String canonicalPath = getCanonicalProgramPath(program);
            programCache.put(canonicalPath, program);
        }

        return program;
    }

    /**
     * Check if a program is currently held in the cache as a consumer
     * @param program The program to check
     * @return true if the program is in the cache
     */
    public static boolean isProgramCached(Program program) {
        if (program == null || program.isClosed()) {
            return false;
        }
        String canonicalPath = getCanonicalProgramPath(program);
        return programCache.containsKey(canonicalPath) &&
               programCache.get(canonicalPath) == program;
    }

    /**
     * Release a program from the cache, removing it as a consumer.
     * This is needed before version control operations which require no active consumers.
     * @param program The program to release from cache
     * @return true if the program was in the cache and released, false otherwise
     */
    public static boolean releaseProgramFromCache(Program program) {
        if (program == null || program.isClosed()) {
            return false;
        }

        String canonicalPath = getCanonicalProgramPath(program);
        Program cachedProgram = programCache.remove(canonicalPath);

        if (cachedProgram != null && cachedProgram == program) {
            Msg.debug(RevaProgramManager.class,
                "Releasing program from cache: " + canonicalPath);
            program.release(programCache);
            return true;
        }

        return false;
    }

    /**
     * Re-open a program and add it back to the cache after it was released.
     * This restores the cache state after operations that required releasing the program.
     * @param programPath The path to the program to re-open
     * @return The re-opened program, or null if it could not be opened
     */
    public static Program reopenProgramToCache(String programPath) {
        if (programPath == null) {
            return null;
        }

        Msg.debug(RevaProgramManager.class,
            "Re-opening program to cache: " + programPath);

        // Clear any existing cache entry first
        programCache.remove(programPath);

        // Use getProgramByPath which will open and cache the program
        return getProgramByPath(programPath);
    }

    /**
     * Clean up and release any resources
     */
    public static void cleanup() {
        // Close any programs we opened
        for (Program program : programCache.values()) {
            if (program != null && !program.isClosed()) {
                program.release(programCache);
            }
        }
        programCache.clear();

        // Clear registered programs (but don't release them as we didn't open them)
        registeredPrograms.clear();
    }
}
