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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.Collection;

import ghidra.app.plugin.core.progmgr.ProgramLocator;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.task.ProgramOpener;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;
import reva.util.RevaInternalServiceRegistry;

/**
 * Manages access to open programs in Ghidra.
 * This is a singleton service that can be accessed throughout the application.
 */
public class RevaProgramManager {
    // Cache of opened programs by path to avoid repeatedly opening the same program
    private static final Map<String, Program> programCache = new ConcurrentHashMap<>();

    // Registry of directly opened programs (mainly for test environments and headless mode)
    private static final Map<String, Program> registeredPrograms = new ConcurrentHashMap<>();

    // Support multiple active programs simultaneously (for PyGhidra mode)
    private static final Map<String, Program> activePrograms = new ConcurrentHashMap<>();
    private static final List<Program> programList = new CopyOnWriteArrayList<>();

    /**
     * Check if we're running in headless mode
     * @return true if in headless mode
     */
    private static boolean isHeadlessMode() {
        return Boolean.getBoolean("java.awt.headless") || 
               Boolean.getBoolean(SystemUtilities.HEADLESS_PROPERTY);
    }

    /**
     * Register multiple programs from pyghidra script
     * @param programs Collection of programs to register
     */
    public static void registerPrograms(Collection<Program> programs) {
        for (Program program : programs) {
            registerProgram(program);
        }
        Msg.info(RevaProgramManager.class, "Registered " + programs.size() + " programs for multi-program access");
    }

    /**
     * Get all currently open programs in any Ghidra tool
     * @return List of open programs
     */
    public static List<Program> getOpenPrograms() {
        List<Program> openPrograms = new ArrayList<>();

        // In headless mode, return registered programs
        if (isHeadlessMode()) {
            openPrograms.addAll(programList);
            if (!openPrograms.isEmpty()) {
                Msg.debug(RevaProgramManager.class, "Returning " + openPrograms.size() + " programs from headless registry");
                return openPrograms;
            }
        }

        // GUI mode or fallback: try to get programs from the tool manager
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            Msg.debug(RevaProgramManager.class, "No active project found");
            return openPrograms;
        }

        // Fall back to existing tool-based program discovery
        openPrograms.addAll(getOpenProgramsFromTools());
        
        Msg.debug(RevaProgramManager.class, "Total open programs found: " + openPrograms.size());
        return openPrograms;
    }

    /**
     * Get programs from running tools (GUI mode)
     * @return List of programs from tools
     */
    private static List<Program> getOpenProgramsFromTools() {
        List<Program> openPrograms = new ArrayList<>();
        
        Project project = AppInfo.getActiveProject();
        if (project == null) {
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
            
            // Add to both legacy registry and new multi-program collections
            registeredPrograms.put(programPath, program);
            activePrograms.put(programPath, program);
            
            if (!programList.contains(program)) {
                programList.add(program);
            }
            
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
            
            // Remove from all collections
            registeredPrograms.remove(programPath);
            activePrograms.remove(programPath);
            programList.remove(program);
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
            
            // Remove from all collections  
            registeredPrograms.remove(programPath);
            activePrograms.remove(programPath);
            programList.remove(program);
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
     * Get a program by its path
     * @param programPath Path to the program
     * @return Program object or null if not found
     */
    public static Program getProgramByPath(String programPath) {
        if (programPath == null) {
            return null;
        }

        Msg.debug(RevaProgramManager.class, "Looking for program with path: " + programPath);

        // Check active programs first (for headless/PyGhidra environments)
        if (activePrograms.containsKey(programPath)) {
            Program activeProgram = activePrograms.get(programPath);
            if (!activeProgram.isClosed()) {
                Msg.debug(RevaProgramManager.class, "Found program in active registry: " + programPath);
                return activeProgram;
            } else {
                // Remove invalid programs from all registries
                activePrograms.remove(programPath);
                programList.remove(activeProgram);
                registeredPrograms.remove(programPath);
            }
        }

        // Check legacy registered programs (for test environments)
        if (registeredPrograms.containsKey(programPath)) {
            Program registeredProgram = registeredPrograms.get(programPath);
            if (!registeredProgram.isClosed()) {
                Msg.debug(RevaProgramManager.class, "Found program in registry: " + programPath);
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
                return program;
            }
        }

        // Get the DomainFile for the program path
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            Msg.warn(RevaProgramManager.class, "No active project");
            return null;
        }

        DomainFile domainFile = project.getProjectData().getRootFolder().getFile(programPath);
        if (domainFile == null) {
            Msg.warn(RevaProgramManager.class, "Could not find program: " + programPath);
            return null;
        }

        // Open the program
        ProgramOpener programOpener = new ProgramOpener(programCache);
        ProgramLocator locator = new ProgramLocator(domainFile);
        Program program = programOpener.openProgram(locator, TaskMonitor.DUMMY);

        if (program != null) {
            // Use canonical domain path as cache key for consistency
            String canonicalPath = getCanonicalProgramPath(program);
            programCache.put(canonicalPath, program);
        }

        return program;
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

        // Clear all program registries (but don't release them as we didn't open them)
        registeredPrograms.clear();
        activePrograms.clear();
        programList.clear();
        
        Msg.info(RevaProgramManager.class, "Cleaned up all program registries");
    }
}
