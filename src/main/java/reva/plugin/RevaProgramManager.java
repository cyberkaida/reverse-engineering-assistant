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
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

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
     * Get all currently open programs from all sources (registered, active, and tool programs)
     * @return List of open programs
     */
    public static List<Program> getOpenPrograms() {
        Set<Program> allPrograms = new HashSet<>();
        
        // Include all registered programs (test environments, direct registration)
        allPrograms.addAll(registeredPrograms.values());
        allPrograms.addAll(activePrograms.values());
        allPrograms.addAll(programList);
        
        // Add programs from running tools (GUI mode)
        allPrograms.addAll(getOpenProgramsFromTools());
        
        // Filter out closed programs and convert to list
        List<Program> openPrograms = allPrograms.stream()
            .filter(p -> p != null && !p.isClosed())
            .collect(Collectors.toList());
        
        Msg.debug(RevaProgramManager.class, "Total open programs: " + openPrograms.size());
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
            String programPath = getCanonicalProgramPath(program);
            
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
            String programPath = getCanonicalProgramPath(program);
            
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
            String programPath = getCanonicalProgramPath(program);
            
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
            String programPath = getCanonicalProgramPath(program);
            // Clear any stale cache entry and let normal lookup repopulate
            programCache.remove(programPath);
            Msg.debug(RevaProgramManager.class, "Program opened, cleared stale cache: " + programPath);
        }
    }

    /**
     * Get the canonical path for a program that can be used for consistent identification.
     * 
     * Returns the Ghidra domain file pathname for regular programs, or falls back to
     * the program name for test programs that don't have domain files.
     * 
     * @param program The program to get the canonical path for
     * @return The canonical path string, never null
     * @throws IllegalArgumentException if program is null
     */
    public static String getCanonicalProgramPath(Program program) {
        if (program == null) {
            throw new IllegalArgumentException("Program cannot be null");
        }
        if (program.getDomainFile() != null) {
            return program.getDomainFile().getPathname();
        } else {
            // Handle test programs that don't have domain files
            return program.getName();
        }
    }

    /**
     * Get a program by its path using unified lookup strategy.
     * 
     * Supports multiple path formats:
     * - Domain paths: "/Hatchery.exe" (standard Ghidra project paths)
     * - Executable paths: "/path/to/binary" (filesystem paths)  
     * - Program names: "Hatchery.exe" (program display names)
     * - Test patterns: "/<program_name>" (test environment convention)
     * - Special keyword: "current" (first available program)
     * 
     * @param programPath Path to the program in any supported format
     * @return Program object or null if not found
     */
    public static Program getProgramByPath(String programPath) {
        if (programPath == null) {
            return null;
        }
        
        Msg.debug(RevaProgramManager.class, "Looking for program: " + programPath);
        
        // Handle "current" keyword - return first available program
        if ("current".equals(programPath)) {
            List<Program> openPrograms = getOpenPrograms();
            if (!openPrograms.isEmpty()) {
                Program current = openPrograms.get(0);
                Msg.debug(RevaProgramManager.class, "Found current program: " + getCanonicalProgramPath(current));
                return current;
            } else {
                Msg.warn(RevaProgramManager.class, "No programs available for 'current' keyword");
                return null;
            }
        }
        
        // Check cache first for performance (thread-safe)
        Program cached = programCache.get(programPath);
        if (cached != null && !cached.isClosed()) {
            Msg.debug(RevaProgramManager.class, "Found program in cache: " + programPath);
            return cached;
        }
        
        // Get all open programs (includes registered, active, and tool programs)
        List<Program> openPrograms = getOpenPrograms();
        Msg.debug(RevaProgramManager.class, "Checking " + openPrograms.size() + " open programs");
        
        // Try different lookup strategies against all open programs
        for (Program program : openPrograms) {
            Program found = tryLookupByCanonicalPath(program, programPath);
            if (found != null) return found;
            
            found = tryLookupByExecutablePath(program, programPath);
            if (found != null) return found;
            
            found = tryLookupByProgramName(program, programPath);
            if (found != null) return found;
            
            found = tryLookupByTestPattern(program, programPath);
            if (found != null) return found;
        }
        
        // If not found in open programs, try to open from project
        return tryOpenFromProject(programPath);
    }

    /**
     * Try to find program by canonical path (exact match)
     */
    private static Program tryLookupByCanonicalPath(Program program, String programPath) {
        String canonicalPath = getCanonicalProgramPath(program);
        Msg.debug(RevaProgramManager.class, "Comparing '" + programPath + "' with canonical path '" + canonicalPath + "'");
        if (canonicalPath.equals(programPath)) {
            programCache.computeIfAbsent(programPath, k -> program);
            Msg.debug(RevaProgramManager.class, "Found program by canonical path: " + programPath);
            return program;
        }
        return null;
    }

    /**
     * Try to find program by executable path (backward compatibility)
     */
    private static Program tryLookupByExecutablePath(Program program, String programPath) {
        if (program.getDomainFile() != null) {
            String execPath = program.getExecutablePath();
            if (execPath != null && execPath.equals(programPath)) {
                programCache.computeIfAbsent(programPath, k -> program);
                Msg.debug(RevaProgramManager.class, "Found program by executable path: " + programPath);
                return program;
            }
        }
        return null;
    }

    /**
     * Try to find program by program name (fallback)
     */
    private static Program tryLookupByProgramName(Program program, String programPath) {
        if (program.getName() != null && program.getName().equals(programPath)) {
            programCache.computeIfAbsent(programPath, k -> program);
            Msg.debug(RevaProgramManager.class, "Found program by program name: " + programPath);
            return program;
        }
        return null;
    }

    /**
     * Try to find program by test pattern "/<program_name>" (test environment)
     */
    private static Program tryLookupByTestPattern(Program program, String programPath) {
        if (programPath.startsWith("/") && program.getName() != null && 
            program.getName().equals(programPath.substring(1))) {
            programCache.computeIfAbsent(programPath, k -> program);
            Msg.debug(RevaProgramManager.class, "Found program by test path pattern: " + programPath);
            return program;
        }
        return null;
    }

    /**
     * Try to open a program from the active project
     * @param programPath Path to the program to open
     * @return Program object or null if not found
     */
    private static Program tryOpenFromProject(String programPath) {
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
