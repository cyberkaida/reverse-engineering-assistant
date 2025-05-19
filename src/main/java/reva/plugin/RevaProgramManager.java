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
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Manages access to open programs in Ghidra.
 * This is a singleton service that can be accessed throughout the application.
 */
public class RevaProgramManager {
    // Cache of opened programs by path to avoid repeatedly opening the same program
    private static final Map<String, Program> programCache = new HashMap<>();

    /**
     * Get all currently open programs in any Ghidra tool
     * @return List of open programs
     */
    public static List<Program> getOpenPrograms() {
        List<Program> openPrograms = new ArrayList<>();

        // Get all tools from the tool manager
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            return openPrograms;
        }

        ToolManager toolManager = project.getToolManager();
        if (toolManager != null) {
            for (PluginTool tool : toolManager.getRunningTools()) {
                ProgramManager programManager = tool.getService(ProgramManager.class);
                if (programManager != null) {
                    Program[] programs = programManager.getAllOpenPrograms();
                    for (Program program : programs) {
                        if (!openPrograms.contains(program)) {
                            openPrograms.add(program);
                        }
                    }
                }
            }
        }

        return openPrograms;
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

        // Check cache first
        if (programCache.containsKey(programPath)) {
            Program cachedProgram = programCache.get(programPath);
            // Ensure the program is still valid
            if (!cachedProgram.isClosed()) {
                return cachedProgram;
            } else {
                // Remove invalid programs from cache
                programCache.remove(programPath);
            }
        }

        // First try to find among open programs
        List<Program> openPrograms = getOpenPrograms();
        for (Program program : openPrograms) {
            if (program.getExecutablePath().equals(programPath) ||
                program.getName().equals(programPath)) {
                // Add to cache for future lookups
                programCache.put(programPath, program);
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
            // Add to cache for future lookups
            programCache.put(programPath, program);
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
    }
}
