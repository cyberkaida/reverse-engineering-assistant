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

import java.util.Collection;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import reva.server.McpServerManager;
import reva.services.RevaMcpService;
import reva.util.RevaInternalServiceRegistry;

/**
 * Helper class for integrating ReVa with PyGhidra scripts that work with multiple programs.
 * This class provides a simple API for PyGhidra scripts to register multiple programs
 * with ReVa's MCP server and make them available for analysis.
 */
public class ReVaPyGhidraSupport {
    
    private static McpServerManager serverManager;
    private static boolean initialized = false;

    /**
     * Initialize ReVa for multiple programs in PyGhidra context.
     * This method sets up the MCP server and registers all provided programs.
     * 
     * @param programs Collection of programs to make available via MCP
     */
    public static void initializeWithPrograms(Collection<Program> programs) {
        if (programs == null || programs.isEmpty()) {
            Msg.warn(ReVaPyGhidraSupport.class, "No programs provided for initialization");
            return;
        }

        Msg.info(ReVaPyGhidraSupport.class, 
            "Initializing ReVa PyGhidra support with " + programs.size() + " programs");

        // Set system property to indicate PyGhidra mode
        System.setProperty("pyghidra.mode", "true");

        // Register all programs with RevaProgramManager
        RevaProgramManager.registerPrograms(programs);

        // Ensure MCP server is running
        ensureMcpServerRunning();

        // Notify plugins about the programs
        RevaPlugin plugin = RevaInternalServiceRegistry.getService(RevaPlugin.class);
        if (plugin != null) {
            plugin.setPyGhidraPrograms(programs);
        }

        initialized = true;
        
        Msg.info(ReVaPyGhidraSupport.class, 
            "ReVa PyGhidra support initialized successfully - MCP server running");
        
        // Log available programs
        for (Program program : programs) {
            Msg.info(ReVaPyGhidraSupport.class, 
                "  Available program: " + program.getName() + " (" + program.getDomainFile().getPathname() + ")");
        }
    }

    /**
     * Add a single program to existing ReVa context.
     * Can be called after initializeWithPrograms() to add additional programs.
     * 
     * @param program The program to add
     */
    public static void addProgram(Program program) {
        if (program == null) {
            Msg.warn(ReVaPyGhidraSupport.class, "Cannot add null program");
            return;
        }

        // Register the program
        RevaProgramManager.registerProgram(program);

        // Notify plugin
        RevaPlugin plugin = RevaInternalServiceRegistry.getService(RevaPlugin.class);
        if (plugin != null) {
            plugin.addPyGhidraProgram(program);
        }

        Msg.info(ReVaPyGhidraSupport.class, 
            "Added program: " + program.getName() + " (" + program.getDomainFile().getPathname() + ")");
    }

    /**
     * Remove a program from ReVa context.
     * 
     * @param program The program to remove
     */
    public static void removeProgram(Program program) {
        if (program == null) {
            return;
        }

        RevaProgramManager.unregisterProgram(program);
        
        RevaPlugin plugin = RevaInternalServiceRegistry.getService(RevaPlugin.class);
        if (plugin != null) {
            plugin.programClosed(program);
        }

        Msg.info(ReVaPyGhidraSupport.class, 
            "Removed program: " + program.getName() + " (" + program.getDomainFile().getPathname() + ")");
    }

    /**
     * Get the MCP server URL for connecting clients.
     * 
     * @return The MCP server URL, or null if server is not running
     */
    public static String getMcpServerUrl() {
        if (serverManager != null) {
            return "http://localhost:" + serverManager.getServerPort();
        }
        return null;
    }

    /**
     * Check if ReVa PyGhidra support has been initialized.
     * 
     * @return true if initialized
     */
    public static boolean isInitialized() {
        return initialized;
    }

    /**
     * Clean up all programs and resources when done with PyGhidra analysis.
     * Call this when your PyGhidra script is finishing.
     */
    public static void cleanup() {
        Msg.info(ReVaPyGhidraSupport.class, "Cleaning up ReVa PyGhidra support");

        // Clean up program registries
        RevaProgramManager.cleanup();

        // Clear PyGhidra mode
        System.clearProperty("pyghidra.mode");

        // Shutdown MCP server if we started it
        if (serverManager != null) {
            serverManager.shutdown();
            serverManager = null;
        }

        initialized = false;
        
        Msg.info(ReVaPyGhidraSupport.class, "ReVa PyGhidra support cleanup complete");
    }

    /**
     * Ensure the MCP server is running.
     * This method will start the server if it's not already running.
     */
    private static void ensureMcpServerRunning() {
        // First try to get existing MCP service
        RevaMcpService mcpService = RevaInternalServiceRegistry.getService(RevaMcpService.class);
        
        if (mcpService != null && mcpService.isServerRunning()) {
            Msg.debug(ReVaPyGhidraSupport.class, "MCP server already running");
            return;
        }

        // Try to get server manager from service registry
        serverManager = RevaInternalServiceRegistry.getService(McpServerManager.class);
        
        if (serverManager == null) {
            // Create new server manager for PyGhidra mode
            serverManager = new McpServerManager(null); // No tool in PyGhidra mode
            RevaInternalServiceRegistry.registerService(McpServerManager.class, serverManager);
            RevaInternalServiceRegistry.registerService(RevaMcpService.class, serverManager);
        }

        // Start the server
        if (!serverManager.isServerRunning()) {
            serverManager.startServer();
            Msg.info(ReVaPyGhidraSupport.class, 
                "Started MCP server for PyGhidra mode on port " + serverManager.getServerPort());
        }
    }

    /**
     * Get information about the current PyGhidra session.
     * 
     * @return String with session information
     */
    public static String getSessionInfo() {
        if (!initialized) {
            return "ReVa PyGhidra support not initialized";
        }

        StringBuilder info = new StringBuilder();
        info.append("ReVa PyGhidra Session Information:\n");
        info.append("  Initialized: ").append(initialized).append("\n");
        info.append("  MCP Server URL: ").append(getMcpServerUrl()).append("\n");
        
        java.util.List<Program> programs = RevaProgramManager.getOpenPrograms();
        info.append("  Registered Programs: ").append(programs.size()).append("\n");
        
        for (Program program : programs) {
            info.append("    - ").append(program.getName())
                .append(" (").append(program.getDomainFile().getPathname()).append(")\n");
        }
        
        return info.toString();
    }
}