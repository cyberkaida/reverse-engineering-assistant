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
package reva.server;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Launcher for running ReVa MCP server in headless mode.
 * This class provides the main entry point for starting the MCP server
 * without requiring Ghidra's GUI plugin system.
 *
 * Designed to work with pyghidra and other headless Ghidra environments.
 *
 * Usage from pyghidra:
 * <pre>
 * import pyghidra
 * pyghidra.start()
 * from reva.server import HeadlessRevaLauncher
 * launcher = HeadlessRevaLauncher()
 * launcher.launch()
 * </pre>
 */
public class HeadlessRevaLauncher {
    private HeadlessMcpServerManager serverManager;
    private DefaultProjectManager projectManager;
    private Project project;
    private List<Program> openPrograms = new ArrayList<>();

    private String serverHost = "127.0.0.1";
    private int serverPort = 8080;

    /**
     * Default constructor using default configuration
     */
    public HeadlessRevaLauncher() {
        this("127.0.0.1", 8080);
    }

    /**
     * Constructor with custom server configuration
     * @param serverHost The host to bind to
     * @param serverPort The port to listen on
     */
    public HeadlessRevaLauncher(String serverHost, int serverPort) {
        this.serverHost = serverHost;
        this.serverPort = serverPort;
    }

    /**
     * Launch the MCP server in headless mode
     */
    public void launch() {
        Msg.info(this, "Launching ReVa in headless mode...");

        // Initialize the headless MCP server manager
        serverManager = new HeadlessMcpServerManager(serverHost, serverPort);

        // Start the server
        serverManager.startServer();

        // Wait for server to be ready
        int maxRetries = 50;
        int retries = 0;
        while (!serverManager.isServerReady() && retries < maxRetries) {
            try {
                Thread.sleep(100);
                retries++;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                Msg.error(this, "Interrupted while waiting for server to start");
                return;
            }
        }

        if (serverManager.isServerReady()) {
            Msg.info(this, "ReVa MCP server is running on http://" + serverHost + ":" + serverPort);
            Msg.info(this, "Server is ready to accept connections");
        } else {
            Msg.error(this, "Failed to start MCP server");
        }
    }

    /**
     * Open a Ghidra project and load programs
     * @param projectPath Path to the Ghidra project directory
     * @param projectName Name of the Ghidra project
     * @return The opened project
     * @throws IOException If project cannot be opened
     */
    public Project openProject(String projectPath, String projectName) throws IOException {
        Msg.info(this, "Opening project: " + projectName + " at " + projectPath);

        if (projectManager == null) {
            projectManager = new DefaultProjectManager();
        }

        File projectDir = new File(projectPath);
        ProjectLocator projectLocator = new ProjectLocator(projectDir.getAbsolutePath(), projectName);

        try {
            project = projectManager.openProject(projectLocator, false, false);
            Msg.info(this, "Project opened successfully: " + projectName);
            return project;
        } catch (Exception e) {
            Msg.error(this, "Failed to open project: " + projectName, e);
            throw new IOException("Failed to open project", e);
        }
    }

    /**
     * Open a program from the current project and register it with the MCP server
     * @param programPath The path to the program within the project (e.g., "/Hatchery.exe")
     * @return The opened program
     * @throws IOException If program cannot be opened
     */
    public Program openProgram(String programPath) throws IOException {
        if (project == null) {
            throw new IllegalStateException("No project is open. Call openProject() first.");
        }

        if (serverManager == null) {
            throw new IllegalStateException("Server not initialized. Call launch() first.");
        }

        Msg.info(this, "Opening program: " + programPath);

        try {
            ghidra.framework.model.DomainFile domainFile = project.getProjectData().getFile(programPath);
            if (domainFile == null) {
                throw new IOException("Program not found in project: " + programPath);
            }

            Program program = (Program) domainFile.getDomainObject(this, false, false, TaskMonitor.DUMMY);
            openPrograms.add(program);

            // Register the program with the MCP server
            serverManager.registerProgram(program);

            Msg.info(this, "Program opened and registered: " + program.getName());
            return program;
        } catch (Exception e) {
            Msg.error(this, "Failed to open program: " + programPath, e);
            throw new IOException("Failed to open program", e);
        }
    }

    /**
     * Close a program and unregister it from the MCP server
     * @param program The program to close
     */
    public void closeProgram(Program program) {
        if (program != null && openPrograms.contains(program)) {
            Msg.info(this, "Closing program: " + program.getName());

            // Unregister from MCP server
            if (serverManager != null) {
                serverManager.unregisterProgram(program);
            }

            // Close the program
            program.release(this);
            openPrograms.remove(program);

            Msg.info(this, "Program closed: " + program.getName());
        }
    }

    /**
     * Close the current project
     */
    public void closeProject() {
        if (project != null) {
            Msg.info(this, "Closing project: " + project.getName());

            // Close all open programs first
            for (Program program : new ArrayList<>(openPrograms)) {
                closeProgram(program);
            }

            project.close();
            project = null;

            Msg.info(this, "Project closed");
        }
    }

    /**
     * Shutdown the MCP server and clean up resources
     */
    public void shutdown() {
        Msg.info(this, "Shutting down ReVa headless launcher...");

        // Close any open programs and project
        closeProject();

        // Shutdown the server
        if (serverManager != null) {
            serverManager.shutdown();
            serverManager = null;
        }

        Msg.info(this, "ReVa headless launcher shutdown complete");
    }

    /**
     * Get the server manager instance
     * @return The headless MCP server manager
     */
    public HeadlessMcpServerManager getServerManager() {
        return serverManager;
    }

    /**
     * Get the current project
     * @return The current project, or null if no project is open
     */
    public Project getProject() {
        return project;
    }

    /**
     * Get the list of open programs
     * @return List of currently open programs
     */
    public List<Program> getOpenPrograms() {
        return new ArrayList<>(openPrograms);
    }

    /**
     * Check if the server is ready
     * @return true if the server is ready to accept connections
     */
    public boolean isServerReady() {
        return serverManager != null && serverManager.isServerReady();
    }

    /**
     * Block until the server shuts down.
     * Useful for keeping the JVM alive in standalone mode.
     */
    public void waitForShutdown() {
        if (serverManager != null) {
            serverManager.waitForShutdown();
        }
    }

    /**
     * Main method for standalone execution (not typically used with pyghidra)
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        Msg.info(HeadlessRevaLauncher.class, "Starting ReVa in headless mode...");
        Msg.info(HeadlessRevaLauncher.class, "Note: This requires Ghidra to be properly initialized.");
        Msg.info(HeadlessRevaLauncher.class, "For best results, use with pyghidra.");

        HeadlessRevaLauncher launcher = new HeadlessRevaLauncher();

        // Add shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            launcher.shutdown();
        }));

        launcher.launch();

        // Keep the server running
        launcher.waitForShutdown();
    }
}
