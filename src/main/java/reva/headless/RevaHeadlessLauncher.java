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
package reva.headless;

import java.io.File;
import java.io.IOException;

import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.model.Project;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.util.Msg;

import reva.plugin.ConfigManager;
import reva.server.McpServerManager;

/**
 * Headless launcher for ReVa MCP server.
 * <p>
 * This class enables ReVa to run in headless Ghidra mode without the GUI plugin system.
 * It can be invoked from pyghidra or other headless contexts.
 * <p>
 * Usage from pyghidra:
 * <pre>
 * from reva.headless import RevaHeadlessLauncher
 *
 * launcher = RevaHeadlessLauncher()
 * launcher.start()
 *
 * # Server is now running
 * if launcher.waitForServer(30000):
 *     print(f"Server ready on port {launcher.getPort()}")
 *
 * # Do work...
 *
 * launcher.stop()
 * </pre>
 */
public class RevaHeadlessLauncher {

    private McpServerManager serverManager;
    private ConfigManager configManager;
    private File configFile;
    private boolean autoInitializeGhidra;

    /**
     * Constructor with default settings (in-memory configuration)
     */
    public RevaHeadlessLauncher() {
        this(null, true);
    }

    /**
     * Constructor with configuration file
     * @param configFile The configuration file to load, or null for defaults
     */
    public RevaHeadlessLauncher(File configFile) {
        this(configFile, true);
    }

    /**
     * Constructor with full control
     * @param configFile The configuration file to load, or null for defaults
     * @param autoInitializeGhidra Whether to automatically initialize Ghidra if not already initialized
     */
    public RevaHeadlessLauncher(File configFile, boolean autoInitializeGhidra) {
        this.configFile = configFile;
        this.autoInitializeGhidra = autoInitializeGhidra;
    }

    /**
     * Start the MCP server in headless mode
     * @throws IOException if configuration file cannot be read
     * @throws IllegalStateException if Ghidra is not initialized and autoInitializeGhidra is false
     */
    public void start() throws IOException {
        Msg.info(this, "Starting ReVa MCP server in headless mode...");

        // Initialize Ghidra application if needed
        if (!Application.isInitialized()) {
            if (autoInitializeGhidra) {
                Msg.info(this, "Initializing Ghidra application in headless mode...");
                ApplicationConfiguration config = new HeadlessGhidraApplicationConfiguration();
                Application.initializeApplication(config);
                Msg.info(this, "Ghidra application initialized");
            } else {
                throw new IllegalStateException(
                    "Ghidra application is not initialized. " +
                    "Call Application.initializeApplication() first or set autoInitializeGhidra=true");
            }
        }

        // Create config manager based on mode
        if (configFile != null) {
            Msg.info(this, "Loading configuration from: " + configFile.getAbsolutePath());
            configManager = new ConfigManager(configFile);
        } else {
            Msg.info(this, "Using default configuration (in-memory)");
            configManager = new ConfigManager();
        }

        // Create and start server manager
        serverManager = new McpServerManager(configManager);
        serverManager.startServer();

        Msg.info(this, "ReVa MCP server started in headless mode");
    }

    /**
     * Stop the server and cleanup
     */
    public void stop() {
        Msg.info(this, "Stopping ReVa MCP server...");

        if (serverManager != null) {
            serverManager.shutdown();
            serverManager = null;
        }

        if (configManager != null) {
            configManager.dispose();
            configManager = null;
        }

        Msg.info(this, "ReVa MCP server stopped");
    }

    /**
     * Get the server port
     * @return The server port, or -1 if server is not running
     */
    public int getPort() {
        if (serverManager != null) {
            return serverManager.getServerPort();
        }
        return -1;
    }

    /**
     * Check if server is running
     * @return True if the server is running
     */
    public boolean isRunning() {
        return serverManager != null && serverManager.isServerRunning();
    }

    /**
     * Check if server is ready to accept connections
     * @return True if the server is ready
     */
    public boolean isServerReady() {
        return serverManager != null && serverManager.isServerReady();
    }

    /**
     * Wait for server to be ready
     * @param timeoutMs Maximum time to wait in milliseconds
     * @return True if server became ready within timeout, false otherwise
     */
    public boolean waitForServer(long timeoutMs) {
        long start = System.currentTimeMillis();
        while (System.currentTimeMillis() - start < timeoutMs) {
            if (isRunning() && isServerReady()) {
                return true;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    /**
     * Get the configuration manager
     * @return The configuration manager, or null if not started
     */
    public ConfigManager getConfigManager() {
        return configManager;
    }

    /**
     * Get the server manager
     * @return The server manager, or null if not started
     */
    public McpServerManager getServerManager() {
        return serverManager;
    }

    /**
     * Main method for standalone execution
     * <p>
     * Example usage:
     * <pre>
     * java -cp ... reva.headless.RevaHeadlessLauncher [configFile]
     * </pre>
     *
     * @param args Optional configuration file path as first argument
     */
    public static void main(String[] args) {
        // Parse arguments
        File configFile = null;
        if (args.length > 0) {
            configFile = new File(args[0]);
            if (!configFile.exists()) {
                System.err.println("Configuration file not found: " + configFile.getAbsolutePath());
                System.exit(1);
            }
        }

        // Create and start launcher
        RevaHeadlessLauncher launcher = new RevaHeadlessLauncher(configFile);

        try {
            launcher.start();

            // Wait for server to be ready
            if (launcher.waitForServer(30000)) {
                System.out.println("ReVa MCP server ready on port " + launcher.getPort());
                System.out.println("Press Ctrl+C to stop");

                // Add shutdown hook for clean exit
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    System.out.println("\nShutting down...");
                    launcher.stop();
                }));

                // Keep running until interrupted
                try {
                    Thread.currentThread().join();
                } catch (InterruptedException e) {
                    // Normal exit
                }
            } else {
                System.err.println("Failed to start server within timeout");
                System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("Error starting server: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
