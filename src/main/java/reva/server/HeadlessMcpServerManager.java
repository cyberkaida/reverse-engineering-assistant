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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.RevaProgramManager;
import reva.resources.ResourceProvider;
import reva.resources.impl.ProgramListResource;
import reva.tools.ToolProvider;
import reva.tools.bookmarks.BookmarkToolProvider;
import reva.tools.comments.CommentToolProvider;
import reva.tools.data.DataToolProvider;
import reva.tools.datatypes.DataTypeToolProvider;
import reva.tools.decompiler.DecompilerToolProvider;
import reva.tools.functions.FunctionToolProvider;
import reva.tools.memory.MemoryToolProvider;
import reva.tools.project.ProjectToolProvider;
import reva.tools.strings.StringToolProvider;
import reva.tools.structures.StructureToolProvider;
import reva.tools.symbols.SymbolToolProvider;
import reva.tools.xrefs.CrossReferencesToolProvider;

/**
 * Manages the Model Context Protocol server in headless mode.
 * This class provides MCP server functionality without requiring Ghidra's GUI plugin system.
 * Designed to work with pyghidra and other headless Ghidra environments.
 */
public class HeadlessMcpServerManager {
    private static final String MCP_MSG_ENDPOINT = "/mcp/message";
    private static final String MCP_SERVER_NAME = "ReVa";
    private static final String MCP_SERVER_VERSION = "1.0.0";

    // Default configuration
    private static final int DEFAULT_PORT = 8080;
    private static final String DEFAULT_HOST = "127.0.0.1";

    private final McpSyncServer server;
    private HttpServletStreamableServerTransportProvider currentTransportProvider;
    private Server httpServer;

    private final List<ResourceProvider> resourceProviders = new ArrayList<>();
    private final List<ToolProvider> toolProviders = new ArrayList<>();
    private volatile boolean serverReady = false;

    private final int serverPort;
    private final String serverHost;

    // Latch for waiting on server startup
    private final CountDownLatch startupLatch = new CountDownLatch(1);

    /**
     * Constructor with default configuration.
     */
    public HeadlessMcpServerManager() {
        this(DEFAULT_HOST, DEFAULT_PORT);
    }

    /**
     * Constructor with custom configuration.
     * @param serverHost The host to bind to
     * @param serverPort The port to listen on
     */
    public HeadlessMcpServerManager(String serverHost, int serverPort) {
        this.serverHost = serverHost;
        this.serverPort = serverPort;

        String baseUrl = "http://" + serverHost + ":" + serverPort;
        Msg.info(this, "Initializing Headless MCP server for " + baseUrl);

        // Initialize MCP transport provider
        currentTransportProvider = HttpServletStreamableServerTransportProvider.builder()
            .mcpEndpoint(MCP_MSG_ENDPOINT)
            .keepAliveInterval(java.time.Duration.ofSeconds(30))
            .build();

        // Configure server capabilities
        McpSchema.ServerCapabilities serverCapabilities = McpSchema.ServerCapabilities.builder()
            .prompts(true)
            .resources(true, true)
            .tools(true)
            .build();

        // Initialize MCP server
        server = McpServer.sync(currentTransportProvider)
            .serverInfo(MCP_SERVER_NAME, MCP_SERVER_VERSION)
            .capabilities(serverCapabilities)
            .build();

        // Create and register resource providers
        initializeResourceProviders();

        // Create and register tool providers
        initializeToolProviders();

        Msg.info(this, "Headless MCP server initialized");
    }

    /**
     * Initialize and register all resource providers
     */
    private void initializeResourceProviders() {
        resourceProviders.add(new ProgramListResource(server));

        // Register all resources with the server
        for (ResourceProvider provider : resourceProviders) {
            provider.register();
        }
    }

    /**
     * Initialize and register all tool providers
     */
    private void initializeToolProviders() {
        // Create tool providers
        toolProviders.add(new SymbolToolProvider(server));
        toolProviders.add(new StringToolProvider(server));
        toolProviders.add(new FunctionToolProvider(server));
        toolProviders.add(new DataToolProvider(server));
        toolProviders.add(new DecompilerToolProvider(server));
        toolProviders.add(new MemoryToolProvider(server));
        toolProviders.add(new ProjectToolProvider(server));
        toolProviders.add(new CrossReferencesToolProvider(server));
        toolProviders.add(new DataTypeToolProvider(server));
        toolProviders.add(new StructureToolProvider(server));
        toolProviders.add(new CommentToolProvider(server));
        toolProviders.add(new BookmarkToolProvider(server));

        // Register all tools with the server
        for (ToolProvider provider : toolProviders) {
            provider.registerTools();
        }
    }

    /**
     * Start the MCP server
     */
    public void startServer() {
        // Check if server is already running
        if (httpServer != null && httpServer.isRunning()) {
            Msg.warn(this, "MCP server is already running.");
            return;
        }

        String baseUrl = "http://" + serverHost + ":" + serverPort;
        Msg.info(this, "Starting Headless MCP server on " + baseUrl);

        ServletContextHandler servletContextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
        servletContextHandler.setContextPath("/");

        ServletHolder servletHolder = new ServletHolder(currentTransportProvider);
        servletHolder.setAsyncSupported(true);
        servletContextHandler.addServlet(servletHolder, "/*");

        // Create server with specific host binding for security
        httpServer = new Server();
        ServerConnector connector = new ServerConnector(httpServer);
        connector.setHost(serverHost);
        connector.setPort(serverPort);
        httpServer.addConnector(connector);
        httpServer.setHandler(servletContextHandler);

        // Start server in separate thread
        Thread serverThread = new Thread(() -> {
            try {
                httpServer.start();
                Msg.info(this, "Headless MCP server started successfully on " + baseUrl);

                // Mark server as ready
                serverReady = true;
                startupLatch.countDown();

                // join() blocks until the server stops
                httpServer.join();
            } catch (Exception e) {
                if (e instanceof InterruptedException) {
                    Msg.info(this, "MCP server was interrupted - this is normal during shutdown");
                    Thread.currentThread().interrupt();
                } else {
                    Msg.error(this, "Error running MCP server", e);
                }
                startupLatch.countDown();
            }
        }, "ReVa-Headless-MCP-Server");

        serverThread.setDaemon(false); // Keep JVM alive
        serverThread.start();

        // Wait for server to be ready
        try {
            if (!startupLatch.await(10, TimeUnit.SECONDS)) {
                Msg.error(this, "Server failed to start within timeout");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            Msg.warn(this, "Interrupted while waiting for server startup");
        }
    }

    /**
     * Check if the server is ready to accept connections
     * @return true if the server is ready
     */
    public boolean isServerReady() {
        return serverReady && httpServer != null && httpServer.isRunning();
    }

    /**
     * Shut down the MCP server and clean up resources
     */
    public void shutdown() {
        Msg.info(this, "Shutting down Headless MCP server...");

        // Mark server as not ready
        serverReady = false;

        // Notify all providers to clean up
        for (ResourceProvider provider : resourceProviders) {
            provider.cleanup();
        }

        for (ToolProvider provider : toolProviders) {
            provider.cleanup();
        }

        // Shut down the HTTP server
        if (httpServer != null) {
            try {
                httpServer.stop();
                httpServer = null;
            } catch (Exception e) {
                Msg.error(this, "Error stopping HTTP server", e);
            }
        }

        // Close the MCP server gracefully
        if (server != null) {
            server.closeGracefully();
        }

        Msg.info(this, "Headless MCP server shutdown complete");
    }

    /**
     * Register a program with the server.
     * This makes the program available to MCP tools.
     * @param program The program to register
     */
    public void registerProgram(Program program) {
        RevaProgramManager.registerProgram(program);

        // Notify providers
        for (ResourceProvider provider : resourceProviders) {
            provider.programOpened(program);
        }

        for (ToolProvider provider : toolProviders) {
            provider.programOpened(program);
        }

        Msg.info(this, "Program registered: " + program.getName());
    }

    /**
     * Unregister a program from the server.
     * @param program The program to unregister
     */
    public void unregisterProgram(Program program) {
        // Notify providers
        for (ResourceProvider provider : resourceProviders) {
            provider.programClosed(program);
        }

        for (ToolProvider provider : toolProviders) {
            provider.programClosed(program);
        }

        RevaProgramManager.programClosed(program);

        Msg.info(this, "Program unregistered: " + program.getName());
    }

    /**
     * Get the server port
     * @return The port the server is listening on
     */
    public int getServerPort() {
        return serverPort;
    }

    /**
     * Get the server host
     * @return The host the server is bound to
     */
    public String getServerHost() {
        return serverHost;
    }

    /**
     * Block until the server shuts down.
     * Useful for keeping the JVM alive in standalone mode.
     */
    public void waitForShutdown() {
        if (httpServer != null) {
            try {
                httpServer.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                Msg.info(this, "Interrupted while waiting for server shutdown");
            }
        }
    }
}
