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

import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import com.fasterxml.jackson.databind.ObjectMapper;

import generic.concurrent.GThreadPool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.HttpServletSseServerTransportProvider;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;

import reva.resources.ResourceProvider;
import reva.resources.impl.ProgramListResource;
import reva.tools.ToolProvider;
import reva.tools.data.DataToolProvider;
import reva.tools.datatypes.DataTypeToolProvider;
import reva.tools.decompiler.DecompilerToolProvider;
import reva.tools.functions.FunctionToolProvider;
import reva.tools.memory.MemoryToolProvider;
import reva.tools.project.ProjectToolProvider;
import reva.tools.strings.StringToolProvider;
import reva.tools.symbols.SymbolToolProvider;
import reva.tools.xrefs.CrossReferencesToolProvider;
import reva.util.ConfigManager;
import reva.util.RevaInternalServiceRegistry;

/**
 * Manages the Model Context Protocol server.
 * This class is responsible for initializing, configuring, and starting the MCP server,
 * as well as registering all resources and tools.
 * Implements singleton pattern to ensure only one server instance exists.
 */
public class McpServerManager {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String MCP_MSG_ENDPOINT = "/mcp/message";
    private static final String MCP_SSE_ENDPOINT = "/mcp/sse";
    private static final String MCP_SERVER_NAME = "ReVa";
    private static final String MCP_SERVER_VERSION = "1.0.0";

    private static volatile McpServerManager instance;
    private static final Object instanceLock = new Object();

    private final McpSyncServer server;
    private final HttpServletSseServerTransportProvider transportProvider;
    private Server httpServer;
    private final GThreadPool threadPool;
    private final ConfigManager configManager;

    private final List<ResourceProvider> resourceProviders = new ArrayList<>();
    private final List<ToolProvider> toolProviders = new ArrayList<>();
    private volatile boolean serverReady = false;

    /**
     * Get the singleton instance of McpServerManager.
     * @param pluginTool The plugin tool, used for configuration (only used on first call)
     * @return The singleton instance
     */
    public static McpServerManager getInstance(PluginTool pluginTool) {
        if (instance == null) {
            synchronized (instanceLock) {
                if (instance == null) {
                    instance = new McpServerManager(pluginTool);
                }
            }
        }
        return instance;
    }

    /**
     * Private constructor. Initializes the MCP server with all capabilities.
     * @param pluginTool The plugin tool, used for configuration
     */
    private McpServerManager(PluginTool pluginTool) {
        Msg.info(this, "[DEADLOCK-DEBUG] McpServerManager constructor starting - Thread: " + Thread.currentThread().getName());
        // Initialize configuration
        configManager = new ConfigManager(pluginTool);
        RevaInternalServiceRegistry.registerService(ConfigManager.class, configManager);
        // Initialize thread pool
        threadPool = GThreadPool.getPrivateThreadPool("ReVa");
        RevaInternalServiceRegistry.registerService(GThreadPool.class, threadPool);
        Msg.info(this, "[DEADLOCK-DEBUG] Thread pool created with size: " + threadPool.getMaxThreadCount());

        // Initialize MCP transport provider with baseUrl
        int serverPort = configManager.getServerPort();
        String baseUrl = "http://localhost:" + serverPort;
        transportProvider = HttpServletSseServerTransportProvider.builder()
            .baseUrl(baseUrl)
            .objectMapper(JSON)
            .messageEndpoint(MCP_MSG_ENDPOINT)
            .sseEndpoint(MCP_SSE_ENDPOINT)
            .build();
        // Configure server capabilities
        McpSchema.ServerCapabilities serverCapabilities = McpSchema.ServerCapabilities.builder()
            .prompts(true)
            .resources(true, true)
            .tools(true)
            .build();

        // Initialize MCP server
        Msg.info(this, "[DEADLOCK-DEBUG] Creating MCP server...");
        server = McpServer.sync(transportProvider)
            .serverInfo(MCP_SERVER_NAME, MCP_SERVER_VERSION)
            .capabilities(serverCapabilities)
            .build();
        Msg.info(this, "[DEADLOCK-DEBUG] MCP server created");

        // Make server and server manager available via service registry
        RevaInternalServiceRegistry.registerService(McpSyncServer.class, server);
        RevaInternalServiceRegistry.registerService(McpServerManager.class, this);

        // Create and register resource providers
        initializeResourceProviders();

        // Create and register tool providers
        initializeToolProviders();
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

        // Register all tools with the server
        for (ToolProvider provider : toolProviders) {
            try {
                provider.registerTools();
            } catch (McpError e) {
                Msg.error(this, "Failed to register tools for provider: " + provider.getClass().getSimpleName(), e);
            }
        }
    }

    /**
     * Start the MCP server
     */
    public void startServer() {
        Msg.info(this, "[MCP-DEBUG] startServer() called - Thread: " + Thread.currentThread().getName());
        // Check if server is enabled in config
        if (!configManager.isServerEnabled()) {
            Msg.info(this, "[MCP-DEBUG] MCP server is disabled in configuration. Not starting server.");
            return;
        }

        // Check if server is already running
        if (httpServer != null && httpServer.isRunning()) {
            Msg.warn(this, "[MCP-DEBUG] MCP server is already running. Not starting again.");
            return;
        }

        int serverPort = configManager.getServerPort();
        String baseUrl = "http://localhost:" + serverPort;
        Msg.info(this, "[MCP-DEBUG] Starting server on port " + serverPort + ", base URL: " + baseUrl);
        Msg.info(this, "[MCP-DEBUG] Message endpoint: " + MCP_MSG_ENDPOINT);
        Msg.info(this, "[MCP-DEBUG] SSE endpoint: " + MCP_SSE_ENDPOINT);
        Msg.info(this, "[MCP-DEBUG] Transport provider base URL: " + transportProvider.toString());

        ServletContextHandler servletContextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
        servletContextHandler.setContextPath("/");
        ServletHolder servletHolder = new ServletHolder(transportProvider);
        servletContextHandler.addServlet(servletHolder, "/*");
        Msg.info(this, "[MCP-DEBUG] Servlet context handler configured with path: /");
        Msg.info(this, "[MCP-DEBUG] Servlet holder configured for all paths: /*");

        httpServer = new Server(serverPort);
        httpServer.setHandler(servletContextHandler);
        Msg.info(this, "[MCP-DEBUG] HTTP server created on port " + serverPort);
        Msg.info(this, "[MCP-DEBUG] Server handler: " + servletContextHandler.getClass().getName());
        Msg.info(this, "[MCP-DEBUG] Servlet holder path: /*");

        Msg.info(this, "[MCP-DEBUG] Submitting server start task to thread pool...");
        threadPool.submit(() -> {
            try {
                Msg.info(this, "[MCP-DEBUG] Server start task running - Thread: " + Thread.currentThread().getName());
                Msg.info(this, "[MCP-DEBUG] About to call httpServer.start()...");
                httpServer.start();
                Msg.info(this, "[MCP-DEBUG] httpServer.start() completed successfully");
                Msg.info(this, "[MCP-DEBUG] Server state: " + httpServer.getState());
                Msg.info(this, "[MCP-DEBUG] Server is running: " + httpServer.isRunning());
                Msg.info(this, "[MCP-DEBUG] Server is started: " + httpServer.isStarted());

                // Mark server as ready
                serverReady = true;
                Msg.info(this, "[MCP-DEBUG] Server marked as ready for connections");

                // Log connector details
                for (org.eclipse.jetty.server.Connector connector : httpServer.getConnectors()) {
                    if (connector instanceof org.eclipse.jetty.server.ServerConnector) {
                        org.eclipse.jetty.server.ServerConnector serverConnector = (org.eclipse.jetty.server.ServerConnector) connector;
                        Msg.info(this, "[MCP-DEBUG] Server connector: " + serverConnector.getHost() + ":" + serverConnector.getLocalPort());
                        Msg.info(this, "[MCP-DEBUG] Connector state: " + serverConnector.getState());
                    }
                }

                Msg.info(this, "[MCP-DEBUG] About to call httpServer.join() - THIS WILL BLOCK INDEFINITELY");
                // Note: join() blocks until the server stops, which is expected behavior
                // The server should remain running to handle requests
                httpServer.join();
                Msg.info(this, "[MCP-DEBUG] httpServer.join() returned - Server has stopped");
            } catch (Exception e) {
                Msg.error(this, "[MCP-DEBUG] Error in server thread", e);
                Msg.error(this, "[MCP-DEBUG] Exception details: " + e.getClass().getName() + ": " + e.getMessage());
                if (e.getCause() != null) {
                    Msg.error(this, "[MCP-DEBUG] Caused by: " + e.getCause().getClass().getName() + ": " + e.getCause().getMessage());
                }
            }
        });
        Msg.info(this, "[MCP-DEBUG] Server start task submitted to thread pool");

        // Wait for server to be ready
        Msg.info(this, "[MCP-DEBUG] Waiting for server to be ready...");
        int maxWaitTime = 10000; // 10 seconds
        int waitInterval = 100; // 100ms
        int totalWait = 0;

        while (!serverReady && totalWait < maxWaitTime) {
            try {
                Thread.sleep(waitInterval);
                totalWait += waitInterval;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                Msg.warn(this, "[MCP-DEBUG] Interrupted while waiting for server startup");
                return;
            }
        }

        if (serverReady) {
            Msg.info(this, "[MCP-DEBUG] Server is ready after " + totalWait + "ms");
        } else {
            Msg.error(this, "[MCP-DEBUG] Server failed to become ready within " + maxWaitTime + "ms");
        }

        Msg.info(this, "[MCP-DEBUG] startServer() method returning");
    }

    /**
     * Notify providers that a program has been opened
     * @param program The program that was opened
     */
    public void programOpened(Program program) {
        for (ResourceProvider provider : resourceProviders) {
            provider.programOpened(program);
        }

        for (ToolProvider provider : toolProviders) {
            provider.programOpened(program);
        }
    }

    /**
     * Notify providers that a program has been closed
     * @param program The program that was closed
     */
    public void programClosed(Program program) {
        for (ResourceProvider provider : resourceProviders) {
            provider.programClosed(program);
        }

        for (ToolProvider provider : toolProviders) {
            provider.programClosed(program);
        }
    }

    /**
     * Check if the server is ready to accept connections
     * @return true if the server is ready
     */
    public boolean isServerReady() {
        return httpServer.getState() == org.eclipse.jetty.server.Server.STARTED;
    }

    /**
     * Shut down the MCP server and clean up resources
     */
    public void shutdown() {
        Msg.info(this, "[DEADLOCK-DEBUG] shutdown() called - Thread: " + Thread.currentThread().getName());
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
            } catch (Exception e) {
                Msg.error(this, "Error stopping HTTP server", e);
            }
        }

        // Close the MCP server gracefully
        if (server != null) {
            server.closeGracefully();
        }

        // Shut down the thread pool
        if (threadPool != null) {
            threadPool.shutdownNow();
        }

        serverReady = false;
        
        // Reset singleton instance on shutdown
        synchronized (instanceLock) {
            instance = null;
        }
        
        Msg.info(this, "[DEADLOCK-DEBUG] McpServerManager shutdown complete - Thread: " + Thread.currentThread().getName());
    }
}
