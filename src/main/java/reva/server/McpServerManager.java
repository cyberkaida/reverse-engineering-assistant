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
import reva.tools.structures.StructureToolProvider;
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
        // Initialize configuration
        configManager = new ConfigManager(pluginTool);
        RevaInternalServiceRegistry.registerService(ConfigManager.class, configManager);
        // Initialize thread pool
        threadPool = GThreadPool.getPrivateThreadPool("ReVa");
        RevaInternalServiceRegistry.registerService(GThreadPool.class, threadPool);

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
        server = McpServer.sync(transportProvider)
            .serverInfo(MCP_SERVER_NAME, MCP_SERVER_VERSION)
            .capabilities(serverCapabilities)
            .build();

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
        toolProviders.add(new StructureToolProvider(server));

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
        // Check if server is enabled in config
        if (!configManager.isServerEnabled()) {
            Msg.info(this, "MCP server is disabled in configuration. Not starting server.");
            return;
        }

        // Check if server is already running
        if (httpServer != null && httpServer.isRunning()) {
            Msg.warn(this, "MCP server is already running.");
            return;
        }

        int serverPort = configManager.getServerPort();
        String baseUrl = "http://localhost:" + serverPort;
        Msg.info(this, "Starting MCP server on port " + serverPort);

        ServletContextHandler servletContextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
        servletContextHandler.setContextPath("/");
        ServletHolder servletHolder = new ServletHolder(transportProvider);
        servletContextHandler.addServlet(servletHolder, "/*");

        httpServer = new Server(serverPort);
        httpServer.setHandler(servletContextHandler);

        threadPool.submit(() -> {
            try {
                httpServer.start();
                Msg.info(this, "MCP server started successfully");

                // Mark server as ready
                serverReady = true;


                // join() blocks until the server stops, which is expected behavior
                httpServer.join();
            } catch (Exception e) {
                Msg.error(this, "Error starting MCP server", e);
            }
        });

        // Wait for server to be ready
        int maxWaitTime = 10000; // 10 seconds
        int waitInterval = 100; // 100ms
        int totalWait = 0;

        while (!serverReady && totalWait < maxWaitTime) {
            try {
                Thread.sleep(waitInterval);
                totalWait += waitInterval;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                Msg.warn(this, "Interrupted while waiting for server startup");
                return;
            }
        }

        if (serverReady) {
        } else {
            Msg.error(this, "Server failed to start within timeout");
        }

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
        
        Msg.info(this, "MCP server shutdown complete");
    }
}
