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
import java.util.Set;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.net.InetSocketAddress;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.servlet.FilterHolder;
import java.util.EnumSet;
import jakarta.servlet.DispatcherType;

import com.fasterxml.jackson.databind.ObjectMapper;

import generic.concurrent.GThreadPool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.ConfigManager;
import reva.plugin.ConfigChangeListener;
import reva.resources.ResourceProvider;
import reva.resources.impl.ProgramListResource;
import reva.services.RevaMcpService;
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
import reva.tools.comments.CommentToolProvider;
import reva.tools.bookmarks.BookmarkToolProvider;
import reva.util.RevaInternalServiceRegistry;

/**
 * Manages the Model Context Protocol server at the application level.
 * This class is responsible for initializing, configuring, and starting the MCP server,
 * as well as registering all resources and tools. It handles multiple tools accessing
 * the same server instance and coordinates program lifecycle events across tools.
 */
public class McpServerManager implements RevaMcpService, ConfigChangeListener {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String MCP_MSG_ENDPOINT = "/mcp/message";
    private static final String MCP_SERVER_NAME = "ReVa";
    private static final String MCP_SERVER_VERSION = "1.0.0";

    private final McpSyncServer server;
    private HttpServletStreamableServerTransportProvider currentTransportProvider;
    private Server httpServer;
    private final GThreadPool threadPool;
    private final ConfigManager configManager;

    private final List<ResourceProvider> resourceProviders = new ArrayList<>();
    private final List<ToolProvider> toolProviders = new ArrayList<>();
    private volatile boolean serverReady = false;

    // Multi-tool tracking
    private final Set<PluginTool> registeredTools = ConcurrentHashMap.newKeySet();
    private final Map<Program, Set<PluginTool>> programToTools = new ConcurrentHashMap<>();
    private volatile Program activeProgram;
    private volatile PluginTool activeTool;

    /**
     * Constructor. Initializes the MCP server with all capabilities.
     * @param pluginTool The plugin tool, used for configuration
     */
    public McpServerManager(PluginTool pluginTool) {
        // Initialize configuration
        configManager = new ConfigManager(pluginTool);
        RevaInternalServiceRegistry.registerService(ConfigManager.class, configManager);

        // Register as a config change listener
        configManager.addConfigChangeListener(this);
        // Initialize thread pool
        threadPool = GThreadPool.getPrivateThreadPool("ReVa");
        RevaInternalServiceRegistry.registerService(GThreadPool.class, threadPool);

        // Initialize MCP transport provider with baseUrl
        recreateTransportProvider();

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
        toolProviders.add(new CommentToolProvider(server));
        toolProviders.add(new BookmarkToolProvider(server));

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
        String serverHost = configManager.getServerHost();
        String baseUrl = "http://" + serverHost + ":" + serverPort;
        Msg.info(this, "Starting MCP server on " + baseUrl);

        ServletContextHandler servletContextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
        servletContextHandler.setContextPath("/");
        ServletHolder servletHolder = new ServletHolder(currentTransportProvider);
        servletHolder.setAsyncSupported(true);
        servletContextHandler.addServlet(servletHolder, "/*");

        // Add API key authentication filter
        FilterHolder authFilter = new FilterHolder(new ApiKeyAuthFilter(configManager));
        servletContextHandler.addFilter(authFilter, "/*", EnumSet.of(DispatcherType.REQUEST));

        httpServer = new Server(new InetSocketAddress(serverHost, serverPort));
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
                if (e instanceof InterruptedException) {
                    Msg.info(this, "MCP server was interrupted - this is normal during shutdown");
                    Thread.currentThread().interrupt(); // Restore interrupt status
                } else {
                    Msg.error(this, "Error starting MCP server", e);
                }
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

    @Override
    public void registerTool(PluginTool tool) {
        registeredTools.add(tool);
        Msg.debug(this, "Registered tool with MCP server: " + tool.getName());
    }

    @Override
    public void unregisterTool(PluginTool tool) {
        registeredTools.remove(tool);

        // Remove tool from all program mappings
        for (Set<PluginTool> tools : programToTools.values()) {
            tools.remove(tool);
        }

        // Clear active tool if it's the one being unregistered
        if (activeTool == tool) {
            activeTool = null;
            activeProgram = null;
        }

        Msg.debug(this, "Unregistered tool from MCP server: " + tool.getName());
    }

    @Override
    public void programOpened(Program program, PluginTool tool) {
        // Add to program-tool mapping
        programToTools.computeIfAbsent(program, k -> ConcurrentHashMap.newKeySet()).add(tool);

        // Set as active program
        setActiveProgram(program, tool);

        // Notify providers
        for (ResourceProvider provider : resourceProviders) {
            provider.programOpened(program);
        }

        for (ToolProvider provider : toolProviders) {
            provider.programOpened(program);
        }

        Msg.debug(this, "Program opened in tool " + tool.getName() + ": " + program.getName());
    }

    @Override
    public void programClosed(Program program, PluginTool tool) {
        // Remove from program-tool mapping
        Set<PluginTool> tools = programToTools.get(program);
        if (tools != null) {
            tools.remove(tool);
            if (tools.isEmpty()) {
                programToTools.remove(program);
            }
        }

        // Clear active program if it was the one being closed
        if (activeProgram == program && activeTool == tool) {
            activeProgram = null;
            activeTool = null;
        }

        // Notify providers only if this was the last tool with the program
        if (tools == null || tools.isEmpty()) {
            for (ResourceProvider provider : resourceProviders) {
                provider.programClosed(program);
            }

            for (ToolProvider provider : toolProviders) {
                provider.programClosed(program);
            }
        }

        Msg.debug(this, "Program closed in tool " + tool.getName() + ": " + program.getName());
    }

    @Override
    public boolean isServerRunning() {
        return httpServer != null && httpServer.isRunning() && serverReady;
    }

    @Override
    public int getServerPort() {
        if (configManager != null) {
            return configManager.getServerPort();
        }
        return -1;
    }

    @Override
    public Program getActiveProgram() {
        return activeProgram;
    }

    @Override
    public void setActiveProgram(Program program, PluginTool tool) {
        this.activeProgram = program;
        this.activeTool = tool;
        Msg.debug(this, "Active program changed to: " + (program != null ? program.getName() : "null") +
                  " in tool: " + (tool != null ? tool.getName() : "null"));
    }

    /**
     * Check if the server is ready to accept connections
     * @return true if the server is ready
     */
    public boolean isServerReady() {
        return httpServer != null && httpServer.getState().equals(org.eclipse.jetty.server.Server.STARTED);
    }

    /**
     * Restart the MCP server with new configuration.
     * This method gracefully stops the current server and starts a new one.
     */
    public void restartServer() {
        Msg.info(this, "Restarting MCP server...");

        // Check if server is enabled in config
        if (!configManager.isServerEnabled()) {
            Msg.info(this, "MCP server is disabled in configuration. Stopping server.");
            stopServer();
            return;
        }

        // Stop the current server
        stopServer();

        // Recreate transport provider with new port configuration
        recreateTransportProvider();

        // Start the server with new configuration
        startServer();

        Msg.info(this, "MCP server restart complete");
    }

    /**
     * Recreate the transport provider with updated port configuration.
     * This is necessary when the port changes during server restart.
     */
    private void recreateTransportProvider() {
        int serverPort = configManager.getServerPort();
        String serverHost = configManager.getServerHost();
        String baseUrl = "http://" + serverHost + ":" + serverPort;

        // Create new transport provider with updated configuration
        currentTransportProvider = HttpServletStreamableServerTransportProvider.builder()
            .objectMapper(JSON)
            .mcpEndpoint(MCP_MSG_ENDPOINT)
            .keepAliveInterval(java.time.Duration.ofSeconds(30))
            .build();
    }

    /**
     * Stop the MCP server without full shutdown cleanup.
     * This is used internally for restart operations.
     */
    private void stopServer() {
        Msg.info(this, "Stopping MCP server...");

        // Mark server as not ready
        serverReady = false;

        // Shut down the HTTP server
        if (httpServer != null) {
            try {
                httpServer.stop();
                httpServer = null;
            } catch (Exception e) {
                Msg.error(this, "Error stopping HTTP server", e);
            }
        }

        Msg.info(this, "MCP server stopped");
    }

    @Override
    public void onConfigChanged(String category, String name, Object oldValue, Object newValue) {
        // Handle server configuration changes
        if (ConfigManager.SERVER_OPTIONS.equals(category)) {
            if (ConfigManager.SERVER_PORT.equals(name)) {
                Msg.info(this, "Server port changed from " + oldValue + " to " + newValue + ". Restarting server...");
                restartServer();
            } else if (ConfigManager.SERVER_HOST.equals(name)) {
                Msg.info(this, "Server host changed from " + oldValue + " to " + newValue + ". Restarting server...");
                restartServer();
            } else if (ConfigManager.SERVER_ENABLED.equals(name)) {
                Msg.info(this, "Server enabled setting changed from " + oldValue + " to " + newValue + ". Restarting server...");
                restartServer();
            } else if (ConfigManager.SERVER_API_KEY.equals(name)) {
                Msg.info(this, "Server API key changed. Restarting server...");
                restartServer();
            }
        }
    }

    /**
     * Shut down the MCP server and clean up resources
     */
    public void shutdown() {
        Msg.info(this, "Shutting down MCP server...");

        // Remove config change listener and dispose
        if (configManager != null) {
            configManager.removeConfigChangeListener(this);
        }

        // Clear all tool registrations
        registeredTools.clear();
        programToTools.clear();
        activeProgram = null;
        activeTool = null;

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

        Msg.info(this, "MCP server shutdown complete");
    }
}
