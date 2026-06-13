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
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;

import java.util.EnumSet;
import jakarta.servlet.DispatcherType;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import generic.concurrent.GThreadPool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import io.modelcontextprotocol.json.jackson2.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.ConfigManager;
import reva.plugin.ConfigChangeListener;
import reva.plugin.ToolGroup;
import reva.plugin.FollowMeService;
import reva.resources.ResourceProvider;
import reva.resources.impl.ProgramListResource;
import reva.services.AnalysisJobManager;
import reva.services.DiffJobManager;
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
import reva.tools.imports.ImportExportToolProvider;
import reva.tools.dataflow.DataFlowToolProvider;
import reva.tools.callgraph.CallGraphToolProvider;
import reva.tools.constants.ConstantSearchToolProvider;
import reva.tools.scripts.ScriptToolProvider;
import reva.tools.vtable.VtableToolProvider;
import reva.tools.diff.DiffToolProvider;
import reva.util.NetworkUtil;
import reva.util.RevaInternalServiceRegistry;

/**
 * Manages the Model Context Protocol server at the application level.
 * This class is responsible for initializing, configuring, and starting the MCP server,
 * as well as registering all resources and tools. It handles multiple tools accessing
 * the same server instance and coordinates program lifecycle events across tools.
 */
public class McpServerManager implements RevaMcpService, ConfigChangeListener {
    private static final String MCP_MSG_ENDPOINT = "/mcp/message";
    private static final String MCP_SERVER_NAME = "ReVa";
    private static final String MCP_SERVER_VERSION = "1.0.0";

    private final McpSyncServer server;
    private ResilientStreamableServerTransportProvider currentTransportProvider;
    private Server httpServer;
    private final GThreadPool threadPool;
    private final ConfigManager configManager;

    private final List<ResourceProvider> resourceProviders = new ArrayList<>();
    private final List<ToolProvider> toolProviders = new java.util.concurrent.CopyOnWriteArrayList<>();
    private final Map<ToolGroup, List<ToolProvider>> providersByGroup = new HashMap<>();
    private volatile boolean serverReady = false;

    // Set while we revert a bind-affecting option after refused consent, so the
    // resulting re-entrant onConfigChanged does not re-handle/restart.
    private volatile boolean suppressBindChangeHandling = false;

    // Multi-tool tracking
    private final Set<PluginTool> registeredTools = ConcurrentHashMap.newKeySet();
    private final Map<Program, Set<PluginTool>> programToTools = new ConcurrentHashMap<>();
    private volatile Program activeProgram;
    private volatile PluginTool activeTool;

    // Mode tracking - headless mode has no GUI context
    private final boolean headlessMode;

    // Follow Me demo navigation service - GUI mode only
    private final FollowMeService followMeService;

    // Background auto-analysis job registry + worker (shared by analyze-program and friends)
    private final AnalysisJobManager analysisJobManager;

    // Background diff job registry (shared by diff-create-session and friends)
    private final DiffJobManager diffJobManager;

    /**
     * Constructor for GUI mode. Initializes the MCP server with all capabilities.
     * This constructor creates a ConfigManager from the PluginTool for backward compatibility.
     * @param pluginTool The plugin tool, used for configuration
     */
    public McpServerManager(PluginTool pluginTool) {
        this(new ConfigManager(pluginTool), false);
    }

    /**
     * Constructor for headless mode. Initializes the MCP server with all capabilities.
     * @param configManager The configuration manager to use
     */
    public McpServerManager(ConfigManager configManager) {
        this(configManager, true);
    }

    /**
     * Primary constructor with ConfigManager and mode flag.
     * @param configManager The configuration manager to use
     * @param headlessMode True if running in headless mode (no GUI context)
     */
    private McpServerManager(ConfigManager configManager, boolean headlessMode) {
        this.headlessMode = headlessMode;
        // Store configuration
        this.configManager = configManager;
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

        // Background analysis job manager: a single per-server instance owning the worker and
        // ticker threads. Registered so analyze-program (and later analysis-status/-cancel) can
        // submit and poll jobs. Disposed in shutdown().
        analysisJobManager = new AnalysisJobManager();
        RevaInternalServiceRegistry.registerService(AnalysisJobManager.class, analysisJobManager);

        diffJobManager = new DiffJobManager();
        RevaInternalServiceRegistry.registerService(DiffJobManager.class, diffJobManager);

        // Follow Me demo navigation is GUI-only — not registered in headless mode,
        // so AbstractToolProvider.followRead/followWrite become no-ops.
        if (!headlessMode) {
            followMeService = new FollowMeService(configManager, this);
            RevaInternalServiceRegistry.registerService(FollowMeService.class, followMeService);
        } else {
            followMeService = null;
        }

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
     * Initialize and register all tool providers for enabled groups.
     */
    private void initializeToolProviders() {
        for (ToolGroup group : ToolGroup.values()) {
            if (configManager.isToolGroupEnabled(group)) {
                enableGroup(group);
            }
        }
    }

    /**
     * Construct the tool providers belonging to a group. New instances each call.
     */
    private List<ToolProvider> createProvidersForGroup(ToolGroup group) {
        switch (group) {
            case CORE_ANALYSIS:
                return List.of(
                    new SymbolToolProvider(server),
                    new StringToolProvider(server),
                    new FunctionToolProvider(server),
                    new DecompilerToolProvider(server),
                    new MemoryToolProvider(server),
                    new CrossReferencesToolProvider(server),
                    new ConstantSearchToolProvider(server),
                    new ImportExportToolProvider(server),
                    new ProjectToolProvider(server, headlessMode));
            case DATA_AND_TYPES:
                return List.of(
                    new DataToolProvider(server),
                    new DataTypeToolProvider(server),
                    new StructureToolProvider(server));
            case ADVANCED_ANALYSIS:
                return List.of(
                    new CallGraphToolProvider(server),
                    new DataFlowToolProvider(server),
                    new VtableToolProvider(server));
            case DIFF:
                return List.of(new DiffToolProvider(server));
            case ANNOTATIONS:
                return List.of(
                    new CommentToolProvider(server),
                    new BookmarkToolProvider(server));
            case SCRIPTING:
                return List.of(ScriptToolProvider.fromGhidra(server, configManager));
            default:
                return List.of();
        }
    }

    /**
     * Register a group's providers with the MCP server and track them. Idempotent:
     * a group already enabled is left untouched.
     */
    private synchronized void enableGroup(ToolGroup group) {
        if (providersByGroup.containsKey(group)) {
            return;
        }
        List<ToolProvider> providers = new ArrayList<>(createProvidersForGroup(group));
        for (ToolProvider provider : providers) {
            provider.registerTools();
            toolProviders.add(provider);
            // Catch the new provider up on any already-open programs.
            for (Program program : programToTools.keySet()) {
                provider.programOpened(program);
            }
        }
        providersByGroup.put(group, providers);
        Msg.info(this, "Enabled tool group: " + group.getDisplayName());
    }

    /**
     * Remove a group's providers from the MCP server. Idempotent.
     */
    private synchronized void disableGroup(ToolGroup group) {
        List<ToolProvider> providers = providersByGroup.remove(group);
        if (providers == null) {
            return;
        }
        for (ToolProvider provider : providers) {
            provider.unregisterTools();
            provider.cleanup();
            toolProviders.remove(provider);
        }
        Msg.info(this, "Disabled tool group: " + group.getDisplayName());
    }

    /**
     * Start the MCP server.
     */
    public void startServer() {
        startServer(false);
    }

    /**
     * Start the MCP server, optionally skipping the public-binding consent check.
     * @param guardAlreadyApproved true if consent was already obtained before calling this
     */
    private void startServer(boolean guardAlreadyApproved) {
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
        if (!guardAlreadyApproved && !approvePublicBinding(serverHost)) {
            Msg.warn(this, "MCP server start aborted: public binding without API key was not approved.");
            return;
        }
        String baseUrl = "http://" + serverHost + ":" + serverPort;
        Msg.info(this, "Starting MCP server on " + baseUrl);

        ServletContextHandler servletContextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
        servletContextHandler.setContextPath("/");

        // Add API key authentication filter if enabled
        if (configManager.isApiKeyEnabled()) {
            FilterHolder filterHolder = new FilterHolder(new ApiKeyAuthFilter(configManager));
            servletContextHandler.addFilter(filterHolder, "/*", EnumSet.of(DispatcherType.REQUEST));
            Msg.info(this, "API key authentication enabled for MCP server");
        }

        // Add request logging filter for debugging (only logs when debug mode is enabled)
        FilterHolder loggingFilter = new FilterHolder(new RequestLoggingFilter(configManager));
        servletContextHandler.addFilter(loggingFilter, "/*", EnumSet.of(DispatcherType.REQUEST));

        ServletHolder servletHolder = new ServletHolder(currentTransportProvider);
        servletHolder.setAsyncSupported(true);
        servletContextHandler.addServlet(servletHolder, "/*");

        // Create server with specific host binding for security
        httpServer = new Server();
        ServerConnector connector = new ServerConnector(httpServer);
        connector.setHost(serverHost);
        connector.setPort(serverPort);
        connector.setIdleTimeout(600000); // 10 minutes - defense in depth against stale connections
        httpServer.addConnector(connector);
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

    /**
     * Guard against silently exposing ReVa on a public interface with no auth.
     * Returns true if the server may proceed to bind.
     */
    private boolean approvePublicBinding(String serverHost) {
        boolean risky = !configManager.isApiKeyEnabled()
            && !NetworkUtil.isLocalhostAddress(serverHost);
        if (!risky) {
            return true;
        }
        if (configManager.isAllowPublicBindingWithoutApiKey()) {
            return true;
        }

        boolean scripting = configManager.isToolGroupEnabled(ToolGroup.SCRIPTING);
        String warning = buildPublicBindingWarning(serverHost, scripting);

        if (headlessMode) {
            Msg.error(this, warning + "\nRefusing to start. Bind to 127.0.0.1, enable API key " +
                "authentication, or set '" + ConfigManager.ALLOW_PUBLIC_BINDING_NO_API_KEY +
                "=true' in your configuration.");
            return false;
        }

        int choice = PublicBindingConsentDialog.prompt(warning);
        switch (choice) {
            case PublicBindingConsentDialog.ALLOW_ALWAYS:
                configManager.setAllowPublicBindingWithoutApiKey(true);
                return true;
            case PublicBindingConsentDialog.ALLOW_ONCE:
                return true;
            default:
                return false;
        }
    }

    private String buildPublicBindingWarning(String host, boolean scripting) {
        StringBuilder sb = new StringBuilder();
        sb.append("ReVa is about to bind to ").append(host)
            .append(" (a non-localhost interface) with API key authentication DISABLED.\n")
            .append("Anyone who can reach this port can read and modify your Ghidra programs");
        if (scripting) {
            sb.append(" and RUN ARBITRARY PYTHON CODE on this host (the run-script tool is enabled)");
        }
        sb.append(".\n\nTo secure it: bind to 127.0.0.1, or enable API key authentication.");
        if (scripting) {
            sb.append(" Disabling the Scripting tool group removes the remote code-execution risk, " +
                "but the server remains reachable on this interface.");
        }
        return sb.toString();
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
    public synchronized void programOpened(Program program, PluginTool tool) {
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
    public synchronized void programClosed(Program program, PluginTool tool) {
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
            // The program is truly going away: cancel any background analysis on it.
            if (analysisJobManager != null) {
                analysisJobManager.cancelJobsForProgram(program.getDomainFile().getPathname());
            }
            if (diffJobManager != null) {
                diffJobManager.cancelJobsForProgram(program.getDomainFile().getPathname());
            }

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

    /**
     * Check if running in headless mode (no GUI context)
     * @return true if running in headless mode
     */
    public boolean isHeadlessMode() {
        return headlessMode;
    }

    /**
     * Get the {@link PluginTool} that most recently opened a program — typically
     * the active CodeBrowser. May be null in headless mode or before any program
     * has been opened. Used by {@link FollowMeService} to reach the GoToService.
     * @return the active CodeBrowser tool, or null if none
     */
    public PluginTool getActiveTool() {
        return activeTool;
    }

    /**
     * Get the GUI-only Follow Me navigation service.
     * @return the service in GUI mode, or null in headless mode
     */
    public FollowMeService getFollowMeService() {
        return followMeService;
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
     */
    public void restartServer() {
        restartServer(false);
    }

    /**
     * Restart the MCP server with new configuration, optionally skipping the
     * public-binding consent check on the subsequent startServer call.
     * @param guardAlreadyApproved true if consent was already obtained before calling this
     */
    private void restartServer(boolean guardAlreadyApproved) {
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
        startServer(guardAlreadyApproved);

        Msg.info(this, "MCP server restart complete");
    }

    /**
     * Recreate the transport provider with updated configuration.
     * This is necessary when configuration changes during server restart.
     */
    private void recreateTransportProvider() {
        int serverPort = configManager.getServerPort();
        String serverHost = configManager.getServerHost();
        String baseUrl = "http://" + serverHost + ":" + serverPort;

        // Create ObjectMapper configured to ignore unknown properties
        // This is a workaround for MCP SDK issue #724 where the SDK doesn't handle
        // newer protocol fields (e.g., from VS Code MCP client using protocol 2025-11-25)
        // See: https://github.com/modelcontextprotocol/java-sdk/issues/724
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        JacksonMcpJsonMapper jsonMapper = new JacksonMcpJsonMapper(objectMapper);

        // Create new transport provider with updated configuration
        // Uses ResilientStreamableServerTransportProvider (forked from MCP SDK) to fix
        // a bug where serialization errors permanently kill the session.
        currentTransportProvider = ResilientStreamableServerTransportProvider.builder()
            .mcpEndpoint(MCP_MSG_ENDPOINT)
            .jsonMapper(jsonMapper)
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
        // Tool-group enable/disable lives in its own options category.
        if (ConfigManager.TOOL_GROUP_OPTIONS.equals(category)) {
            ToolGroup group = ToolGroup.fromDisplayName(name);
            if (group != null) {
                boolean enabled = Boolean.TRUE.equals(newValue);
                Msg.info(this, "Tool group '" + group.getDisplayName() + "' " +
                    (enabled ? "enabled" : "disabled") + " — updating registered tools.");
                if (enabled) {
                    enableGroup(group);
                } else {
                    disableGroup(group);
                }
            }
            return;
        }

        // Handle server configuration changes
        if (ConfigManager.SERVER_OPTIONS.equals(category)) {
            // Note: ALLOW_PUBLIC_BINDING_NO_API_KEY intentionally does NOT trigger a restart.
            // It is consulted only at startServer() time (the public-binding guard); flipping it
            // must not bounce a running, already-consented server, and "Allow Always" sets it from
            // within startServer() itself — restarting there would re-enter server startup.
            if (ConfigManager.SERVER_PORT.equals(name)) {
                Msg.info(this, "Server port changed from " + oldValue + " to " + newValue + ". Restarting server...");
                restartServer();
            } else if (ConfigManager.SERVER_HOST.equals(name)) {
                handleBindAffectingChange(name, oldValue,
                    "Server host changed from " + oldValue + " to " + newValue);
            } else if (ConfigManager.SERVER_ENABLED.equals(name)) {
                Msg.info(this, "Server enabled setting changed from " + oldValue + " to " + newValue + ". Restarting server...");
                restartServer();
            } else if (ConfigManager.API_KEY_ENABLED.equals(name)) {
                handleBindAffectingChange(name, oldValue,
                    "API key authentication setting changed from " + oldValue + " to " + newValue);
            } else if (ConfigManager.API_KEY.equals(name)) {
                Msg.info(this, "API key changed. Restarting server...");
                restartServer();
            }
        }
    }

    /**
     * Handle a config change (host / api-key-auth) that may newly create a risky public
     * bind. Obtains consent BEFORE tearing the running server down. On refusal/cancel,
     * reverts the option to its previous value and leaves the running server untouched
     * (a true no-op). On approval, restarts without re-prompting.
     */
    private void handleBindAffectingChange(String optionName, Object oldValue, String logMessage) {
        if (suppressBindChangeHandling) {
            return; // re-entrant notification triggered by our own revert
        }
        if (!approvePublicBinding(configManager.getServerHost())) {
            Msg.info(this, "Public binding not approved; reverting " + optionName + " to " +
                oldValue + " and leaving the running server unchanged.");
            revertBindOption(optionName, oldValue);
            return;
        }
        Msg.info(this, logMessage + ". Restarting server...");
        restartServer(true); // consent already obtained — do not re-prompt in startServer
    }

    /**
     * Revert a bind-affecting option to its previous value without re-triggering
     * handleBindAffectingChange (and thus without restarting the running server).
     */
    private void revertBindOption(String optionName, Object oldValue) {
        suppressBindChangeHandling = true;
        try {
            if (ConfigManager.SERVER_HOST.equals(optionName)) {
                configManager.setServerHost((String) oldValue);
            } else if (ConfigManager.API_KEY_ENABLED.equals(optionName)) {
                configManager.setApiKeyEnabled((Boolean) oldValue);
            }
        } finally {
            suppressBindChangeHandling = false;
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

        // Dispose the background analysis job manager (cancels running jobs, reaps worker/ticker
        // threads) and unregister it so a fresh server instance does not see a dead manager.
        if (analysisJobManager != null) {
            analysisJobManager.dispose();
            RevaInternalServiceRegistry.unregisterService(AnalysisJobManager.class);
        }
        if (diffJobManager != null) {
            diffJobManager.dispose();
            RevaInternalServiceRegistry.unregisterService(DiffJobManager.class);
        }

        // Notify all providers to clean up
        for (ResourceProvider provider : resourceProviders) {
            provider.cleanup();
        }

        synchronized (this) {
            for (ToolProvider provider : toolProviders) {
                provider.cleanup();
            }
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

    /**
     * Get the list of registered tool providers for debug/diagnostic purposes.
     * @return List of tool providers, or empty list if none registered
     */
    public List<ToolProvider> getToolProviders() {
        return new ArrayList<>(toolProviders);
    }

    /**
     * Get the number of registered PluginTools for debug/diagnostic purposes.
     * @return Number of registered tools
     */
    public int getRegisteredToolsCount() {
        return registeredTools.size();
    }

    /**
     * Get the server host binding for debug/diagnostic purposes.
     * @return Server host string, or null if not configured
     */
    public String getServerHost() {
        if (configManager != null) {
            return configManager.getServerHost();
        }
        return null;
    }
}
