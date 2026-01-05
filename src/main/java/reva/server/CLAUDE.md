# CLAUDE.md - Server Package

This file provides guidance for Claude Code when working with the ReVa MCP server architecture in the `reva.server` package.

## Package Overview

The `reva.server` package contains the core MCP (Model Context Protocol) server implementation that enables AI-assisted reverse engineering through Ghidra. The server uses Jetty with streamable HTTP transport to provide real-time communication between AI clients and Ghidra's analysis capabilities.

### Key Architecture Components

- **MCP Server**: Built on MCP SDK v0.14.0 with streamable transport (NOT SSE)
- **HTTP Server**: Jetty 11.0.26 embedded servlet container
- **Transport Layer**: HttpServletStreamableServerTransportProvider for bidirectional streaming
- **Security Layer**: Optional API key authentication via ApiKeyAuthFilter
- **Service Registry**: Integration with RevaInternalServiceRegistry for component coordination
- **Configuration Management**: Dynamic configuration with automatic server restart on changes

## Core Classes

### McpServerManager

The central orchestrator for the entire MCP server infrastructure. This class manages:

- **Server Lifecycle**: Start, stop, restart operations with graceful handling
- **Transport Configuration**: Jetty server setup with streamable HTTP transport
- **Provider Registration**: Registration of 17 tool providers and resource providers
- **Multi-Tool Coordination**: Tracking programs across multiple Ghidra tool instances
- **Configuration Integration**: Dynamic response to configuration changes with automatic restart
- **Security**: Optional API key authentication filter integration

#### Key Responsibilities

1. **Server Management**
   - Initialize MCP server with capabilities (prompts, resources with subscriptions, tools)
   - Configure Jetty HTTP server with ServerConnector for host/port binding
   - Manage server startup/shutdown lifecycle with readiness checks
   - Handle configuration-driven automatic restarts

2. **Provider Orchestration**
   - Register 17 ToolProvider implementations (symbols, functions, decompiler, data, memory, etc.)
   - Register ResourceProvider implementations (program list, etc.)
   - Coordinate program lifecycle events across all providers
   - Handle provider cleanup on shutdown

3. **Multi-Tool Support**
   - Track which tools have which programs open using ConcurrentHashMap
   - Maintain active program/tool state with volatile fields
   - Coordinate program open/close events across tools
   - Notify providers only when last tool closes a program

4. **Security Management**
   - Optional API key authentication via ApiKeyAuthFilter
   - Configurable server host binding (localhost, 0.0.0.0, etc.)
   - Dynamic authentication configuration with automatic restart

## Server Architecture

### MCP Server Configuration

```java
// Server capabilities configuration
McpSchema.ServerCapabilities serverCapabilities = McpSchema.ServerCapabilities.builder()
    .prompts(true)      // Support prompt templates
    .resources(true, true)  // Support resources with subscriptions
    .tools(true)        // Support tool calls
    .build();

// Server initialization
server = McpServer.sync(currentTransportProvider)
    .serverInfo(MCP_SERVER_NAME, MCP_SERVER_VERSION)
    .capabilities(serverCapabilities)
    .build();
```

### Jetty Server Setup

```java
// Create servlet context handler
ServletContextHandler servletContextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
servletContextHandler.setContextPath("/");

// Add optional API key authentication filter
if (configManager.isApiKeyEnabled()) {
    FilterHolder filterHolder = new FilterHolder(new ApiKeyAuthFilter(configManager));
    servletContextHandler.addFilter(filterHolder, "/*", EnumSet.of(DispatcherType.REQUEST));
}

// Configure servlet with async support
ServletHolder servletHolder = new ServletHolder(currentTransportProvider);
servletHolder.setAsyncSupported(true);
servletContextHandler.addServlet(servletHolder, "/*");

// Configure HTTP server with host binding
httpServer = new Server();
ServerConnector connector = new ServerConnector(httpServer);
connector.setHost(serverHost);  // Configurable: localhost, 0.0.0.0, etc.
connector.setPort(serverPort);
httpServer.addConnector(connector);
httpServer.setHandler(servletContextHandler);
```

### Streamable Transport Implementation

The server uses `HttpServletStreamableServerTransportProvider` for bidirectional streaming:

```java
// Transport provider configuration
// Note: As of MCP SDK v0.14.0, objectMapper uses McpJsonMapper.getDefault() automatically
currentTransportProvider = HttpServletStreamableServerTransportProvider.builder()
    .mcpEndpoint(MCP_MSG_ENDPOINT)  // "/mcp/message"
    .keepAliveInterval(java.time.Duration.ofSeconds(30))
    .build();
```

**CRITICAL**: Always use `HttpServletStreamableServerTransportProvider` - NEVER revert to SSE transport.

## Server Lifecycle Management

### Startup Process

1. **Configuration Validation**: Check if server is enabled via ConfigManager
2. **Host/Port Binding**: Configure ServerConnector with host and port
3. **Security Setup**: Add ApiKeyAuthFilter if authentication is enabled
4. **Transport Initialization**: Configure streamable HTTP transport
5. **Provider Registration**: Register all 17 tool providers and resource providers
6. **Server Launch**: Start Jetty server in background GThreadPool thread
7. **Readiness Check**: Wait up to 10 seconds for server to be ready

### Shutdown Process

1. **Configuration Cleanup**: Remove config change listeners
2. **Tool Deregistration**: Clear all registered tools and program mappings
3. **Provider Cleanup**: Notify all providers to clean up resources
4. **Server Shutdown**: Stop Jetty server gracefully
5. **MCP Cleanup**: Close MCP server gracefully
6. **Thread Pool Shutdown**: Terminate background thread pool

### Restart Handling

The server supports dynamic restart for configuration changes:

```java
public void restartServer() {
    // Stop current server
    stopServer();
    
    // Recreate transport with new configuration
    recreateTransportProvider();
    
    // Start with new configuration
    startServer();
}
```

## Tool and Resource Provider Registration

### Tool Provider Registration Pattern

```java
private void initializeToolProviders() {
    // Create all 17 tool providers
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
    toolProviders.add(new ImportExportToolProvider(server));
    toolProviders.add(new DataFlowToolProvider(server));
    toolProviders.add(new CallGraphToolProvider(server));
    toolProviders.add(new ConstantSearchToolProvider(server));
    toolProviders.add(new VtableToolProvider(server));

    // Register all tools with the server
    // Note: As of MCP SDK v0.14.0, tool registration is idempotent and replaces duplicates
    for (ToolProvider provider : toolProviders) {
        provider.registerTools();
    }
}
```

### Resource Provider Registration Pattern

```java
private void initializeResourceProviders() {
    resourceProviders.add(new ProgramListResource(server));
    // ... additional resource providers
    
    // Register all resources
    for (ResourceProvider provider : resourceProviders) {
        provider.register();
    }
}
```

## Configuration Integration

### Dynamic Configuration Updates

The server implements `ConfigChangeListener` to respond to configuration changes:

```java
@Override
public void onConfigChanged(String category, String name, Object oldValue, Object newValue) {
    if (ConfigManager.SERVER_OPTIONS.equals(category)) {
        if (ConfigManager.SERVER_PORT.equals(name)) {
            // Port changed - restart server
            restartServer();
        } else if (ConfigManager.SERVER_HOST.equals(name)) {
            // Host binding changed - restart server
            restartServer();
        } else if (ConfigManager.SERVER_ENABLED.equals(name)) {
            // Enable/disable changed - restart server
            restartServer();
        } else if (ConfigManager.API_KEY_ENABLED.equals(name)) {
            // API key authentication toggle - restart server
            restartServer();
        } else if (ConfigManager.API_KEY.equals(name)) {
            // API key value changed - restart server
            restartServer();
        }
    }
}
```

### Configuration-Driven Transport Recreation

When configuration changes require transport updates:

```java
private void recreateTransportProvider() {
    int serverPort = configManager.getServerPort();
    String serverHost = configManager.getServerHost();
    String baseUrl = "http://" + serverHost + ":" + serverPort;

    // Note: As of MCP SDK v0.14.0, objectMapper uses McpJsonMapper.getDefault() automatically
    currentTransportProvider = HttpServletStreamableServerTransportProvider.builder()
        .mcpEndpoint(MCP_MSG_ENDPOINT)
        .keepAliveInterval(java.time.Duration.ofSeconds(30))
        .build();
}
```

## Error Handling and Server Stability

### Graceful Startup Error Handling

```java
threadPool.submit(() -> {
    try {
        httpServer.start();
        serverReady = true;
        httpServer.join(); // Blocks until server stops
    } catch (Exception e) {
        if (e instanceof InterruptedException) {
            // Normal shutdown
            Thread.currentThread().interrupt();
        } else {
            Msg.error(this, "Error starting MCP server", e);
        }
    }
});
```

### Server Readiness Validation

```java
// Wait for server startup with timeout
int maxWaitTime = 10000; // 10 seconds
int totalWait = 0;

while (!serverReady && totalWait < maxWaitTime) {
    Thread.sleep(waitInterval);
    totalWait += waitInterval;
}

if (!serverReady) {
    Msg.error(this, "Server failed to start within timeout");
}
```

## Threading and Concurrency

### Thread Pool Management

The server uses Ghidra's `GThreadPool` for background operations:

```java
// Initialize dedicated thread pool
threadPool = GThreadPool.getPrivateThreadPool("ReVa");
RevaInternalServiceRegistry.registerService(GThreadPool.class, threadPool);

// Submit server startup task
threadPool.submit(() -> {
    try {
        httpServer.start();
        serverReady = true;
        httpServer.join(); // Blocks until server stops
    } catch (Exception e) {
        if (e instanceof InterruptedException) {
            Thread.currentThread().interrupt(); // Always restore interrupt status
        } else {
            Msg.error(this, "Error starting MCP server", e);
        }
    }
});

// Shutdown cleanup
threadPool.shutdownNow();
```

### Thread-Safe Data Structures

All server state uses concurrent data structures for thread safety:

```java
// Thread-safe collections for multi-tool tracking
private final Set<PluginTool> registeredTools = ConcurrentHashMap.newKeySet();
private final Map<Program, Set<PluginTool>> programToTools = new ConcurrentHashMap<>();

// Volatile fields for active state (visibility across threads)
private volatile Program activeProgram;
private volatile PluginTool activeTool;
private volatile boolean serverReady = false;
```

**Key Pattern**: Use `ConcurrentHashMap.newKeySet()` for thread-safe Set, `ConcurrentHashMap` for Map, and `volatile` for simple state flags.

### ApiKeyAuthFilter

Optional servlet filter that provides API key authentication:

```java
public class ApiKeyAuthFilter implements Filter {
    private static final String API_KEY_HEADER = "X-API-Key";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        // Check if API key authentication is enabled
        if (!configManager.isApiKeyEnabled()) {
            chain.doFilter(request, response);
            return;
        }

        // Validate X-API-Key header against configured API key
        String providedApiKey = httpRequest.getHeader(API_KEY_HEADER);
        String configuredApiKey = configManager.getApiKey();

        if (providedApiKey == null || !providedApiKey.equals(configuredApiKey)) {
            sendUnauthorizedResponse(httpResponse, "Invalid API key");
            return;
        }

        // API key valid - continue
        chain.doFilter(request, response);
    }
}
```

**Security Features**:
- Optional authentication (disabled by default)
- Checks `X-API-Key` header against configured value
- Returns HTTP 401 with JSON error response on failure
- Logs authentication attempts with client IP and user agent
- Dynamic enable/disable with automatic server restart

## Multi-Tool Program Coordination

### Program Lifecycle Tracking

```java
@Override
public void programOpened(Program program, PluginTool tool) {
    // Add to program-tool mapping
    programToTools.computeIfAbsent(program, k -> ConcurrentHashMap.newKeySet()).add(tool);
    
    // Set as active program
    setActiveProgram(program, tool);
    
    // Notify all providers
    for (ResourceProvider provider : resourceProviders) {
        provider.programOpened(program);
    }
    for (ToolProvider provider : toolProviders) {
        provider.programOpened(program);
    }
}
```

### Program Close Coordination

```java
@Override
public void programClosed(Program program, PluginTool tool) {
    // Remove from mapping
    Set<PluginTool> tools = programToTools.get(program);
    if (tools != null) {
        tools.remove(tool);
        if (tools.isEmpty()) {
            programToTools.remove(program);
        }
    }
    
    // Only notify providers if last tool closed the program
    if (tools == null || tools.isEmpty()) {
        for (ResourceProvider provider : resourceProviders) {
            provider.programClosed(program);
        }
        for (ToolProvider provider : toolProviders) {
            provider.programClosed(program);
        }
    }
}
```

## Testing Patterns for Server Components

### Integration Test Setup

```java
// Server manager initialization in tests
McpServerManager serverManager = new McpServerManager(testTool);

// Register test tool
serverManager.registerTool(testTool);

// Validate server startup
assertTrue("Server should be running", serverManager.isServerRunning());
```

### Server Lifecycle Testing

```java
// Test graceful restart
serverManager.restartServer();
waitForServerReady(serverManager);

// Test configuration change handling
configManager.setServerPort(newPort);
// Verify server restarts automatically

// Test shutdown cleanup
serverManager.shutdown();
assertFalse("Server should be stopped", serverManager.isServerRunning());
```

## Service Registry Integration

### Service Registration Pattern

```java
// Register services for component access
RevaInternalServiceRegistry.registerService(ConfigManager.class, configManager);
RevaInternalServiceRegistry.registerService(McpSyncServer.class, server);
RevaInternalServiceRegistry.registerService(McpServerManager.class, this);
RevaInternalServiceRegistry.registerService(RevaMcpService.class, this);
```

### Service Consumption Pattern

```java
// Access services from other components
McpServerManager serverManager = RevaInternalServiceRegistry.getService(McpServerManager.class);
ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
```

## Common Development Patterns

### Adding New Tool Providers

1. Create provider class extending `AbstractToolProvider`
2. Implement `registerTools()` method to define all tools
3. Add to `initializeToolProviders()` list in McpServerManager
4. Handle program lifecycle events (`programOpened`, `programClosed`) appropriately
5. Implement `cleanup()` method for shutdown

### Adding New Resource Providers

1. Create provider class extending `AbstractResourceProvider`
2. Implement `register()` method to register resources with server
3. Add to `initializeResourceProviders()` list in McpServerManager
4. Handle program lifecycle events appropriately
5. Implement `cleanup()` method for shutdown

### Configuration-Driven Features

1. Add configuration option to `ConfigManager` with getter/setter
2. Add configuration option name constant to `ConfigManager`
3. Implement `onConfigChanged()` in McpServerManager or appropriate component
4. Use `restartServer()` for changes requiring transport/servlet reconfiguration
5. Handle dynamic updates without restart when possible (minimal changes)

## Important Implementation Notes

- **NEVER revert to SSE transport** - Always use `HttpServletStreamableServerTransportProvider` (streamable HTTP)
- **MCP SDK v0.14.0** - Tool registration is idempotent; `McpJsonMapper.getDefault()` used automatically
- **Always restore interrupt status** - Use `Thread.currentThread().interrupt()` after catching `InterruptedException`
- **Volatile for visibility** - `serverReady`, `activeProgram`, `activeTool` must be volatile for thread visibility
- **ConcurrentHashMap for thread safety** - Use `ConcurrentHashMap.newKeySet()` for sets, `ConcurrentHashMap` for maps
- **Graceful shutdown** - Always clean up providers, close server, and shutdown thread pool
- **Multi-tool coordination** - Notify providers only when last tool closes a program
- **Configuration changes trigger restart** - Port, host, enable/disable, API key changes all restart server
- **Host binding for security** - Use `ServerConnector` with configurable host (localhost vs 0.0.0.0)
- **Optional API key auth** - Use `ApiKeyAuthFilter` with X-API-Key header validation

## Constants and Configuration

```java
private static final String MCP_MSG_ENDPOINT = "/mcp/message";
private static final String MCP_SERVER_NAME = "ReVa";
private static final String MCP_SERVER_VERSION = "1.0.0";
private static final String API_KEY_HEADER = "X-API-Key";  // For ApiKeyAuthFilter

// Timeouts and intervals
private static final int MAX_STARTUP_WAIT = 10000; // 10 seconds
private static final int STARTUP_CHECK_INTERVAL = 100; // 100ms
private static final Duration KEEP_ALIVE_INTERVAL = Duration.ofSeconds(30);
```

## Server Classes Summary

- **McpServerManager**: Main server orchestrator, manages lifecycle, providers, and multi-tool coordination
- **ApiKeyAuthFilter**: Optional servlet filter for API key authentication via X-API-Key header