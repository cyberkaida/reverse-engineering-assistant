# CLAUDE.md - Server Package

This file provides guidance for Claude Code when working with the ReVa MCP server architecture in the `reva.server` package.

## Package Overview

The `reva.server` package contains the core MCP (Model Context Protocol) server implementation that enables AI-assisted reverse engineering through Ghidra. The server uses Jetty with streamable transport to provide real-time communication between AI clients and Ghidra's analysis capabilities.

### Key Architecture Components

- **MCP Server**: Built on MCP SDK v0.11.2 with streamable transport
- **HTTP Server**: Jetty 11.0.26 embedded servlet container
- **Transport Layer**: HttpServletStreamableServerTransportProvider for real-time streaming
- **Service Registry**: Integration with RevaInternalServiceRegistry for component coordination
- **Configuration Management**: Dynamic configuration with hot-reload capabilities

## Core Classes

### McpServerManager

The central orchestrator for the entire MCP server infrastructure. This class manages:

- **Server Lifecycle**: Start, stop, restart operations with graceful handling
- **Transport Configuration**: Jetty server setup with streamable transport
- **Provider Registration**: Registration of tool and resource providers
- **Multi-Tool Coordination**: Tracking programs across multiple Ghidra tool instances
- **Configuration Integration**: Dynamic response to configuration changes

#### Key Responsibilities

1. **Server Management**
   - Initialize MCP server with appropriate capabilities
   - Configure Jetty HTTP server with servlet handlers
   - Manage server startup/shutdown lifecycle
   - Handle configuration-driven restarts

2. **Provider Orchestration**
   - Register all ToolProvider implementations
   - Register all ResourceProvider implementations
   - Coordinate program lifecycle events across providers
   - Handle provider cleanup on shutdown

3. **Multi-Tool Support**
   - Track which tools have which programs open
   - Maintain active program/tool state
   - Coordinate program open/close events across tools
   - Prevent resource conflicts between tools

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

// Configure servlet with async support
ServletHolder servletHolder = new ServletHolder(currentTransportProvider);
servletHolder.setAsyncSupported(true);
servletContextHandler.addServlet(servletHolder, "/*");

// Configure HTTP server
httpServer = new Server(serverPort);
httpServer.setHandler(servletContextHandler);
```

### Streamable Transport Implementation

The server uses `HttpServletStreamableServerTransportProvider` for real-time bidirectional communication:

```java
// Transport provider configuration
currentTransportProvider = HttpServletStreamableServerTransportProvider.builder()
    .objectMapper(JSON)
    .mcpEndpoint(MCP_MSG_ENDPOINT)  // "/mcp/message"
    .keepAliveInterval(java.time.Duration.ofSeconds(30))
    .build();
```

## Server Lifecycle Management

### Startup Process

1. **Configuration Validation**: Check if server is enabled
2. **Port Binding**: Attempt to bind to configured port
3. **Transport Initialization**: Configure streamable transport
4. **Provider Registration**: Register all tool and resource providers
5. **Server Launch**: Start Jetty server in background thread
6. **Readiness Check**: Wait for server to be ready with timeout

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
    // Create all tool providers
    toolProviders.add(new SymbolToolProvider(server));
    toolProviders.add(new FunctionToolProvider(server));
    toolProviders.add(new DecompilerToolProvider(server));
    // ... additional providers
    
    // Register with error handling
    for (ToolProvider provider : toolProviders) {
        try {
            provider.registerTools();
        } catch (McpError e) {
            Msg.error(this, "Failed to register tools for provider: " + 
                      provider.getClass().getSimpleName(), e);
        }
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
        } else if (ConfigManager.SERVER_ENABLED.equals(name)) {
            // Enable/disable changed - restart server
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
    String baseUrl = "http://localhost:" + serverPort;
    
    currentTransportProvider = HttpServletStreamableServerTransportProvider.builder()
        .objectMapper(JSON)
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

## Threading and Concurrency Considerations

### Thread Pool Management

The server uses Ghidra's `GThreadPool` for background operations:

```java
// Initialize dedicated thread pool
threadPool = GThreadPool.getPrivateThreadPool("ReVa");
RevaInternalServiceRegistry.registerService(GThreadPool.class, threadPool);

// Submit server startup task
threadPool.submit(() -> {
    // Server startup logic
});

// Shutdown cleanup
threadPool.shutdownNow();
```

### Concurrent Data Structures

For multi-tool coordination:

```java
// Thread-safe collections for multi-tool tracking
private final Set<PluginTool> registeredTools = ConcurrentHashMap.newKeySet();
private final Map<Program, Set<PluginTool>> programToTools = new ConcurrentHashMap<>();

// Volatile fields for active state
private volatile Program activeProgram;
private volatile PluginTool activeTool;
private volatile boolean serverReady = false;
```

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
2. Implement `registerTools()` method
3. Add to `initializeToolProviders()` in McpServerManager
4. Handle program lifecycle events appropriately

### Adding New Resource Providers

1. Create provider class extending `AbstractResourceProvider`
2. Implement `register()` method
3. Add to `initializeResourceProviders()` in McpServerManager
4. Handle program lifecycle events appropriately

### Configuration-Driven Features

1. Add configuration option to `ConfigManager`
2. Implement configuration change listener in appropriate component
3. Handle dynamic updates without requiring full restart when possible
4. Use restart mechanism for changes requiring transport reconfiguration

## Important Implementation Notes

- **Never revert to SSE transport** - Always use HttpServletStreamableServerTransportProvider
- **Always handle InterruptedException** - Restore interrupt status appropriately
- **Use volatile for server state** - serverReady, activeProgram, activeTool must be volatile
- **Graceful shutdown is critical** - Always clean up providers and close server gracefully
- **Multi-tool coordination is essential** - Track program-to-tool mappings carefully
- **Configuration changes require restart** - Port and enable/disable changes need full restart
- **Thread pool management** - Use GThreadPool and shut down properly
- **Error handling is mandatory** - Log errors but continue operation when possible

## Constants and Configuration

```java
private static final String MCP_MSG_ENDPOINT = "/mcp/message";
private static final String MCP_SERVER_NAME = "ReVa";
private static final String MCP_SERVER_VERSION = "1.0.0";

// Timeouts and intervals
private static final int MAX_STARTUP_WAIT = 10000; // 10 seconds
private static final int STARTUP_CHECK_INTERVAL = 100; // 100ms
private static final Duration KEEP_ALIVE_INTERVAL = Duration.ofSeconds(30);
```