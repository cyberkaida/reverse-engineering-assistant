# CLAUDE.md - Server Package

This file provides guidance for Claude Code when working with the ReVa MCP server architecture in the `reva.server` package.

## Quick Reference

| Item | Value |
|------|-------|
| **MCP Endpoint** | `http://localhost:8080/mcp/message` |
| **Transport** | Streamable HTTP (NOT SSE) |
| **MCP SDK Version** | v0.17.0 |
| **Jetty Version** | 11.0.26 |
| **Default Port** | 8080 |
| **Default Host** | 127.0.0.1 (localhost) |

## Package Overview

The `reva.server` package contains the core MCP (Model Context Protocol) server implementation that enables AI-assisted reverse engineering through Ghidra. The server uses Jetty with streamable HTTP transport to provide real-time communication between AI clients and Ghidra's analysis capabilities.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        MCP Clients                              │
│  (Claude CLI, VSCode, other MCP clients)                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                    HTTP POST /mcp/message
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Jetty HTTP Server                           │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              ApiKeyAuthFilter (optional)                    ││
│  └─────────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────────┐│
│  │     HttpServletStreamableServerTransportProvider            ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    McpSyncServer                                │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ Tool Providers  │  │Resource Providers│  │   Prompts      │ │
│  │     (17)        │  │      (1+)       │  │   (future)     │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Ghidra Programs                              │
│              (via RevaProgramManager)                           │
└─────────────────────────────────────────────────────────────────┘
```

### Key Architecture Components

- **MCP Server**: Built on MCP SDK v0.17.0 with streamable transport (NOT SSE)
- **HTTP Server**: Jetty 11.0.26 embedded servlet container
- **Transport Layer**: HttpServletStreamableServerTransportProvider for bidirectional streaming
- **Security Layer**: Optional API key authentication via ApiKeyAuthFilter
- **Service Registry**: Integration with RevaInternalServiceRegistry for component coordination
- **Configuration Management**: Dynamic configuration with automatic server restart on changes

## Core Classes

### McpServerManager

The central orchestrator for the entire MCP server infrastructure. Implements `RevaMcpService` interface.

**Key Responsibilities:**

| Responsibility | Description |
|----------------|-------------|
| Server Lifecycle | Start, stop, restart with graceful handling |
| Transport Config | Jetty server setup with streamable HTTP |
| Provider Registration | 17 tool providers + resource providers |
| Multi-Tool Coordination | Track programs across Ghidra tool instances |
| Configuration | Dynamic response to config changes |
| Security | Optional API key authentication |

### ApiKeyAuthFilter

Optional servlet filter for API key authentication:
- Header: `X-API-Key`
- Disabled by default
- Returns HTTP 401 on invalid key
- Logs authentication attempts

## Server Configuration

### MCP Server Initialization

```java
// Server capabilities (MCP SDK v0.17.0)
McpSchema.ServerCapabilities serverCapabilities = McpSchema.ServerCapabilities.builder()
    .prompts(true)           // Support prompt templates
    .resources(true, true)   // Support resources with subscriptions
    .tools(true)             // Support tool calls
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

### Streamable Transport Configuration

```java
// Transport provider configuration (MCP SDK v0.17.0)
// Note: objectMapper uses McpJsonMapper.getDefault() automatically
currentTransportProvider = HttpServletStreamableServerTransportProvider.builder()
    .mcpEndpoint(MCP_MSG_ENDPOINT)  // "/mcp/message"
    .keepAliveInterval(java.time.Duration.ofSeconds(30))
    .build();
```

**CRITICAL**: Always use `HttpServletStreamableServerTransportProvider` - NEVER revert to SSE transport.

## Server Lifecycle

### Startup Sequence

1. **Configuration Validation** - Check if server is enabled via ConfigManager
2. **Host/Port Binding** - Configure ServerConnector with host and port
3. **Security Setup** - Add ApiKeyAuthFilter if authentication is enabled
4. **Transport Initialization** - Configure streamable HTTP transport
5. **Provider Registration** - Register all 17 tool providers and resource providers
6. **Server Launch** - Start Jetty server in background GThreadPool thread
7. **Readiness Check** - Wait up to 10 seconds for server to be ready

### Shutdown Sequence

1. **Configuration Cleanup** - Remove config change listeners
2. **Tool Deregistration** - Clear all registered tools and program mappings
3. **Provider Cleanup** - Notify all providers to clean up resources
4. **Server Shutdown** - Stop Jetty server gracefully
5. **MCP Cleanup** - Close MCP server gracefully
6. **Thread Pool Shutdown** - Terminate background thread pool

### Dynamic Restart

The server supports dynamic restart for configuration changes:

```java
public void restartServer() {
    stopServer();
    recreateTransportProvider();
    startServer();
}
```

**Configuration changes that trigger restart:**
- Server port
- Server host binding
- Server enabled/disabled
- API key enabled/disabled
- API key value

## Tool and Resource Providers

### Tool Provider Registration

```java
private void initializeToolProviders() {
    // Core Analysis (6)
    toolProviders.add(new SymbolToolProvider(server));
    toolProviders.add(new StringToolProvider(server));
    toolProviders.add(new FunctionToolProvider(server));
    toolProviders.add(new DecompilerToolProvider(server));
    toolProviders.add(new CrossReferencesToolProvider(server));
    toolProviders.add(new MemoryToolProvider(server));

    // Data & Types (3)
    toolProviders.add(new DataToolProvider(server));
    toolProviders.add(new DataTypeToolProvider(server));
    toolProviders.add(new StructureToolProvider(server));

    // Advanced Analysis (5)
    toolProviders.add(new CallGraphToolProvider(server));
    toolProviders.add(new DataFlowToolProvider(server));
    toolProviders.add(new ConstantSearchToolProvider(server));
    toolProviders.add(new VtableToolProvider(server));
    toolProviders.add(new ImportExportToolProvider(server));

    // Annotations (2)
    toolProviders.add(new CommentToolProvider(server));
    toolProviders.add(new BookmarkToolProvider(server));

    // Project Management (1)
    toolProviders.add(new ProjectToolProvider(server));

    // Register all tools with the server
    // Note: MCP SDK v0.17.0 - tool registration is idempotent
    for (ToolProvider provider : toolProviders) {
        provider.registerTools();
    }
}
```

### Resource Provider Registration

```java
private void initializeResourceProviders() {
    resourceProviders.add(new ProgramListResource(server));
    // ... additional resource providers

    for (ResourceProvider provider : resourceProviders) {
        provider.register();
    }
}
```

## Threading and Concurrency

### Thread-Safe Data Structures

```java
// Thread-safe collections for multi-tool tracking
private final Set<PluginTool> registeredTools = ConcurrentHashMap.newKeySet();
private final Map<Program, Set<PluginTool>> programToTools = new ConcurrentHashMap<>();

// Volatile fields for cross-thread visibility
private volatile Program activeProgram;
private volatile PluginTool activeTool;
private volatile boolean serverReady = false;
```

### Thread Pool Management

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

@Override
public void programClosed(Program program, PluginTool tool) {
    Set<PluginTool> tools = programToTools.get(program);
    if (tools != null) {
        tools.remove(tool);
        if (tools.isEmpty()) {
            programToTools.remove(program);
        }
    }

    // Only notify providers if LAST tool closed the program
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

## Configuration Integration

### Dynamic Configuration Updates

The server implements `ConfigChangeListener`:

```java
@Override
public void onConfigChanged(String category, String name, Object oldValue, Object newValue) {
    if (ConfigManager.SERVER_OPTIONS.equals(category)) {
        // These changes require server restart
        if (ConfigManager.SERVER_PORT.equals(name) ||
            ConfigManager.SERVER_HOST.equals(name) ||
            ConfigManager.SERVER_ENABLED.equals(name) ||
            ConfigManager.API_KEY_ENABLED.equals(name) ||
            ConfigManager.API_KEY.equals(name)) {
            restartServer();
        }
    }
}
```

## Service Registry Integration

```java
// Register services for component access
RevaInternalServiceRegistry.registerService(ConfigManager.class, configManager);
RevaInternalServiceRegistry.registerService(McpSyncServer.class, server);
RevaInternalServiceRegistry.registerService(McpServerManager.class, this);
RevaInternalServiceRegistry.registerService(RevaMcpService.class, this);

// Access services from other components
McpServerManager serverManager = RevaInternalServiceRegistry.getService(McpServerManager.class);
ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
```

## Adding New Providers

### New Tool Provider Checklist

1. Create class extending `AbstractToolProvider`
2. Implement `registerTools()` method
3. Add to `initializeToolProviders()` in McpServerManager
4. Handle `programOpened()` and `programClosed()` events
5. Implement `cleanup()` for shutdown
6. Add package-level CLAUDE.md documentation

### New Resource Provider Checklist

1. Create class extending `AbstractResourceProvider`
2. Implement `register()` method
3. Add to `initializeResourceProviders()` in McpServerManager
4. Handle program lifecycle events
5. Implement `cleanup()` for shutdown

## Constants

```java
private static final String MCP_MSG_ENDPOINT = "/mcp/message";
private static final String MCP_SERVER_NAME = "ReVa";
private static final String MCP_SERVER_VERSION = "1.0.0";
private static final String API_KEY_HEADER = "X-API-Key";

// Timeouts and intervals
private static final int MAX_STARTUP_WAIT = 10000;  // 10 seconds
private static final int STARTUP_CHECK_INTERVAL = 100;  // 100ms
private static final Duration KEEP_ALIVE_INTERVAL = Duration.ofSeconds(30);
```

## Troubleshooting

### Server Won't Start

| Symptom | Cause | Solution |
|---------|-------|----------|
| Port already in use | Another process on port 8080 | Change port in Ghidra settings or stop other process |
| Server not ready timeout | Slow startup or error | Check Ghidra console for errors |
| Jackson conflicts | Wrong Jackson version | Run `rm lib/*.jar` and rebuild |

### Connection Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| Connection refused | Server not running | Ensure Ghidra is running with ReVa enabled |
| 401 Unauthorized | API key mismatch | Check X-API-Key header matches configured key |
| Timeout | Server overloaded | Increase client timeout or reduce concurrent requests |

### Tool Errors

| Symptom | Cause | Solution |
|---------|-------|----------|
| Program not found | Program not open in Ghidra | Open program in Ghidra first |
| Tool not registered | Provider initialization failed | Check logs for registration errors |

## Testing

### Integration Test Setup

```java
// Server manager initialization in tests
McpServerManager serverManager = new McpServerManager(testTool);
serverManager.registerTool(testTool);
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

## Critical Implementation Notes

- **NEVER revert to SSE transport** - Always use `HttpServletStreamableServerTransportProvider`
- **MCP SDK v0.17.0** - Tool registration is idempotent; `McpJsonMapper.getDefault()` used automatically
- **Always restore interrupt status** - Use `Thread.currentThread().interrupt()` after catching `InterruptedException`
- **Volatile for visibility** - `serverReady`, `activeProgram`, `activeTool` must be volatile
- **ConcurrentHashMap for thread safety** - Use `ConcurrentHashMap.newKeySet()` for sets
- **Graceful shutdown** - Always clean up providers, close server, shutdown thread pool
- **Multi-tool coordination** - Notify providers only when LAST tool closes a program
- **Configuration changes trigger restart** - Port, host, enable/disable, API key changes

## Related Documentation

- `/src/main/java/reva/plugin/CLAUDE.md` - ConfigManager, plugin architecture
- `/src/main/java/reva/tools/CLAUDE.md` - Tool provider patterns
- `/src/main/java/reva/resources/CLAUDE.md` - Resource provider patterns
- `/src/main/java/reva/services/CLAUDE.md` - RevaMcpService interface
- `/src/main/java/reva/headless/CLAUDE.md` - Headless mode server usage
