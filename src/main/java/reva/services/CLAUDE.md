# CLAUDE.md - Services Package

This file provides guidance for working with the ReVa services package, which implements the service layer integration between Ghidra plugins and the MCP server.

## Quick Reference

| Item | Value |
|------|-------|
| **Service Interface** | `RevaMcpService` |
| **Service Provider** | `RevaApplicationPlugin` (application-level) |
| **Service Consumer** | `RevaPlugin` (tool-level) |
| **Implementation** | `McpServerManager` |
| **MCP SDK Version** | v0.17.0 |
| **Jackson Version** | 2.20.x |
| **PyGhidra Version** | 3.0.0+ |

## Package Overview

The `reva.services` package defines the service interface that bridges the gap between Ghidra's plugin architecture and ReVa's MCP server. It provides a clean abstraction layer that allows tool-level plugins to interact with the application-level MCP server without direct coupling to server implementation details.

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
│                     MCP Server Layer                            │
│              (McpServerManager, Jetty, Transport)               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Service Layer                                │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              RevaMcpService Interface                       ││
│  │  • Tool registration      • Program lifecycle               ││
│  │  • Server status          • Multi-tool coordination         ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Plugin Layer                                 │
│  ┌─────────────────┐              ┌─────────────────────────┐  │
│  │ RevaApplication │─────────────▶│ RevaPlugin (per-tool)   │  │
│  │ Plugin (shared) │              │ RevaPlugin (per-tool)   │  │
│  └─────────────────┘              │ RevaPlugin (per-tool)   │  │
│                                   └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Ghidra Core                                  │
│              (Programs, functions, data)                        │
└─────────────────────────────────────────────────────────────────┘
```

### Service Layer Responsibilities

| Responsibility | Description |
|----------------|-------------|
| Abstraction Layer | Decouples tool plugins from MCP server implementation |
| Lifecycle Coordinator | Manages program and tool lifecycle events across the MCP server |
| Service Bridge | Connects Ghidra's service architecture with ReVa's MCP capabilities |
| Multi-Tool Support | Coordinates multiple analysis tools accessing a shared server |

## Core Interface: RevaMcpService

### Interface Methods

| Method | Description |
|--------|-------------|
| `registerTool(tool)` | Register a tool with the MCP server |
| `unregisterTool(tool)` | Unregister when tool is closing |
| `programOpened(program, tool)` | Notify server when program opens in tool |
| `programClosed(program, tool)` | Notify server when program closes in tool |
| `getActiveProgram()` | Get current active program for MCP operations |
| `setActiveProgram(program, tool)` | Set active program for MCP operations |
| `isServerRunning()` | Check server availability |
| `getServerPort()` | Get current server port |

### Usage Examples

```java
// Tool Registration
mcpService.registerTool(tool);
mcpService.unregisterTool(tool);

// Program Lifecycle
mcpService.programOpened(program, tool);
mcpService.programClosed(program, tool);

// Active Program Management
Program active = mcpService.getActiveProgram();
mcpService.setActiveProgram(program, tool);

// Server Status
boolean running = mcpService.isServerRunning();
int port = mcpService.getServerPort();
```

## Two-Tier Plugin Architecture

### Plugin Roles

| Plugin | Level | Role | Lifecycle |
|--------|-------|------|-----------|
| `RevaApplicationPlugin` | Application | Provides RevaMcpService, manages McpServerManager | Persists across tool sessions |
| `RevaPlugin` | Tool | Consumes RevaMcpService, handles program events | Per analysis tool instance |

### Service Provider (Application Plugin)

```java
@PluginInfo(
    servicesProvided = { RevaMcpService.class },
    servicesRequired = { FrontEndService.class }
)
public class RevaApplicationPlugin extends Plugin
    implements ApplicationLevelOnlyPlugin, ProjectListener {

    private McpServerManager serverManager;

    @Override
    protected void init() {
        serverManager = new McpServerManager(tool);
        registerServiceProvided(RevaMcpService.class, serverManager);
        serverManager.startServer();
    }
}
```

### Service Consumer (Tool Plugin)

```java
public class RevaPlugin extends ProgramPlugin {
    private RevaMcpService mcpService;

    @Override
    public void init() {
        // Primary: Ghidra's service registry
        mcpService = tool.getService(RevaMcpService.class);

        // Fallback: Internal registry for testing
        if (mcpService == null) {
            mcpService = RevaInternalServiceRegistry.getService(RevaMcpService.class);
        }

        if (mcpService != null) {
            mcpService.registerTool(tool);
        }
    }

    @Override
    protected void programOpened(Program program) {
        if (mcpService != null) {
            mcpService.programOpened(program, tool);
        }
    }
}
```

## Service Registration Flow

1. **Application Startup**: `RevaApplicationPlugin` initializes and starts MCP server
2. **Service Registration**: Plugin registers `RevaMcpService` with Ghidra
3. **Tool Initialization**: Tool plugins request service via `tool.getService()`
4. **Tool Registration**: Tools register themselves with the service
5. **Program Events**: Tools notify service of program open/close events

## Multi-Tool Coordination

### Thread-Safe State Management

```java
public class McpServerManager implements RevaMcpService {
    // Thread-safe collections for multi-tool tracking
    private final Set<PluginTool> registeredTools = ConcurrentHashMap.newKeySet();
    private final Map<Program, Set<PluginTool>> programToTools = new ConcurrentHashMap<>();

    // Volatile for cross-thread visibility
    private volatile Program activeProgram;
    private volatile PluginTool activeTool;
}
```

### Program State Tracking

```java
@Override
public void programOpened(Program program, PluginTool tool) {
    programToTools.computeIfAbsent(program, k -> ConcurrentHashMap.newKeySet()).add(tool);
    setActiveProgram(program, tool);
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
}
```

## Service Lifecycle Management

### Application-Level Lifecycle

```java
// In RevaApplicationPlugin
@Override
protected void init() {
    serverManager = new McpServerManager(tool);
    registerServiceProvided(RevaMcpService.class, serverManager);
    serverManager.startServer();

    // Shutdown hook for clean disposal
    ShutdownHookRegistry.addShutdownHook(() -> {
        if (serverManager != null) {
            serverManager.shutdown();
        }
    }, ShutdownPriority.FIRST.after());
}

@Override
protected void dispose() {
    if (serverManager != null) {
        serverManager.shutdown();
    }
    RevaInternalServiceRegistry.clearAllServices();
}
```

### Tool-Level Lifecycle

```java
// In RevaPlugin
@Override
protected void cleanup() {
    if (mcpService != null) {
        mcpService.unregisterTool(tool);
    }
    RevaInternalServiceRegistry.unregisterService(RevaPlugin.class);
}
```

## Service Discovery

### Discovery Methods

| Method | Usage | Context |
|--------|-------|---------|
| `tool.getService(RevaMcpService.class)` | Primary | Ghidra runtime |
| `RevaInternalServiceRegistry.getService()` | Fallback | Testing, headless |

### Discovery Pattern

```java
@Override
public void init() {
    mcpService = tool.getService(RevaMcpService.class);
    if (mcpService == null) {
        mcpService = RevaInternalServiceRegistry.getService(RevaMcpService.class);
    }

    if (mcpService == null) {
        Msg.error(this, "RevaMcpService not available - RevaApplicationPlugin may not be loaded");
        return; // Graceful degradation
    }
}
```

## Configuration Integration

The service layer integrates with ConfigManager for dynamic configuration:

```java
public class McpServerManager implements RevaMcpService, ConfigChangeListener {
    private final ConfigManager configManager;

    public McpServerManager(PluginTool tool) {
        configManager = new ConfigManager(tool);
        configManager.addConfigChangeListener(this);
    }

    @Override
    public void onConfigChanged(String setting, Object newValue) {
        if ("serverPort".equals(setting)) {
            restartServer();
        }
    }
}
```

## Best Practices

### 1. Defensive Service Usage

```java
// Always check service availability
if (mcpService != null) {
    mcpService.programOpened(program, tool);
} else {
    Msg.warn(this, "MCP service not available - program event not propagated");
}
```

### 2. Null-Safe Registration

```java
@Override
public void registerTool(PluginTool tool) {
    if (tool == null) {
        Msg.warn(this, "Attempted to register null tool");
        return;
    }
    if (registeredTools.contains(tool)) {
        Msg.debug(this, "Tool already registered: " + tool.getName());
        return;
    }
    registeredTools.add(tool);
    Msg.info(this, "Registered tool: " + tool.getName());
}
```

### 3. Proper Cleanup on Unregister

```java
@Override
public void unregisterTool(PluginTool tool) {
    registeredTools.remove(tool);

    // Clean up program associations
    programToTools.entrySet().removeIf(entry -> {
        entry.getValue().remove(tool);
        return entry.getValue().isEmpty();
    });

    // Clear active state if this was the active tool
    if (activeTool == tool) {
        activeProgram = null;
        activeTool = null;
    }
}
```

## Testing

### Integration Test Setup

```java
public class ServiceIntegrationTest extends RevaIntegrationTestBase {
    @Before
    public void setUp() {
        RevaMcpService mcpService = RevaInternalServiceRegistry.getService(RevaMcpService.class);
        assertNotNull("MCP service should be available in tests", mcpService);
    }
}
```

### Graceful Degradation Testing

```java
public class PluginUnitTest {
    @Test
    public void testPluginWithoutService() {
        // Test graceful handling when service is unavailable
        RevaPlugin plugin = new RevaPlugin(mockTool);
        plugin.init(); // Should not throw exception
    }
}
```

## Troubleshooting

### Service Not Available

| Symptom | Cause | Solution |
|---------|-------|----------|
| `mcpService == null` after `getService()` | RevaApplicationPlugin not loaded | Check Ghidra Extensions for ReVa |
| Service methods throw NPE | Service disposed during shutdown | Add null checks before service calls |
| Program events not propagated | Tool not registered | Call `mcpService.registerTool(tool)` in `init()` |

### Multi-Tool Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| Wrong active program | Multiple tools updating active program | Use `setActiveProgram()` on focus change |
| Program still tracked after close | Tool didn't call `programClosed()` | Ensure cleanup in `programClosed()` override |
| Tool not receiving events | Tool not registered with service | Verify `registerTool()` called during init |

### Lifecycle Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| Server not stopped on Ghidra exit | Missing shutdown hook | Register with `ShutdownHookRegistry` |
| Leaked resources after tool close | Missing `cleanup()` implementation | Implement `unregisterTool()` in cleanup |
| Service errors in headless mode | Using Ghidra registry in headless | Use `RevaInternalServiceRegistry` fallback |

## Critical Implementation Notes

- **Thread Safety**: Use `ConcurrentHashMap.newKeySet()` for tool sets, `ConcurrentHashMap` for program mappings
- **Volatile Fields**: `activeProgram`, `activeTool` must be volatile for cross-thread visibility
- **Defensive Coding**: Always null-check service before use; gracefully degrade if unavailable
- **Proper Cleanup**: Unregister tools and clear program associations on shutdown
- **Two Registries**: Support both Ghidra's service registry (primary) and internal registry (testing/headless)
- **Comprehensive Logging**: Log registration, unregistration, and program lifecycle events

## Related Documentation

- `/src/main/java/reva/server/CLAUDE.md` - MCP server implementation, provider registration
- `/src/main/java/reva/plugin/CLAUDE.md` - ConfigManager, plugin architecture
- `/src/main/java/reva/tools/CLAUDE.md` - Tool provider patterns
- `/src/main/java/reva/resources/CLAUDE.md` - Resource provider patterns
- `/src/main/java/reva/headless/CLAUDE.md` - Headless mode service usage
