# CLAUDE.md - Services Package

This file provides guidance for working with the ReVa services package, which implements the service layer integration between Ghidra plugins and the MCP server.

## Package Overview

The `reva.services` package defines the service interface that bridges the gap between Ghidra's plugin architecture and ReVa's MCP server. It provides a clean abstraction layer that allows tool-level plugins to interact with the application-level MCP server without direct coupling to server implementation details.

### Service Layer Role

The services package serves as:
- **Abstraction Layer**: Decouples tool plugins from MCP server implementation
- **Lifecycle Coordinator**: Manages program and tool lifecycle events across the MCP server
- **Service Bridge**: Connects Ghidra's service architecture with ReVa's MCP capabilities
- **Multi-Tool Support**: Coordinates multiple analysis tools accessing a shared server

## Service Interface: RevaMcpService

The core service interface provides these key capabilities:

### Tool Registration
```java
// Register a tool with the MCP server
mcpService.registerTool(tool);

// Unregister when tool is closing
mcpService.unregisterTool(tool);
```

### Program Lifecycle Management
```java
// Notify server when programs open/close in tools
mcpService.programOpened(program, tool);
mcpService.programClosed(program, tool);

// Track active program for MCP operations
Program active = mcpService.getActiveProgram();
mcpService.setActiveProgram(program, tool);
```

### Server Status Monitoring
```java
// Check server availability
boolean running = mcpService.isServerRunning();
int port = mcpService.getServerPort();
```

## Service Implementation Patterns

### Service Provider (Application Plugin)
The `RevaApplicationPlugin` implements the service provider pattern:

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
        // Initialize server manager
        serverManager = new McpServerManager(tool);
        
        // Register the service
        registerServiceProvided(RevaMcpService.class, serverManager);
        
        // Start MCP server
        serverManager.startServer();
    }
}
```

### Service Consumer (Tool Plugin)
The `RevaPlugin` demonstrates the service consumer pattern:

```java
public class RevaPlugin extends ProgramPlugin {
    private RevaMcpService mcpService;
    
    @Override
    public void init() {
        // Get service from Ghidra's service registry
        mcpService = tool.getService(RevaMcpService.class);
        
        // Fallback for testing environments
        if (mcpService == null) {
            mcpService = RevaInternalServiceRegistry.getService(RevaMcpService.class);
        }
        
        // Register this tool
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

## Service Integration Architecture

### Two-Tier Plugin Architecture
```
Application Level:
├── RevaApplicationPlugin (implements ApplicationLevelOnlyPlugin)
│   ├── Provides: RevaMcpService
│   ├── Manages: McpServerManager
│   └── Lifecycle: Persists across tool sessions

Tool Level:
├── RevaPlugin (extends ProgramPlugin)
│   ├── Consumes: RevaMcpService
│   ├── Handles: Program lifecycle events
│   └── Scope: Per analysis tool instance
```

### Service Registration Flow
1. **Application Startup**: `RevaApplicationPlugin` initializes and starts MCP server
2. **Service Registration**: Plugin registers `RevaMcpService` with Ghidra
3. **Tool Initialization**: Tool plugins request service via `tool.getService()`
4. **Tool Registration**: Tools register themselves with the service
5. **Program Events**: Tools notify service of program open/close events

## MCP Service Implementation

The `McpServerManager` class implements `RevaMcpService` and provides:

### Multi-Tool Coordination
```java
public class McpServerManager implements RevaMcpService {
    // Track registered tools
    private final Set<PluginTool> registeredTools = ConcurrentHashMap.newKeySet();
    
    // Map programs to tools that have them open
    private final Map<Program, Set<PluginTool>> programToTools = new ConcurrentHashMap<>();
    
    // Track active program/tool for MCP operations
    private volatile Program activeProgram;
    private volatile PluginTool activeTool;
}
```

### Program State Management
```java
@Override
public void programOpened(Program program, PluginTool tool) {
    // Track which tools have which programs open
    programToTools.computeIfAbsent(program, k -> ConcurrentHashMap.newKeySet()).add(tool);
    
    // Update active program if this is the most recent
    setActiveProgram(program, tool);
}

@Override
public void programClosed(Program program, PluginTool tool) {
    // Remove tool from program mapping
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
    
    // Register shutdown hook for clean disposal
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

## Service Registration and Discovery

### Ghidra Service Registry (Primary)
```java
// Service provider registration
registerServiceProvided(RevaMcpService.class, serverManager);

// Service consumer discovery
RevaMcpService service = tool.getService(RevaMcpService.class);
```

### Internal Service Registry (Fallback)
```java
// Fallback registration for testing
RevaInternalServiceRegistry.registerService(RevaMcpService.class, serverManager);

// Fallback discovery
RevaMcpService service = RevaInternalServiceRegistry.getService(RevaMcpService.class);
```

## Error Handling in Service Context

### Service Availability Checks
```java
@Override
public void init() {
    mcpService = tool.getService(RevaMcpService.class);
    if (mcpService == null) {
        // Try fallback registry
        mcpService = RevaInternalServiceRegistry.getService(RevaMcpService.class);
    }
    
    if (mcpService == null) {
        Msg.error(this, "RevaMcpService not available - RevaApplicationPlugin may not be loaded");
        return; // Graceful degradation
    }
}
```

### Defensive Service Usage
```java
@Override
protected void programOpened(Program program) {
    // Always check service availability before use
    if (mcpService != null) {
        mcpService.programOpened(program, tool);
    } else {
        Msg.warn(this, "MCP service not available - program event not propagated");
    }
}
```

## Testing Considerations for Services

### Integration Test Setup
```java
public class ServiceIntegrationTest extends RevaIntegrationTestBase {
    @Before
    public void setUp() {
        // Integration tests use shared server manager
        // Service is pre-registered in test base class
        RevaMcpService mcpService = RevaInternalServiceRegistry.getService(RevaMcpService.class);
        assertNotNull("MCP service should be available in tests", mcpService);
    }
}
```

### Service Mocking for Unit Tests
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

## Architectural Role in the Overall System

### Service Layer Position
```
┌─────────────────┐
│   MCP Clients   │ (External AI assistants)
└─────────────────┘
         │
┌─────────────────┐
│   MCP Server    │ (HTTP transport, tools, resources)
└─────────────────┘
         │
┌─────────────────┐
│ Service Layer   │ ← RevaMcpService (this package)
└─────────────────┘
         │
┌─────────────────┐
│ Plugin Layer    │ (RevaApplicationPlugin, RevaPlugin)
└─────────────────┘
         │
┌─────────────────┐
│ Ghidra Core     │ (Programs, functions, data)
└─────────────────┘
```

### Service Responsibilities
- **Upward Interface**: Provides MCP server access to plugins
- **Downward Interface**: Abstracts Ghidra plugin complexity from server
- **Horizontal Coordination**: Manages multi-tool program state
- **Lifecycle Management**: Coordinates startup/shutdown sequences

## Best Practices for Service Implementation

### 1. Service Interface Design
```java
public interface RevaMcpService {
    // Clear, focused interface with single responsibility
    // Methods should be self-documenting with comprehensive JavaDoc
    // Avoid exposing implementation details
    
    /**
     * Register a tool with the MCP server.
     * This allows the tool to receive program lifecycle notifications
     * and participate in MCP server operations.
     * 
     * @param tool The tool to register
     */
    void registerTool(PluginTool tool);
}
```

### 2. Defensive Implementation
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

### 3. Thread-Safe Operations
```java
// Use concurrent collections for multi-tool access
private final Set<PluginTool> registeredTools = ConcurrentHashMap.newKeySet();
private final Map<Program, Set<PluginTool>> programToTools = new ConcurrentHashMap<>();

// Use volatile for shared state
private volatile Program activeProgram;
```

### 4. Proper Cleanup
```java
@Override
public void unregisterTool(PluginTool tool) {
    registeredTools.remove(tool);
    
    // Clean up any program associations
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

### 5. Comprehensive Logging
```java
// Provide visibility into service operations
Msg.info(this, "Tool registered: " + tool.getName() + " (total: " + registeredTools.size() + ")");
Msg.debug(this, "Program opened: " + program.getName() + " in tool: " + tool.getName());
```

## Service Configuration

Services can be configured through the `ConfigManager`:

```java
public class McpServerManager implements RevaMcpService, ConfigChangeListener {
    private final ConfigManager configManager;
    
    public McpServerManager(PluginTool tool) {
        configManager = new ConfigManager(tool);
        configManager.addConfigChangeListener(this);
    }
    
    @Override
    public void onConfigChanged(String setting, Object newValue) {
        // React to configuration changes
        if ("serverPort".equals(setting)) {
            restartServer();
        }
    }
}
```

This service layer design provides a clean, maintainable interface between Ghidra's plugin architecture and ReVa's MCP server capabilities, ensuring proper lifecycle management and multi-tool coordination.