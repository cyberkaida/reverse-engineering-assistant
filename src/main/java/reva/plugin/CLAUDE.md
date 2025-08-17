# CLAUDE.md - Plugin Package

This file provides guidance for working with the ReVa plugin infrastructure components in `/src/main/java/reva/plugin/`.

## Package Overview

The `reva.plugin` package contains the core Ghidra plugin infrastructure that manages the ReVa extension lifecycle, configuration, and program state. This package implements a two-tier plugin architecture:

1. **Application-level plugin** (`RevaApplicationPlugin`) - Manages MCP server at Ghidra application level
2. **Tool-level plugin** (`RevaPlugin`) - Handles program lifecycle in individual analysis tools

## Plugin Architecture

### Two-Tier Plugin Design

ReVa uses Ghidra's dual plugin architecture to ensure the MCP server persists across tool sessions:

```java
// Application-level: persists across tool sessions
@PluginInfo(status = PluginStatus.RELEASED, packageName = "ReVa")
public class RevaApplicationPlugin extends Plugin implements ApplicationLevelOnlyPlugin, ProjectListener

// Tool-level: connects individual tools to the application-level service
@PluginInfo(status = PluginStatus.RELEASED, packageName = "ReVa")
public class RevaPlugin extends ProgramPlugin
```

### Plugin Lifecycle Patterns

#### Application Plugin Lifecycle
- **Initialization**: Creates `McpServerManager`, registers services, starts MCP server
- **Project events**: Handles project open/close but keeps server running
- **Shutdown**: Graceful server shutdown with priority-based shutdown hooks

#### Tool Plugin Lifecycle
- **Initialization**: Connects to application-level MCP service, registers with server
- **Program events**: Notifies MCP service and program manager of program open/close
- **Cleanup**: Unregisters from MCP service, cleans tool-specific resources

## Configuration Management

### ConfigManager - Ghidra Options Integration

`ConfigManager` provides centralized configuration using Ghidra's official `OptionsChangeListener`:

```java
public class ConfigManager implements OptionsChangeListener {
    // Configuration categories
    public static final String SERVER_OPTIONS = "ReVa Server Options";
    
    // Option registration with Ghidra
    private void registerOptionsWithGhidra() {
        HelpLocation help = new HelpLocation("ReVa", "Configuration");
        toolOptions.registerOption(SERVER_PORT, DEFAULT_PORT, help, "Port number for the ReVa MCP server");
    }
}
```

### Configuration Options and Defaults

| Option | Default | Description |
|--------|---------|-------------|
| `SERVER_PORT` | 8080 | MCP server port number |
| `SERVER_ENABLED` | true | Whether MCP server is enabled |
| `DEBUG_MODE` | false | Enable debug logging |
| `MAX_DECOMPILER_SEARCH_FUNCTIONS` | 1000 | Function limit for search operations |
| `DECOMPILER_TIMEOUT_SECONDS` | 10 | Decompiler operation timeout |

### Configuration Change Handling

The system supports two levels of configuration change listeners:

1. **Ghidra's OptionsChangeListener**: Automatic detection of changes from Ghidra UI or programmatic calls
2. **Custom ConfigChangeListener**: Application-specific handling of configuration changes

```java
// Ghidra's official callback - called for ANY configuration change
@Override
public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue) {
    // Update cache and notify custom listeners
    cachedOptions.put(optionName, newValue);
    notifyConfigChangeListeners(SERVER_OPTIONS, optionName, oldValue, newValue);
}

// Custom listener interface for application-specific handling
public interface ConfigChangeListener {
    void onConfigChanged(String category, String name, Object oldValue, Object newValue);
}
```

## Program State Management

### RevaProgramManager - Program Tracking

`RevaProgramManager` provides centralized access to open programs across all Ghidra tools:

```java
public class RevaProgramManager {
    // Get all open programs from any tool
    public static List<Program> getOpenPrograms()
    
    // Program lifecycle management
    public static void programOpened(Program program)
    public static void programClosed(Program program)
    
    // Program lookup by path
    public static Program getProgramByPath(String programPath)
}
```

### Program Caching Strategy

The manager implements a multi-tier caching strategy:

1. **Registered programs**: Direct program registration (test environments)
2. **Program cache**: Cached programs by canonical path
3. **Tool manager lookup**: Active programs in running tools
4. **Domain file opening**: Open programs from project files as needed

### Program Path Resolution

Always use canonical domain paths for consistent program identification:

```java
// Get canonical path for caching
public static String getCanonicalProgramPath(Program program) {
    return program.getDomainFile().getPathname();
}

// Program lookup supports multiple path formats
// 1. Domain path: "/Hatchery.exe" (preferred)
// 2. Executable path: "/path/to/binary"
// 3. Program name: "Hatchery.exe"
```

## Plugin Registration and Setup

### Service Registration Pattern

Use Ghidra's service system for loose coupling between components:

```java
// Application plugin provides services
@PluginInfo(servicesProvided = { RevaMcpService.class })
public class RevaApplicationPlugin extends Plugin {
    @Override
    protected void init() {
        // Register the service with Ghidra
        registerServiceProvided(RevaMcpService.class, serverManager);
        
        // Also register in internal registry for backward compatibility
        RevaInternalServiceRegistry.registerService(McpServerManager.class, serverManager);
    }
}

// Tool plugin consumes services
public class RevaPlugin extends ProgramPlugin {
    @Override
    public void init() {
        // Get service from Ghidra's service system
        mcpService = tool.getService(RevaMcpService.class);
        
        // Fallback for testing environments
        if (mcpService == null) {
            mcpService = RevaInternalServiceRegistry.getService(RevaMcpService.class);
        }
    }
}
```

### Plugin Dependencies

Declare service dependencies in `@PluginInfo`:

```java
@PluginInfo(
    servicesProvided = { RevaMcpService.class },
    servicesRequired = { FrontEndService.class }  // Required for project events
)
```

## Event Handling and Listeners

### Project Event Handling

Application plugin implements `ProjectListener` for project lifecycle:

```java
@Override
public void projectOpened(Project project) {
    this.currentProject = project;
    // MCP server continues running across projects
}

@Override
public void projectClosed(Project project) {
    // Server remains active even when projects close
}
```

### Program Event Handling

Tool plugin overrides `ProgramPlugin` methods:

```java
@Override
protected void programOpened(Program program) {
    // Update program manager cache
    RevaProgramManager.programOpened(program);
    
    // Notify MCP service
    if (mcpService != null) {
        mcpService.programOpened(program, tool);
    }
}

@Override
protected void programClosed(Program program) {
    // Clean up stale cache entries
    RevaProgramManager.programClosed(program);
    
    // Notify MCP service
    if (mcpService != null) {
        mcpService.programClosed(program, tool);
    }
}
```

## Error Handling in Plugin Context

### Configuration Error Handling

Use `OptionsVetoException` to prevent invalid configuration changes:

```java
@Override
public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue) 
        throws OptionsVetoException {
    
    // Validate configuration changes
    if (SERVER_PORT.equals(optionName) && ((Integer) newValue) < 1) {
        throw new OptionsVetoException("Server port must be positive");
    }
}
```

### Service Availability Handling

Always check for service availability and provide graceful degradation:

```java
// Check service availability
if (mcpService == null) {
    Msg.error(this, "RevaMcpService not available - RevaApplicationPlugin may not be loaded");
    return; // Graceful degradation
}

// Handle service method failures
try {
    mcpService.programOpened(program, tool);
} catch (Exception e) {
    Msg.error(this, "Failed to notify MCP service of program opening", e);
    // Continue operation - don't fail the entire plugin
}
```

### Resource Cleanup

Implement proper cleanup in plugin disposal:

```java
@Override
protected void dispose() {
    // Remove listeners to prevent memory leaks
    if (toolOptions != null) {
        toolOptions.removeOptionsChangeListener(this);
    }
    
    // Clear service registrations
    RevaInternalServiceRegistry.unregisterService(RevaPlugin.class);
    
    // Clean up resources
    if (serverManager != null) {
        serverManager.shutdown();
    }
    
    super.dispose();
}
```

## Integration with Ghidra's Tool System

### Tool Service Integration

Leverage Ghidra's service architecture for plugin communication:

```java
// Register tool with MCP service
mcpService.registerTool(tool);

// Access other Ghidra services
ProgramManager programManager = tool.getService(ProgramManager.class);
FrontEndService frontEndService = tool.getService(FrontEndService.class);
```

### Component Provider Integration

For UI components, follow Ghidra's component provider pattern:

```java
// TODO: Implement when UI is needed
// provider = new RevaProvider(this, getName());
// tool.addComponentProvider(provider, false);
```

### Shutdown Hook Registration

Use Ghidra's shutdown system for clean application exit:

```java
ShutdownHookRegistry.addShutdownHook(
    () -> {
        if (serverManager != null) {
            serverManager.shutdown();
        }
    },
    ShutdownPriority.FIRST.after()  // Shutdown after other components
);
```

## Testing Considerations

### Plugin Testing Patterns

1. **Service registry fallback**: Use `RevaInternalServiceRegistry` for test environments where Ghidra's service system isn't available
2. **Direct program registration**: Use `RevaProgramManager.registerProgram()` for test programs
3. **Configuration isolation**: Fork tests to prevent configuration conflicts

### Test Environment Setup

```java
// Test setup - register program directly
RevaProgramManager.registerProgram(testProgram);

// Test setup - register services for components that need them
RevaInternalServiceRegistry.registerService(RevaMcpService.class, mockMcpService);

// Test cleanup - clear all registrations
RevaProgramManager.cleanup();
RevaInternalServiceRegistry.clearAllServices();
```

### Integration Test Requirements

- Tests require `java.awt.headless=false` for Ghidra GUI components
- Fork tests to prevent plugin configuration conflicts
- Use real Ghidra environment for testing plugin lifecycle events

## Common Development Patterns

### Configuration Access Pattern

```java
// Get configuration instance from tool
ConfigManager config = new ConfigManager(tool);

// Access configuration values
int port = config.getServerPort();
boolean enabled = config.isServerEnabled();

// Update configuration (triggers change events)
config.setServerPort(8081);
```

### Service Lookup Pattern

```java
// Primary: Use Ghidra's service system
RevaMcpService service = tool.getService(RevaMcpService.class);

// Fallback: Use internal registry for testing
if (service == null) {
    service = RevaInternalServiceRegistry.getService(RevaMcpService.class);
}

// Always check availability
if (service != null) {
    service.doSomething();
}
```

### Program Access Pattern

```java
// Get all open programs
List<Program> programs = RevaProgramManager.getOpenPrograms();

// Get specific program by path
Program program = RevaProgramManager.getProgramByPath("/Hatchery.exe");

// Register program for test environments
RevaProgramManager.registerProgram(testProgram);
```

## Key Implementation Notes

- **Thread safety**: Use `ConcurrentHashMap.newKeySet()` for listener collections
- **Memory management**: Always remove listeners and clear caches in disposal methods  
- **Error isolation**: Catch and log individual listener failures without affecting others
- **Service lifecycle**: Application plugin manages service creation, tool plugins consume services
- **Configuration persistence**: Ghidra automatically persists registered options
- **Project independence**: MCP server runs at application level, independent of specific projects