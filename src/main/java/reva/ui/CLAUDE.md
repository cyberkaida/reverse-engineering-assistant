# CLAUDE.md - UI Package

This file provides guidance for working with the ReVa user interface components in `/src/main/java/reva/ui/`.

## Package Overview

The `reva.ui` package contains UI components for the ReVa (Reverse Engineering Assistant) Ghidra extension. This package provides graphical interfaces for monitoring and configuring the MCP server, though it's currently of **lower priority** compared to the core server/tools functionality. The UI components integrate with Ghidra's docking framework and follow Ghidra's ComponentProvider patterns.

**Note**: This package is less critical for core reverse engineering functionality. The primary ReVa capabilities are exposed through the MCP server interface, making the UI optional for most use cases.

## UI Architecture

### ComponentProvider Pattern

ReVa UI follows Ghidra's standard `ComponentProvider` pattern for creating dockable UI panels:

```java
public class RevaProvider extends ComponentProvider {
    private JPanel panel;
    private JTextArea statusArea;
    private DockingAction configAction;
    
    public RevaProvider(Plugin plugin, String owner) {
        super(plugin.getTool(), "ReVa Provider", owner);
        buildPanel();
        createActions();
    }
}
```

### UI Integration with Plugin System

The UI provider integrates with the plugin architecture through the tool-level plugin:

```java
// In RevaPlugin.java - UI creation is currently commented out (TODO)
// provider = new RevaProvider(this, getName());
// tool.addComponentProvider(provider, false);
```

## Key Components

### RevaProvider - Main UI Component

`RevaProvider` is the primary UI component that provides:

1. **Status Display**: Text area showing MCP server status and activity
2. **Configuration Actions**: Toolbar actions for server configuration
3. **Dockable Interface**: Integrates with Ghidra's docking window system

```java
public class RevaProvider extends ComponentProvider {
    // Status monitoring
    public void setStatusText(String status) {
        statusArea.append(status + "\n");
        statusArea.setCaretPosition(statusArea.getText().length());
    }
    
    // UI component access
    @Override
    public JComponent getComponent() {
        return panel;
    }
}
```

## UI Component Development Patterns

### Panel Construction

Follow Ghidra's UI patterns for consistent look and feel:

```java
private void buildPanel() {
    panel = new JPanel(new BorderLayout());
    
    // Status area with scroll support
    statusArea = new JTextArea(10, 40);
    statusArea.setEditable(false);
    
    // Add components to panel
    panel.add(new JScrollPane(statusArea), BorderLayout.CENTER);
    
    setVisible(true);
}
```

### Action Creation

Use Ghidra's `DockingAction` for toolbar and menu integration:

```java
private void createActions() {
    configAction = new DockingAction("ReVa Configuration", getName()) {
        @Override
        public void actionPerformed(ActionContext context) {
            // TODO: Show configuration dialog
            JOptionPane.showMessageDialog(panel,
                "ReVa Configuration (TODO)",
                "ReVa Configuration",
                JOptionPane.INFORMATION_MESSAGE);
        }
    };
    
    // Configure action properties
    configAction.setToolBarData(new ToolBarData(Icons.HELP_ICON, null));
    configAction.setEnabled(true);
    configAction.setDescription("Configure ReVa");
    configAction.setHelpLocation(new HelpLocation("ReVa", "Configuration"));
    
    addLocalAction(configAction);
}
```

## UI Lifecycle Management

### ComponentProvider Lifecycle

The UI components follow Ghidra's ComponentProvider lifecycle:

1. **Construction**: Create UI components and actions
2. **Registration**: Add provider to tool with `tool.addComponentProvider()`
3. **Visibility**: Control visibility with `setVisible()`
4. **Cleanup**: Remove provider with `tool.removeComponentProvider()`

```java
// Plugin initialization (currently disabled)
@Override
public void init() {
    // TODO: Create the UI provider when needed
    // provider = new RevaProvider(this, getName());
    // tool.addComponentProvider(provider, false);
}

// Plugin cleanup
@Override
protected void cleanup() {
    // Remove the UI provider
    if (provider != null) {
        tool.removeComponentProvider(provider);
    }
}
```

### UI State Management

Status updates are managed through simple text appending:

```java
public void setStatusText(String status) {
    statusArea.append(status + "\n");
    statusArea.setCaretPosition(statusArea.getText().length());
}
```

**Future Enhancement**: Consider implementing structured status models for more sophisticated UI updates.

## Integration with Ghidra's Tool System

### Docking Framework Integration

ReVa UI integrates with Ghidra's docking framework:

- **Dockable panels**: UI can be docked, undocked, and repositioned
- **Window management**: Integrates with Ghidra's window layout system
- **Tool integration**: Responds to tool lifecycle events

### Icon and Resource Management

Use Ghidra's icon system for consistent UI appearance:

```java
// Using standard Ghidra icons
configAction.setToolBarData(new ToolBarData(Icons.HELP_ICON, null));

// For custom icons, place in resources and reference appropriately
// configAction.setToolBarData(new ToolBarData(new GIcon("images/reva-icon.png"), null));
```

### Help System Integration

Integrate with Ghidra's help system:

```java
configAction.setHelpLocation(new HelpLocation("ReVa", "Configuration"));
```

## User Interaction Patterns

### Status Monitoring

The primary user interaction is passive monitoring of MCP server status:

```java
// Current pattern: Simple text status updates
setStatusText("ReVa Model Context Protocol server is running");
setStatusText("Client connected: " + clientInfo);
setStatusText("Request processed: " + requestType);
```

### Configuration Interface

Currently implemented as a placeholder dialog:

```java
// TODO implementation - simple message dialog
JOptionPane.showMessageDialog(panel,
    "ReVa Configuration (TODO)",
    "ReVa Configuration", 
    JOptionPane.INFORMATION_MESSAGE);
```

**Future Enhancement**: Replace with proper configuration dialog using Ghidra's options system.

## Event Handling in UI Context

### Action Event Handling

UI actions follow standard Swing/Ghidra patterns:

```java
configAction = new DockingAction("ReVa Configuration", getName()) {
    @Override
    public void actionPerformed(ActionContext context) {
        // Handle configuration action
        showConfigurationDialog();
    }
};
```

### Status Update Events

Status updates are currently push-based from external components:

```java
// External components push status updates
if (provider != null) {
    provider.setStatusText("Server started on port " + port);
}
```

**Future Enhancement**: Consider implementing event-driven status updates using observer pattern.

## Testing Considerations for UI Components

### UI Testing Challenges

UI components present unique testing challenges:

1. **Headless environment**: Ghidra UI requires `java.awt.headless=false`
2. **Component lifecycle**: Need to test provider registration/unregistration
3. **Action testing**: Verify action availability and behavior
4. **Threading**: UI updates must occur on EDT (Event Dispatch Thread)

### Testing Patterns

```java
// Test setup for UI components
@Before
public void setUp() {
    // Ensure GUI environment
    System.setProperty("java.awt.headless", "false");
    
    // Create test plugin and provider
    plugin = new RevaPlugin(mockTool);
    provider = new RevaProvider(plugin, "Test");
}

// Test action registration
@Test
public void testConfigActionRegistered() {
    List<DockingAction> actions = provider.getLocalActions();
    assertNotNull("Config action should be registered", 
        findActionByName(actions, "ReVa Configuration"));
}

// Test status updates
@Test
public void testStatusTextUpdate() {
    provider.setStatusText("Test status");
    String text = getStatusAreaText();
    assertTrue("Status should contain test message", 
        text.contains("Test status"));
}
```

### Integration Test Requirements

- Use `@Fork` annotation to prevent UI state pollution between tests
- Test actual component provider registration with tool
- Verify UI responds correctly to plugin lifecycle events

## Relationship to Headless/Server Operations

### UI Optional Design

The ReVa architecture deliberately makes UI components optional:

1. **Core functionality**: All reverse engineering capabilities available through MCP server
2. **Headless operation**: Server can run without any UI components
3. **Optional enhancement**: UI provides monitoring and configuration convenience

### Server Integration

UI components integrate with server operations for monitoring:

```java
// UI provides status visibility for server operations
public void notifyServerStarted(int port) {
    if (provider != null) {
        provider.setStatusText("MCP server started on port " + port);
    }
}

public void notifyClientConnected(String clientInfo) {
    if (provider != null) {
        provider.setStatusText("Client connected: " + clientInfo);
    }
}
```

### Headless Compatibility

Always check for UI availability before using:

```java
// Pattern for headless-compatible code
if (provider != null) {
    provider.setStatusText(status);
} else {
    // Fallback for headless environments
    Msg.info(this, status);
}
```

## Future UI Development Guidelines

### Configuration Dialog Implementation

When implementing the configuration dialog:

```java
// Use Ghidra's OptionsDialog pattern
public class RevaConfigurationDialog extends DialogComponentProvider {
    private ConfigManager configManager;
    
    public RevaConfigurationDialog(ConfigManager config) {
        super("ReVa Configuration", true, true, true, false);
        this.configManager = config;
        buildDialog();
    }
    
    private void buildDialog() {
        // Use Ghidra's options panel components
        JPanel panel = new JPanel(new BorderLayout());
        
        // Server configuration section
        JPanel serverPanel = createServerConfigPanel();
        panel.add(serverPanel, BorderLayout.NORTH);
        
        // Add OK/Cancel buttons
        addOKButton();
        addCancelButton();
        
        addWorkPanel(panel);
    }
}
```

### Advanced Status Display

Consider implementing structured status display:

```java
// Enhanced status model
public class ServerStatus {
    private final ServerState state;
    private final int connectedClients;
    private final long requestCount;
    private final List<String> recentActivity;
    
    // Update UI with structured data
    public void updateStatusDisplay(ServerStatus status) {
        updateServerStateIndicator(status.getState());
        updateClientCountDisplay(status.getConnectedClients());
        updateActivityLog(status.getRecentActivity());
    }
}
```

### Event-Driven Updates

Implement observer pattern for status updates:

```java
public interface StatusUpdateListener {
    void onStatusChanged(ServerStatus status);
    void onClientConnected(ClientInfo client);
    void onRequestProcessed(RequestInfo request);
}

// UI provider implements listener
public class RevaProvider extends ComponentProvider implements StatusUpdateListener {
    @Override
    public void onStatusChanged(ServerStatus status) {
        SwingUtilities.invokeLater(() -> updateUI(status));
    }
}
```

## Common UI Development Patterns

### Safe UI Updates

Always update UI on the Event Dispatch Thread:

```java
public void updateStatus(String message) {
    SwingUtilities.invokeLater(() -> {
        statusArea.append(message + "\n");
        statusArea.setCaretPosition(statusArea.getText().length());
    });
}
```

### Resource Management

Properly manage UI resources:

```java
@Override
public void dispose() {
    // Clean up UI resources
    if (statusUpdateTimer != null) {
        statusUpdateTimer.stop();
    }
    
    // Remove listeners
    configManager.removeConfigChangeListener(this);
    
    super.dispose();
}
```

### Error Handling in UI

Handle UI errors gracefully:

```java
private void showConfigurationDialog() {
    try {
        RevaConfigurationDialog dialog = new RevaConfigurationDialog(configManager);
        DockingWindowManager.showDialog(dialog);
    } catch (Exception e) {
        Msg.showError(this, getComponent(), "Configuration Error", 
            "Failed to show configuration dialog", e);
    }
}
```

## Key Implementation Notes

- **Low priority**: UI components are secondary to core MCP server functionality
- **Optional operation**: System must work without UI components
- **Headless compatibility**: Always check for UI availability before use
- **Ghidra integration**: Follow Ghidra's ComponentProvider and docking patterns
- **Thread safety**: Use EDT for all UI updates
- **Resource cleanup**: Properly dispose of UI resources and listeners
- **Future enhancement**: Current implementation is basic, designed for future expansion
- **Testing requirements**: UI tests need `java.awt.headless=false` and component lifecycle testing