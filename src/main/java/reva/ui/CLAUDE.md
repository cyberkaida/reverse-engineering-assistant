# CLAUDE.md - UI Package

This file provides guidance for Claude Code when working with the ReVa user interface components in the `reva.ui` package.

## Quick Reference

| Item | Value |
|------|-------|
| **Priority** | Low - optional UI components |
| **Status** | Basic implementation, designed for future expansion |
| **Files** | RevaProvider.java, CaptureDebugAction.java |
| **Pattern** | Ghidra ComponentProvider/DockingAction |
| **Testing** | Requires `java.awt.headless=false` |

**Note**: This package is **lower priority** compared to core server/tools functionality. The primary ReVa capabilities are exposed through the MCP server interface, making the UI optional for most use cases.

## Package Components

| Component | Purpose | Status |
|-----------|---------|--------|
| `RevaProvider` | Dockable status panel for server monitoring | Basic (TODO items) |
| `CaptureDebugAction` | Menu action for debug info capture | Complete |

## RevaProvider

Main UI component providing a dockable panel for monitoring MCP server status.

### Current Capabilities

- Status text display (append-only text area)
- Configuration action (placeholder dialog)
- Ghidra docking framework integration

### Usage Pattern

```java
// Creation (currently commented out in RevaApplicationPlugin)
provider = new RevaProvider(plugin, getName());
tool.addComponentProvider(provider, false);

// Status updates from server components
if (provider != null) {
    provider.setStatusText("Server started on port " + port);
}

// Cleanup on plugin dispose
if (provider != null) {
    tool.removeComponentProvider(provider);
}
```

### Thread Safety

Always update UI on the Event Dispatch Thread:

```java
public void updateStatus(String message) {
    SwingUtilities.invokeLater(() -> {
        statusArea.append(message + "\n");
        statusArea.setCaretPosition(statusArea.getText().length());
    });
}
```

## CaptureDebugAction

Menu action for capturing debug information (Tools > ReVa > Capture Debug Info).

### Features

- Shows input dialog for user-provided context message
- Creates zip file with debug information via DebugCaptureService
- Displays success/error message with file location

### Dependencies

- `reva.debug.DebugCaptureService` - Performs actual capture
- Ghidra's `DockingAction` and `InputDialog`

## UI Development Patterns

### ComponentProvider Pattern

```java
public class RevaProvider extends ComponentProvider {
    public RevaProvider(Plugin plugin, String owner) {
        super(plugin.getTool(), "ReVa Provider", owner);
        buildPanel();
        createActions();
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }
}
```

### DockingAction Pattern

```java
DockingAction action = new DockingAction("Action Name", owner) {
    @Override
    public void actionPerformed(ActionContext context) {
        // Handle action
    }
};
action.setToolBarData(new ToolBarData(Icons.HELP_ICON, null));
action.setMenuBarData(new MenuData(new String[] { "Tools", "ReVa", "Action" }));
action.setDescription("Action description");
action.setHelpLocation(new HelpLocation("ReVa", "Topic"));
addLocalAction(action);
```

### Headless Compatibility

Always check for UI availability:

```java
// Pattern for headless-compatible code
if (provider != null) {
    provider.setStatusText(status);
} else {
    // Fallback for headless environments
    Msg.info(this, status);
}
```

## Testing Considerations

| Challenge | Solution |
|-----------|----------|
| Headless environment | Set `java.awt.headless=false` |
| Component lifecycle | Test registration/unregistration |
| EDT compliance | Use `SwingUtilities.invokeLater()` |
| State isolation | Use `forkEvery=1` for integration tests |

### Test Setup Example

```java
@Before
public void setUp() {
    System.setProperty("java.awt.headless", "false");
    plugin = new RevaPlugin(mockTool);
    provider = new RevaProvider(plugin, "Test");
}
```

## Future Enhancement Areas

| Enhancement | Description |
|-------------|-------------|
| Configuration dialog | Replace placeholder with proper Ghidra options dialog |
| Structured status | Replace text area with structured status model |
| Event-driven updates | Implement observer pattern for status changes |
| Server metrics | Show connected clients, request counts, etc. |

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| UI tests fail in CI | Headless environment | Set `java.awt.headless=false`, use headed runner |
| Status updates lag | Not on EDT | Wrap updates in `SwingUtilities.invokeLater()` |
| Memory leak | Timer not stopped | Call `dispose()` to clean up resources |

## Related Documentation

| File | Description |
|------|-------------|
| `/src/main/java/reva/plugin/CLAUDE.md` | Plugin architecture, ConfigManager |
| `/src/main/java/reva/server/CLAUDE.md` | Server integration, status events |
| `/src/main/java/reva/debug/CLAUDE.md` | DebugCaptureService used by CaptureDebugAction |
| `/CLAUDE.md` | Project-wide guidelines and version requirements |
