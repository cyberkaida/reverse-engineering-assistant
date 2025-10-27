# Headless Ghidra Support Architecture Plan

## Executive Summary

This document outlines the architectural changes needed to enable ReVa MCP server to run in headless Ghidra mode via pyghidra. The goal is to decouple the server from the GUI plugin system while maintaining backward compatibility with the existing plugin-based architecture.

## Current Architecture Analysis

### Dependencies on GUI Components

1. **RevaApplicationPlugin**
   - Extends `ApplicationLevelOnlyPlugin` (GUI-specific)
   - Requires `FrontEndService` (GUI-only service)
   - Uses `PluginTool` for initialization
   - Location: `src/main/java/reva/plugin/RevaApplicationPlugin.java:49`

2. **ConfigManager**
   - Requires `PluginTool` in constructor
   - Uses `ToolOptions` for configuration storage
   - Location: `src/main/java/reva/plugin/ConfigManager.java:37`

3. **McpServerManager**
   - Currently instantiated only by `RevaApplicationPlugin`
   - Receives `PluginTool` for `ConfigManager` initialization
   - Location: `src/main/java/reva/server/McpServerManager.java:93`

### What Works Already

1. **McpServerManager** - Core server logic is largely independent
   - Server initialization and lifecycle management
   - Tool provider registration
   - HTTP server (Jetty) management
   - No direct dependency on GUI beyond ConfigManager

2. **Tool Providers** - All tool providers are headless-compatible
   - Use `AbstractToolProvider` with programmatic APIs
   - Work with `Program` objects directly
   - No GUI dependencies

3. **Existing Headless Test Base** - `RevaHeadlessIntegrationTestBase`
   - Already demonstrates headless program creation
   - Shows pattern for headless Ghidra usage

## Proposed Architecture

### 1. Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                     Entry Points                             │
├─────────────────────┬───────────────────────────────────────┤
│  GUI Mode           │  Headless Mode                        │
│  (Existing)         │  (New)                                │
│                     │                                       │
│  RevaApplication    │  RevaHeadlessLauncher                │
│  Plugin             │  (PyGhidra Script)                    │
└─────────┬───────────┴──────────────┬────────────────────────┘
          │                          │
          │    ┌─────────────────────┘
          │    │
          ▼    ▼
     ┌──────────────────────┐
     │  McpServerManager    │
     │  (Unchanged)         │
     └──────────┬───────────┘
                │
                ▼
     ┌──────────────────────┐
     │  ConfigManager       │
     │  (Refactored)        │
     └──────────────────────┘
```

### 2. Configuration Management Refactoring

**Current Issues:**
- ConfigManager requires PluginTool
- Uses ToolOptions for persistence
- Tightly coupled to GUI plugin lifecycle

**Solution: Dual-Mode ConfigManager**

```java
public class ConfigManager {
    private final ConfigurationBackend backend;

    // GUI mode constructor (existing)
    public ConfigManager(PluginTool tool) {
        this.backend = new ToolOptionsBackend(tool);
    }

    // Headless mode constructor (new)
    public ConfigManager(File configFile) {
        this.backend = new FileBackend(configFile);
    }

    // Headless mode with defaults (new)
    public ConfigManager() {
        this.backend = new InMemoryBackend();
    }
}

interface ConfigurationBackend {
    int getInt(String category, String name, int defaultValue);
    String getString(String category, String name, String defaultValue);
    boolean getBoolean(String category, String name, boolean defaultValue);
    void setInt(String category, String name, int value);
    void setString(String category, String name, String value);
    void setBoolean(String category, String name, boolean value);
}
```

### 3. Headless Launcher

**New Class: `RevaHeadlessLauncher`**

```java
package reva.headless;

/**
 * Headless launcher for ReVa MCP server.
 * Can be invoked from pyghidra or other headless contexts.
 */
public class RevaHeadlessLauncher {
    private McpServerManager serverManager;
    private ConfigManager configManager;
    private File configFile;

    public RevaHeadlessLauncher() {
        this(null);
    }

    public RevaHeadlessLauncher(File configFile) {
        this.configFile = configFile;
    }

    /**
     * Start the MCP server in headless mode
     */
    public void start() {
        // Initialize Ghidra application if not already initialized
        if (!Application.isInitialized()) {
            ApplicationConfiguration config =
                new HeadlessGhidraApplicationConfiguration();
            Application.initializeApplication(
                ApplicationLayout.findGhidraApplicationLayout(), config);
        }

        // Create config manager (headless mode)
        if (configFile != null) {
            configManager = new ConfigManager(configFile);
        } else {
            configManager = new ConfigManager(); // Use defaults
        }

        // Create and start server manager
        serverManager = new McpServerManager(configManager);
        serverManager.startServer();
    }

    /**
     * Stop the server and cleanup
     */
    public void stop() {
        if (serverManager != null) {
            serverManager.shutdown();
        }
    }

    /**
     * Get the server port
     */
    public int getPort() {
        return serverManager != null ?
            serverManager.getServerPort() : -1;
    }

    /**
     * Check if server is running
     */
    public boolean isRunning() {
        return serverManager != null &&
            serverManager.isServerRunning();
    }

    /**
     * Wait for server to be ready
     */
    public boolean waitForServer(long timeoutMs) {
        long start = System.currentTimeMillis();
        while (System.currentTimeMillis() - start < timeoutMs) {
            if (isRunning() && serverManager.isServerReady()) {
                return true;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }
}
```

### 4. McpServerManager Refactoring

**Current Constructor:**
```java
public McpServerManager(PluginTool pluginTool) {
    configManager = new ConfigManager(pluginTool);
    // ...
}
```

**New Constructor:**
```java
public McpServerManager(ConfigManager configManager) {
    this.configManager = configManager;
    // ...
}

// Backward compatibility constructor for GUI mode
public McpServerManager(PluginTool pluginTool) {
    this(new ConfigManager(pluginTool));
}
```

### 5. PyGhidra Integration

**New Python Script: `scripts/reva_headless_server.py`**

```python
#!/usr/bin/env python3
"""
ReVa MCP Server Headless Launcher

This script starts the ReVa MCP server in headless Ghidra mode.
Can be used from pyghidra or as a standalone headless server.
"""

import argparse
import sys
import time
import signal
from pathlib import Path

# Import after pyghidra is initialized
launcher = None

def signal_handler(sig, frame):
    """Handle shutdown signals gracefully"""
    print("\nShutting down ReVa MCP server...")
    if launcher:
        launcher.stop()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description="Start ReVa MCP server in headless mode"
    )
    parser.add_argument(
        "--port", type=int, default=8080,
        help="Server port (default: 8080)"
    )
    parser.add_argument(
        "--host", default="localhost",
        help="Server host (default: localhost)"
    )
    parser.add_argument(
        "--config", type=Path,
        help="Path to configuration file"
    )
    parser.add_argument(
        "--wait", action="store_true",
        help="Wait for server (keep running)"
    )
    args = parser.parse_args()

    # Import Java classes
    from reva.headless import RevaHeadlessLauncher

    # Create and start launcher
    global launcher
    if args.config:
        from java.io import File
        launcher = RevaHeadlessLauncher(File(str(args.config)))
    else:
        launcher = RevaHeadlessLauncher()

    print(f"Starting ReVa MCP server on {args.host}:{args.port}...")
    launcher.start()

    # Wait for server to be ready
    if launcher.waitForServer(30000):  # 30 second timeout
        print(f"✓ ReVa MCP server ready on port {launcher.getPort()}")

        if args.wait:
            # Register signal handlers
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)

            print("Server running. Press Ctrl+C to stop.")
            try:
                while launcher.isRunning():
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            finally:
                launcher.stop()

        return 0
    else:
        print("✗ Failed to start server", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
```

### 6. End-to-End Test with PyGhidra

**New Test: `src/test/python/test_headless_e2e.py`**

```python
#!/usr/bin/env python3
"""
End-to-end test for ReVa MCP server in headless mode via pyghidra
"""

import pytest
import requests
import json
import time
from pathlib import Path
import tempfile

def test_headless_server_startup():
    """Test that the server starts in headless mode"""
    from reva.headless import RevaHeadlessLauncher

    launcher = RevaHeadlessLauncher()
    try:
        launcher.start()
        assert launcher.waitForServer(30000), "Server failed to start"
        assert launcher.isRunning(), "Server not running"
        port = launcher.getPort()
        assert port > 0, "Invalid port"

        # Test server is responding
        url = f"http://localhost:{port}/mcp/message"
        # Note: Actual MCP protocol test would go here

    finally:
        launcher.stop()

def test_headless_server_with_config():
    """Test server with custom configuration"""
    from reva.headless import RevaHeadlessLauncher
    from java.io import File

    # Create temp config
    with tempfile.NamedTemporaryFile(mode='w', suffix='.properties', delete=False) as f:
        f.write("server.port=9090\n")
        f.write("server.host=localhost\n")
        config_path = f.name

    try:
        launcher = RevaHeadlessLauncher(File(config_path))
        launcher.start()
        assert launcher.waitForServer(30000)
        assert launcher.getPort() == 9090
    finally:
        launcher.stop()
        Path(config_path).unlink()

def test_mcp_tools_available():
    """Test that MCP tools are available in headless mode"""
    from reva.headless import RevaHeadlessLauncher

    launcher = RevaHeadlessLauncher()
    try:
        launcher.start()
        assert launcher.waitForServer(30000)

        # Test tools/list endpoint (when implemented)
        # This would test that all tool providers are registered

    finally:
        launcher.stop()

def test_program_loading_headless():
    """Test loading a program in headless mode and using MCP tools"""
    from reva.headless import RevaHeadlessLauncher
    from ghidra.program.database import ProgramDB
    from ghidra.program.model.lang import LanguageID

    launcher = RevaHeadlessLauncher()
    try:
        launcher.start()
        assert launcher.waitForServer(30000)

        # Create a test program
        language = getLanguageService().getLanguage(LanguageID("x86:LE:32:default"))
        program = ProgramDB("TestHeadlessProgram", language, language.getDefaultCompilerSpec(), None)

        # Test MCP operations on the program
        # This would test list-functions, etc.

    finally:
        launcher.stop()

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
```

## Implementation Plan

### Phase 1: Configuration Refactoring (Week 1)

1. **Create ConfigurationBackend Interface**
   - Define interface with get/set methods
   - Location: `src/main/java/reva/plugin/config/ConfigurationBackend.java`

2. **Implement Backends**
   - `ToolOptionsBackend` - Existing behavior
   - `InMemoryBackend` - For headless with defaults
   - `FileBackend` - For headless with config file
   - Location: `src/main/java/reva/plugin/config/`

3. **Refactor ConfigManager**
   - Add backend-based constructors
   - Maintain backward compatibility
   - Update tests

4. **Update McpServerManager**
   - Accept ConfigManager in constructor
   - Keep backward-compatible PluginTool constructor
   - Update RevaApplicationPlugin to use new pattern

### Phase 2: Headless Launcher (Week 2)

1. **Create RevaHeadlessLauncher**
   - Location: `src/main/java/reva/headless/RevaHeadlessLauncher.java`
   - Implement start/stop/status methods
   - Add configuration support

2. **Add Headless Package Documentation**
   - Location: `src/main/java/reva/headless/CLAUDE.md`
   - Document usage patterns
   - Provide examples

3. **Create Unit Tests**
   - Location: `src/test/java/reva/headless/RevaHeadlessLauncherTest.java`
   - Test initialization
   - Test lifecycle

### Phase 3: PyGhidra Integration (Week 3)

1. **Create PyGhidra Script**
   - Location: `scripts/reva_headless_server.py`
   - Command-line interface
   - Signal handling
   - Configuration support

2. **Create Python E2E Tests**
   - Location: `src/test/python/test_headless_e2e.py`
   - Server startup tests
   - MCP protocol tests
   - Program loading tests

3. **Add Helper Scripts**
   - `scripts/test_headless.sh` - Run headless tests
   - `scripts/start_headless.sh` - Quick start script

### Phase 4: CI/CD Integration (Week 4)

1. **Update GitHub Actions Workflow**
   - Add pyghidra installation
   - Add headless test job
   - Separate headless and GUI tests

2. **Add Test Fixtures**
   - Sample binaries for testing
   - Test configurations
   - Expected outputs

3. **Documentation**
   - Update README.md
   - Add HEADLESS_USAGE.md
   - Update CLAUDE.md

## Testing Strategy

### Unit Tests
- ConfigManager backends (all three)
- RevaHeadlessLauncher lifecycle
- Configuration loading/saving

### Integration Tests (Headless)
- Server startup in headless mode
- Tool provider registration
- MCP protocol compliance
- Program operations

### End-to-End Tests (PyGhidra)
- Full server lifecycle via Python
- MCP client connections
- Real program analysis workflows
- Configuration file handling

### Backward Compatibility Tests
- Existing GUI plugin still works
- Existing integration tests pass
- No breaking changes to public APIs

## Risk Mitigation

### Risk 1: ConfigManager Refactoring Breaks GUI Mode
**Mitigation:**
- Keep existing constructor
- Add comprehensive backward compatibility tests
- Gradual migration with deprecation warnings

### Risk 2: PyGhidra Environment Issues
**Mitigation:**
- Test on multiple platforms (Linux, macOS, Windows)
- Document pyghidra installation clearly
- Provide Docker container for testing

### Risk 3: Server Lifecycle Management in Headless
**Mitigation:**
- Proper signal handling
- Graceful shutdown procedures
- Resource cleanup verification
- Timeout mechanisms

### Risk 4: Configuration Persistence in Headless
**Mitigation:**
- Clear documentation of configuration precedence
- Sensible defaults
- Configuration validation
- Example config files

## Success Criteria

1. **Functional Requirements**
   - ✓ MCP server starts in headless mode via pyghidra
   - ✓ All tool providers work in headless mode
   - ✓ Configuration can be provided via file or defaults
   - ✓ Server can be stopped gracefully
   - ✓ Multiple instances can run on different ports

2. **Non-Functional Requirements**
   - ✓ No breaking changes to existing GUI mode
   - ✓ Startup time < 10 seconds in headless mode
   - ✓ All existing tests continue to pass
   - ✓ New tests achieve >80% coverage of new code
   - ✓ Documentation is complete and clear

3. **Testing Requirements**
   - ✓ E2E tests pass on GitHub CI
   - ✓ Tests run on Linux (primary), macOS, Windows
   - ✓ Tests can run without network access
   - ✓ Tests are reproducible

## Future Enhancements

1. **Configuration Management**
   - Environment variable support
   - Configuration hot-reload
   - Configuration validation API

2. **Process Management**
   - Daemon mode
   - Process supervision
   - Health check endpoint

3. **Deployment**
   - Docker container
   - systemd service file
   - Kubernetes deployment

4. **Monitoring**
   - Metrics endpoint
   - Logging configuration
   - Performance monitoring

## Conclusion

This architecture provides a clean separation between GUI and headless modes while maintaining backward compatibility. The dual-mode ConfigManager is the key abstraction that enables both modes to coexist. The PyGhidra integration provides a Python-friendly way to launch and test the server, which is ideal for automation and CI/CD.

The phased implementation approach allows for incremental development and testing, reducing risk and enabling early feedback. Each phase builds on the previous one and can be tested independently.
