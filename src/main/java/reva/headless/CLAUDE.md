# CLAUDE.md - Headless Package

This file provides guidance for Claude Code when working with the ReVa headless infrastructure in the `reva.headless` package.

## Quick Reference

| Item | Value |
|------|-------|
| **Main Class** | `RevaHeadlessLauncher` |
| **Default Port** | 8080 |
| **Default Host** | 127.0.0.1 |
| **MCP SDK Version** | v0.17.0 |
| **Jackson Version** | 2.20.x |
| **PyGhidra Version** | 3.0.0+ |
| **Startup Time** | 4-7 seconds |
| **Memory Usage** | ~250-400 MB |

## Package Overview

The `reva.headless` package enables ReVa MCP server operation in non-GUI environments:

| Mode | Use Case | Project Type |
|------|----------|--------------|
| **PyGhidra Scripts** | Python-based automation and testing | Persistent or none |
| **CI/CD Pipelines** | Automated analysis workflows | Ephemeral |
| **Claude CLI (stdio)** | Direct integration via `mcp-reva` | Ephemeral temp |
| **Long-running Servers** | Headless analysis services | Persistent |

### Architecture Diagram

```
+---------------------------------------------------------+
|                    Entry Points                          |
+-----------------+------------------+---------------------+
|    GUI Mode     |  Headless Mode   |  Claude CLI Mode    |
|                 |                  |                     |
| RevaApp Plugin  | RevaHeadless     |  mcp-reva CLI       |
| (ToolOptions)   | Launcher         |  (Python)           |
+--------+--------+---------+--------+---------+-----------+
         |                  |                  |
         |                  +--------+---------+
         |                           |
         +---------------------------+--------------------+
                                     v                    |
                          +------------------+            |
                          | ConfigManager    |            |
                          | (File/InMemory)  |            |
                          +---------+--------+            |
                                    v                     |
                          +------------------+            |
                          | McpServerManager |<-----------+
                          | (Jetty HTTP)     |
                          +------------------+
```

## Core Components

### RevaHeadlessLauncher

Main entry point for headless operation.

**Key Features:**

| Feature | Description |
|---------|-------------|
| Auto Ghidra Init | Automatic initialization with `HeadlessGhidraApplicationConfiguration` |
| Flexible Config | File-based (`.properties`), in-memory (defaults), or custom |
| Project Lifecycle | Optional persistent project creation/management |
| Server Lifecycle | Start, stop, ready-wait with timeout |
| Random Port | Useful for parallel instances and CLI mode |

**Configuration Backends:**

| Backend | Description | Use Case |
|---------|-------------|----------|
| `InMemoryBackend` | Default values, no persistence | Headless default |
| `FileBackend` | Load from `.properties` file | Custom configs |
| `ToolOptionsBackend` | Ghidra ToolOptions | GUI mode only |

## Constructor API Reference

```java
// 1. Default: in-memory config, auto-init Ghidra, default port, no project
RevaHeadlessLauncher()

// 2. With config file
RevaHeadlessLauncher(File configFile)
RevaHeadlessLauncher(String configFilePath)  // PyGhidra convenience

// 3. With random port
RevaHeadlessLauncher(File configFile, boolean useRandomPort)

// 4. Full control (no project)
RevaHeadlessLauncher(File configFile, boolean autoInitGhidra, boolean useRandomPort)

// 5. With persistent project
RevaHeadlessLauncher(File configFile, boolean useRandomPort,
                     File projectLocation, String projectName)

// 6. Full control with project
RevaHeadlessLauncher(File configFile, boolean autoInitGhidra, boolean useRandomPort,
                     File projectLocation, String projectName)
```

## API Methods

| Method | Return Type | Description |
|--------|-------------|-------------|
| `start()` | `void` | Start the MCP server (throws IOException) |
| `stop()` | `void` | Stop the MCP server |
| `isRunning()` | `boolean` | Check if server is running |
| `isServerReady()` | `boolean` | Check if server is ready for requests |
| `waitForServer(long timeoutMs)` | `boolean` | Wait for server readiness |
| `getPort()` | `int` | Get the server port (useful with random port) |
| `getConfigManager()` | `ConfigManager` | Get the configuration manager |
| `getServerManager()` | `McpServerManager` | Get the server manager |

## Usage Patterns

### 1. Basic PyGhidra Script

```python
import pyghidra
pyghidra.start()  # Initialize Ghidra BEFORE importing ReVa

from reva.headless import RevaHeadlessLauncher

launcher = RevaHeadlessLauncher()
launcher.start()

if launcher.waitForServer(30000):
    print(f"Server ready on port {launcher.getPort()}")
    # Use server...

launcher.stop()
```

### 2. With Random Port (Recommended for CLI)

```python
from reva.headless import RevaHeadlessLauncher

# Use random available port (avoids conflicts)
launcher = RevaHeadlessLauncher(None, True)  # useRandomPort=True
launcher.start()
port = launcher.getPort()  # e.g., 52431
```

### 3. With Persistent Project

```python
from java.io import File
from reva.headless import RevaHeadlessLauncher

project_dir = File("/path/to/projects")
launcher = RevaHeadlessLauncher(
    configFile=None,
    useRandomPort=True,
    projectLocation=project_dir,
    projectName="my_analysis"
)

launcher.start()
# Project created at /path/to/projects/my_analysis/
# Project persists after launcher.stop()
launcher.stop()
```

### 4. With Configuration File

**reva.properties:**
```properties
# Server settings
reva.server.options.server.port=9090
reva.server.options.server.host=127.0.0.1
reva.server.options.server.enabled=true

# Security
reva.server.options.api.key.authentication.enabled=false
reva.server.options.api.key=

# Performance
reva.server.options.debug.mode=false
reva.server.options.max.decompiler.search.functions=1000
reva.server.options.decompiler.timeout.seconds=10
reva.server.options.import.analysis.timeout.seconds=600
```

**Usage:**
```python
from java.io import File
from reva.headless import RevaHeadlessLauncher

config = File("reva.properties")
launcher = RevaHeadlessLauncher(config)
launcher.start()
```

### 5. Standalone Java Execution

```bash
# With defaults (in-memory config, port 8080)
java -cp ghidra.jar:reva.jar reva.headless.RevaHeadlessLauncher

# With config file
java -cp ghidra.jar:reva.jar reva.headless.RevaHeadlessLauncher reva.properties
```

## Default Configuration Values

| Setting | Default Value |
|---------|---------------|
| Port | 8080 |
| Host | 127.0.0.1 |
| Server Enabled | true |
| API Key Auth | disabled |
| Debug Mode | false |
| Max Decompiler Search Functions | 1000 |
| Decompiler Timeout | 10 seconds |
| Import Analysis Timeout | 600 seconds |

## Project Management Modes

| Mode | Project Type | Lifecycle | Use Case |
|------|--------------|-----------|----------|
| **GUI** | Existing Ghidra project | Managed by Ghidra | Normal plugin usage |
| **Headless** | Persistent via constructor | Survives restarts | Long-running servers |
| **CLI (stdio)** | Ephemeral temp directory | Auto-cleanup on exit | `mcp-reva` sessions |

## Python CLI Integration (mcp-reva)

### Lifecycle Flow

1. `mcp-reva` CLI entry point (`src/reva_cli/__main__.py`)
2. PyGhidra initialization (**BEFORE** asyncio)
3. `ReVaLauncher.start()` creates Java `RevaHeadlessLauncher`
4. Ephemeral project created in `tempfile.mkdtemp(prefix="reva_project_")`
5. Server starts on random port
6. `StdioBridge` proxies stdio to HTTP MCP protocol
7. On exit: project temp dir cleaned up via `shutil.rmtree()`

### Key Design Points

- PyGhidra init is **blocking** (BEFORE `asyncio.run()`)
- Projects are ephemeral temp directories
- Random ports avoid conflicts with GUI/other instances
- Clean project cleanup on stop

## Troubleshooting

### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| `IllegalStateException: Ghidra application is not initialized` | PyGhidra not started first | Initialize PyGhidra BEFORE importing ReVa classes |
| `java.net.BindException: Address already in use` | Port conflict | Use `useRandomPort=True` |
| Server timeout | Slow startup or error | Increase timeout to 60000ms, check Ghidra logs |
| Jackson conflicts | Wrong Jackson version | Run `rm lib/*.jar` and rebuild |
| Server not responding | Server not fully started | Always use `waitForServer()` before making requests |

### Ghidra Not Initialized

```python
# ERROR: IllegalStateException: Ghidra application is not initialized
# FIX: Initialize PyGhidra BEFORE importing ReVa
import pyghidra
pyghidra.start()
from reva.headless import RevaHeadlessLauncher  # Now safe
```

### Port Already in Use

```python
# ERROR: java.net.BindException: Address already in use
# FIX: Use random port
launcher = RevaHeadlessLauncher(None, True)  # useRandomPort=True
```

### Server Not Ready (Timeout)

```python
# Increase timeout or check Msg.error logs
if not launcher.waitForServer(60000):  # 60 seconds
    print("Server failed to start - check Ghidra logs")
```

## Performance Notes

| Metric | Value |
|--------|-------|
| Startup time | 4-7 seconds (Ghidra init + server start) |
| Memory usage | ~250-400 MB (base Ghidra + ReVa) |
| Concurrent instances | Use random ports or different configured ports |

## Security Considerations

| Configuration | Value | Notes |
|---------------|-------|-------|
| Default binding | `127.0.0.1:8080` | Localhost only |
| API key auth | Disabled by default | Enable for production |
| Remote access | Bind to `0.0.0.0` | Use with caution |

## Testing

### Java Integration Tests

**Base class:** `RevaHeadlessIntegrationTestBase.java`

```java
public abstract class RevaHeadlessIntegrationTestBase
    extends AbstractGhidraHeadlessIntegrationTest {
    protected Program program;
    // Creates default x86 test program
}
```

### Python Tests

**Location:** `/tests/`

| Marker | Description |
|--------|-------------|
| `@pytest.mark.unit` | Fast tests with mocks |
| `@pytest.mark.integration` | Require PyGhidra initialization |
| `@pytest.mark.e2e` | End-to-end subprocess tests |

**Example:**
```python
def test_launcher_starts_and_stops(ghidra_initialized):
    from reva.headless import RevaHeadlessLauncher
    launcher = RevaHeadlessLauncher()
    launcher.start()
    assert launcher.waitForServer(30000)
    launcher.stop()
```

## Critical Implementation Notes

- **PyGhidra init order** - MUST initialize PyGhidra BEFORE `asyncio.run()` in CLI mode
- **Random ports for CLI** - Always use random ports to avoid conflicts with GUI instances
- **Ephemeral projects** - CLI mode uses temp directories, auto-cleaned on exit
- **MCP SDK v0.17.0** - Uses `HttpServletStreamableServerTransportProvider` (NOT SSE)
- **Jackson 2.20.x** - Force-resolved for MCP SDK compatibility

## Related Documentation

| Document | Description |
|----------|-------------|
| `/src/main/java/reva/server/CLAUDE.md` | McpServerManager, transport, threading |
| `/src/main/java/reva/plugin/CLAUDE.md` | ConfigManager backends, plugin lifecycle |
| `/src/reva_cli/` | Python CLI implementation (launcher.py, stdio_bridge.py) |
| `/tests/` | Python integration tests |
| `/src/test.slow/` | Java integration test base classes |
