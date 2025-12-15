# ReVa Headless Package

This package provides infrastructure for running ReVa MCP server in headless Ghidra mode without the GUI plugin system.

## Overview

The headless package enables ReVa to run in non-GUI environments:
- **PyGhidra scripts** - Python-based automation and testing
- **CI/CD pipelines** - Automated analysis workflows
- **Claude CLI (stdio mode)** - Direct integration with Claude desktop
- **Long-running servers** - Headless analysis services

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                  Entry Points                          │
├─────────────────┬──────────────────┬───────────────────┤
│   GUI Mode      │  Headless Mode   │  Claude CLI Mode  │
│                 │                  │                   │
│  RevaApp Plugin │  RevaHeadless    │  mcp-reva CLI     │
│  (ToolOptions)  │  Launcher        │  (Python)         │
└───────┬─────────┴────────┬─────────┴────────┬──────────┘
        │                  │                  │
        │                  └──────────┬───────┘
        │                             │
        └─────────────────────────────┼─────────────────┐
                                      ▼                 │
                           ┌──────────────────┐         │
                           │ ConfigManager    │         │
                           │ (File/InMemory)  │         │
                           └──────────┬───────┘         │
                                      ▼                 │
                           ┌──────────────────┐         │
                           │ McpServerManager │◄────────┘
                           │ (Jetty HTTP)     │
                           └──────────────────┘
```

## Key Components

### RevaHeadlessLauncher

Main entry point for headless operation (`RevaHeadlessLauncher.java`):

**Core Features:**
- Automatic Ghidra initialization with `HeadlessGhidraApplicationConfiguration`
- Flexible configuration: file-based (`.properties`), in-memory (defaults), or custom
- Project lifecycle: Optional persistent project creation/management
- Server lifecycle: Start, stop, ready-wait with timeout
- Random port allocation: Useful for parallel instances and CLI mode

**Configuration Backends:**
- `InMemoryBackend` - Default values, no persistence (headless default)
- `FileBackend` - Load from `.properties` file (custom configs)
- `ToolOptionsBackend` - Ghidra ToolOptions (GUI mode only)

**Project Support:**
- Optional project creation: Pass `projectLocation` and `projectName` to constructor
- Persistent projects: Created in specified directory, survive server restarts
- Ephemeral projects: Python CLI creates temp projects (auto-cleanup on exit)
- No project mode: Can run without a project (project-less tools only)

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

### 2. With Persistent Project

```python
from java.io import File
from reva.headless import RevaHeadlessLauncher

# Create launcher with project support
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

### 3. With Configuration File

```python
from java.io import File
from reva.headless import RevaHeadlessLauncher

config = File("reva.properties")
launcher = RevaHeadlessLauncher(config)

launcher.start()
launcher.waitForServer(30000)
# ... use server ...
launcher.stop()
```

### 4. Python CLI Integration (Stdio Mode)

**Handled by `src/reva_cli/launcher.py`:**

```python
from reva_cli.launcher import ReVaLauncher

# CLI creates ephemeral temp projects (auto-cleanup)
launcher = ReVaLauncher(use_random_port=True)
port = launcher.start()  # Returns random port

# Project created in tempfile.mkdtemp(prefix="reva_project_")
# Cleaned up automatically on launcher.stop()
launcher.stop()
```

### 5. Standalone Java Execution

```bash
# With defaults (in-memory config, port 8080)
java -cp ghidra.jar:reva.jar reva.headless.RevaHeadlessLauncher

# With config file
java -cp ghidra.jar:reva.jar reva.headless.RevaHeadlessLauncher reva.properties
```

## Configuration

### Default Values (InMemoryBackend)

```java
RevaHeadlessLauncher launcher = new RevaHeadlessLauncher();
// Port: 8080
// Host: 127.0.0.1
// Server Enabled: true
// API Key Auth: disabled
// Debug Mode: false
// Max Decompiler Search Functions: 1000
// Decompiler Timeout: 10 seconds
// Import Analysis Timeout: 600 seconds
```

### Random Port (CLI Mode)

```java
// Use random available port (avoids conflicts)
RevaHeadlessLauncher launcher = new RevaHeadlessLauncher(null, true);
launcher.start();
int port = launcher.getPort();  // e.g., 52431
```

### File-Based Configuration

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
```java
File config = new File("reva.properties");
RevaHeadlessLauncher launcher = new RevaHeadlessLauncher(config);
```

## Integration with PyGhidra

### Python CLI Lifecycle (mcp-reva)

**Flow:**
1. `mcp-reva` CLI entry point (`src/reva_cli/__main__.py`)
2. PyGhidra initialization (BEFORE asyncio)
3. `ReVaLauncher.start()` creates Java `RevaHeadlessLauncher`
4. Ephemeral project created in `tempfile.mkdtemp(prefix="reva_project_")`
5. Server starts on random port
6. `StdioBridge` proxies stdio ↔ HTTP MCP protocol
7. On exit: project temp dir cleaned up automatically

**Key Design Points:**
- PyGhidra init is **blocking** (BEFORE `asyncio.run()`)
- Projects are ephemeral temp directories (not `.reva/projects/`)
- Random ports avoid conflicts with GUI/other instances
- Clean project cleanup via `shutil.rmtree()` on stop

### Project Management Modes

**1. GUI Mode (RevaApplicationPlugin):**
- Uses existing Ghidra project/tool system
- No project creation needed
- Programs managed by Ghidra's ProgramManager

**2. Headless Mode (scripts):**
- Optional persistent projects via constructor parameters
- Projects survive server restarts
- Useful for long-running analysis servers

**3. CLI Mode (mcp-reva stdio):**
- Ephemeral temp projects (session-scoped)
- Auto-cleanup on exit keeps filesystem clean
- One project per CLI session

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

**Test categories (pytest markers):**
- `@pytest.mark.unit` - Fast tests with mocks
- `@pytest.mark.integration` - Require PyGhidra initialization
- `@pytest.mark.e2e` - End-to-end subprocess tests

**Example:**
```python
def test_launcher_starts_and_stops(ghidra_initialized):
    from reva.headless import RevaHeadlessLauncher
    launcher = RevaHeadlessLauncher()
    launcher.start()
    assert launcher.waitForServer(30000)
    launcher.stop()
```

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

```java
// Lifecycle
void start() throws IOException
void stop()

// Status
boolean isRunning()
boolean isServerReady()
boolean waitForServer(long timeoutMs)

// Configuration
int getPort()
ConfigManager getConfigManager()
McpServerManager getServerManager()
```

## Troubleshooting

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
launcher = RevaHeadlessLauncher(None, useRandomPort=True)
```

### Server Not Ready (Timeout)

```python
# Increase timeout or check Msg.error logs
if not launcher.waitForServer(60000):  # 60 seconds
    print("Server failed - check Ghidra logs")
```

## Performance Notes

- **Startup time:** 4-7 seconds (Ghidra init + server start)
- **Memory usage:** ~250-400 MB (base Ghidra + ReVa)
- **Concurrent instances:** Use random ports or different configured ports

## Security

**Default:** `127.0.0.1:8080`, no API key authentication
**Production:** Enable API keys, bind to specific interfaces
**Remote access:** Use with caution (bind to `0.0.0.0` only if needed)

## Related Documentation

- `/src/main/java/reva/plugin/CLAUDE.md` - ConfigManager backends
- `/src/main/java/reva/server/CLAUDE.md` - McpServerManager details
- `/tests/` - Python integration tests
- `/src/test/java/reva/` - Java integration test base classes
