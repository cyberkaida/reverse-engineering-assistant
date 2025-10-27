# ReVa Headless Package

This package provides the infrastructure for running ReVa MCP server in headless Ghidra mode, without requiring the GUI plugin system.

## Overview

The headless package enables ReVa to run in environments where a full Ghidra GUI is not available or not desired:
- **PyGhidra scripts** - Python-based automation and testing
- **CI/CD pipelines** - Automated analysis and testing
- **Server deployments** - Long-running analysis servers
- **Docker containers** - Containerized reverse engineering workflows

## Architecture

```
┌─────────────────────────────────────────────┐
│         Entry Points                         │
├──────────────────┬──────────────────────────┤
│  GUI Mode        │  Headless Mode           │
│  (Existing)      │  (New)                   │
│                  │                          │
│  RevaApplication │  RevaHeadlessLauncher   │
│  Plugin          │                          │
└────────┬─────────┴───────────┬──────────────┘
         │                     │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │  McpServerManager   │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │  ConfigManager      │
         │  (Backend-based)    │
         └─────────────────────┘
```

## Key Components

### RevaHeadlessLauncher

Main entry point for headless operation. Provides:
- **Automatic Ghidra initialization** - Handles HeadlessGhidraApplicationConfiguration
- **Configuration management** - Supports file-based or in-memory config
- **Server lifecycle** - Start, stop, wait for ready
- **Status monitoring** - Check if running and ready

## Usage Patterns

### 1. PyGhidra Script

```python
#!/usr/bin/env python3
"""
Start ReVa MCP server from pyghidra
"""
import pyghidra

# pyghidra will initialize Ghidra
pyghidra.start()

# Import after pyghidra is initialized
from reva.headless import RevaHeadlessLauncher

# Create launcher with defaults
launcher = RevaHeadlessLauncher()

try:
    # Start server
    launcher.start()

    # Wait for server to be ready (30 second timeout)
    if launcher.waitForServer(30000):
        print(f"✓ Server ready on port {launcher.getPort()}")

        # Server is now running
        # ... do work ...

    else:
        print("✗ Server failed to start")

finally:
    # Clean shutdown
    launcher.stop()
```

### 2. PyGhidra with Configuration File

```python
from java.io import File
from reva.headless import RevaHeadlessLauncher

# Use custom configuration
config_file = File("/path/to/reva.properties")
launcher = RevaHeadlessLauncher(config_file)

launcher.start()
# ... use server ...
launcher.stop()
```

### 3. Long-Running Server

```python
import signal
import sys

launcher = RevaHeadlessLauncher()

def signal_handler(sig, frame):
    print("\nShutting down...")
    launcher.stop()
    sys.exit(0)

# Register signal handler
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Start and wait
launcher.start()
if launcher.waitForServer(30000):
    print("Server running. Press Ctrl+C to stop.")
    while launcher.isRunning():
        time.sleep(1)
```

### 4. Standalone Java Execution

```bash
# With default configuration
java -cp ghidra.jar:reva.jar reva.headless.RevaHeadlessLauncher

# With configuration file
java -cp ghidra.jar:reva.jar reva.headless.RevaHeadlessLauncher /path/to/config.properties
```

## Configuration

### In-Memory (Defaults)

```java
// Uses default values for all settings
RevaHeadlessLauncher launcher = new RevaHeadlessLauncher();
```

**Default Values:**
- Port: 8080
- Host: 127.0.0.1
- Server Enabled: true
- API Key Auth: disabled
- Debug Mode: false

### File-Based Configuration

```java
File configFile = new File("reva.properties");
RevaHeadlessLauncher launcher = new RevaHeadlessLauncher(configFile);
```

**Configuration File Format (properties):**
```properties
# ReVa Headless Configuration
reva.server.options.server.port=9090
reva.server.options.server.host=0.0.0.0
reva.server.options.server.enabled=true
reva.server.options.api.key.authentication.enabled=true
reva.server.options.api.key=ReVa-your-api-key-here
reva.server.options.debug.mode=true
reva.server.options.max.decompiler.search.functions=1000
reva.server.options.decompiler.timeout.seconds=10
```

## Testing

### Unit Tests

```java
@Test
public void testHeadlessLauncherStartStop() throws Exception {
    RevaHeadlessLauncher launcher = new RevaHeadlessLauncher();

    launcher.start();
    assertTrue("Server should be running", launcher.isRunning());
    assertTrue("Server should be ready", launcher.waitForServer(10000));

    int port = launcher.getPort();
    assertTrue("Port should be valid", port > 0);

    launcher.stop();
    assertFalse("Server should be stopped", launcher.isRunning());
}
```

### End-to-End Tests with PyGhidra

See `src/test/python/test_headless_e2e.py` for comprehensive E2E tests.

## Common Patterns

### Pattern 1: One-Shot Analysis

```python
def analyze_binary(binary_path):
    """Quick analysis with headless server"""
    launcher = RevaHeadlessLauncher()
    try:
        launcher.start()
        launcher.waitForServer(30000)

        # Create program
        # Use MCP tools
        # Get results

    finally:
        launcher.stop()
```

### Pattern 2: Test Fixture

```python
@pytest.fixture
def reva_server():
    """Pytest fixture for ReVa server"""
    launcher = RevaHeadlessLauncher()
    launcher.start()
    launcher.waitForServer(30000)

    yield launcher  # Tests run here

    launcher.stop()

def test_with_server(reva_server):
    """Test using the server fixture"""
    assert reva_server.isRunning()
    port = reva_server.getPort()
    # ... test MCP operations ...
```

### Pattern 3: Configuration Override

```python
from reva.plugin.config import InMemoryBackend
from reva.plugin import ConfigManager

# Create custom config
backend = InMemoryBackend()
backend.setInt("ReVa Server Options", "Server Port", 9999)
backend.setBoolean("ReVa Server Options", "API Key Authentication Enabled", True)

config = ConfigManager(backend)

# Create server with custom config
from reva.server import McpServerManager
server = McpServerManager(config)
server.startServer()
```

## Troubleshooting

### Issue: Ghidra not initialized

**Error:**
```
IllegalStateException: Ghidra application is not initialized
```

**Solution:**
```python
import pyghidra
pyghidra.start()  # Must be called before importing ReVa classes
```

### Issue: Port already in use

**Error:**
```
java.net.BindException: Address already in use
```

**Solution:**
```python
# Use custom port
backend = InMemoryBackend()
backend.setInt("ReVa Server Options", "Server Port", 8081)
config = ConfigManager(backend)
launcher = RevaHeadlessLauncher()
launcher.start()
```

### Issue: Server not ready

**Symptom:**
`waitForServer()` returns false

**Solution:**
```python
# Increase timeout
if not launcher.waitForServer(60000):  # 60 seconds
    # Check logs for errors
    print("Server failed to start - check Msg.error logs")
```

## Performance Considerations

### Startup Time

- **Ghidra initialization**: 3-5 seconds
- **Server startup**: 1-2 seconds
- **Total**: 4-7 seconds typical

### Memory Usage

- **Base Ghidra**: ~200-300 MB
- **ReVa Server**: ~50-100 MB
- **Total**: ~250-400 MB minimum

### Concurrent Instances

Multiple headless instances can run concurrently if using different ports:

```python
# Instance 1 on port 8080
launcher1 = RevaHeadlessLauncher()

# Instance 2 on port 8081
from reva.plugin.config import InMemoryBackend
backend2 = InMemoryBackend()
backend2.setInt("ReVa Server Options", "Server Port", 8081)
config2 = ConfigManager(backend2)
from reva.server import McpServerManager
server2 = McpServerManager(config2)
```

## Security Notes

### Headless API Key Generation

When using in-memory configuration, a random API key is generated but API key authentication is disabled by default. For production:

```python
backend = InMemoryBackend()
backend.setBoolean("ReVa Server Options", "API Key Authentication Enabled", True)
backend.setString("ReVa Server Options", "API Key", "your-secure-key")
config = ConfigManager(backend)
```

### Network Binding

Default binding is `127.0.0.1` (localhost only). To accept remote connections:

```python
backend.setString("ReVa Server Options", "Server Host", "0.0.0.0")
```

**Warning:** Only bind to `0.0.0.0` if you understand the security implications.

## Integration with CI/CD

### GitHub Actions Example

```yaml
- name: Setup PyGhidra
  run: |
    pip install pyghidra

- name: Run headless tests
  env:
    GHIDRA_INSTALL_DIR: /opt/ghidra
  run: |
    python scripts/test_headless.py
```

### Docker Example

```dockerfile
FROM ghidra:latest

# Install pyghidra
RUN pip install pyghidra

# Copy ReVa
COPY reva.jar /opt/reva/

# Run headless
CMD ["python", "/scripts/start_reva_headless.py"]
```

## Future Enhancements

- **Auto-restart** - Automatic server restart on failure
- **Health checks** - Built-in health check endpoint
- **Metrics** - Performance and usage metrics
- **Process management** - Daemon mode with PID files
- **Configuration hot-reload** - Update config without restart

## Related Documentation

- `HEADLESS_ARCHITECTURE.md` - Overall architecture design
- `plugin/CLAUDE.md` - Plugin architecture
- `server/CLAUDE.md` - Server implementation details
- `../../../test/python/test_headless_e2e.py` - E2E test examples
