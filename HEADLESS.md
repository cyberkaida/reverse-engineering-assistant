# ReVa Headless Mode

This document describes how to run ReVa MCP server in headless mode using pyghidra, without requiring Ghidra's GUI.

## Overview

ReVa supports two operational modes:

1. **GUI Mode** - Traditional Ghidra plugin that runs within Ghidra's GUI
2. **Headless Mode** - Standalone MCP server using pyghidra (no GUI required)

Headless mode is ideal for:
- Automated reverse engineering workflows
- CI/CD pipelines
- Docker containers
- Remote server deployments
- Integration with AI assistants and automation tools

## Architecture

### GUI Mode
```
Ghidra GUI → Plugin System → RevaApplicationPlugin → McpServerManager → MCP Server
```

### Headless Mode
```
pyghidra → HeadlessRevaLauncher → HeadlessMcpServerManager → MCP Server
```

## Prerequisites

### Required Software
- Java 21 or later
- Python 3.8 or later
- Ghidra 11.4 or later
- Gradle 8.14 or later (for building)

### Environment Variables
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
```

## Installation

### 1. Install Python Dependencies

```bash
pip install -r requirements-headless.txt
```

Or manually:
```bash
pip install pyghidra
```

### 2. Build ReVa Extension

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
gradle buildExtension
```

This compiles the Java classes and creates the extension package.

## Usage

### Basic Usage

Start the MCP server with default settings (localhost:8080):

```bash
python3 reva_headless.py
```

### Custom Host and Port

Bind to a specific host and port:

```bash
python3 reva_headless.py --host 0.0.0.0 --port 9000
```

### Load a Ghidra Project

Open a Ghidra project and load programs:

```bash
python3 reva_headless.py \
  --project-dir ~/ghidra_projects \
  --project-name MyProject \
  --programs /binary1.exe /binary2.exe
```

### All Options

```
usage: reva_headless.py [-h] [--host HOST] [--port PORT]
                        [--project-dir PROJECT_DIR]
                        [--project-name PROJECT_NAME]
                        [--programs PROGRAMS [PROGRAMS ...]]
                        [--extension-dir EXTENSION_DIR]
                        [--verbose]

Launch ReVa MCP server in headless mode

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           Host to bind the MCP server to (default: 127.0.0.1)
  --port PORT           Port for the MCP server (default: 8080)
  --project-dir PROJECT_DIR
                        Path to the Ghidra project directory
  --project-name PROJECT_NAME
                        Name of the Ghidra project to open
  --programs PROGRAMS [PROGRAMS ...]
                        List of program paths within the project to load
  --extension-dir EXTENSION_DIR
                        Path to ReVa extension directory
  --verbose             Enable verbose logging
```

## Programmatic Usage

You can also use the headless launcher programmatically from Python:

```python
import pyghidra
import os

# Set Ghidra installation directory
os.environ['GHIDRA_INSTALL_DIR'] = '/path/to/ghidra'

# Initialize pyghidra
launcher = pyghidra.launcher.HeadlessPyGhidraLauncher()

# Add ReVa extension to classpath
launcher.add_classpaths('/path/to/reva/build/classes/java/main')

# Start Ghidra
launcher.start()

# Import and use HeadlessRevaLauncher
from reva.server import HeadlessRevaLauncher

# Create launcher
reva_launcher = HeadlessRevaLauncher('127.0.0.1', 8080)

# Start the MCP server
reva_launcher.launch()

# Open a project
project = reva_launcher.openProject('/path/to/projects', 'MyProject')

# Load a program
program = reva_launcher.openProgram('/binary.exe')

# Server is now ready for MCP connections
print(f"Server ready: {reva_launcher.isServerReady()}")

# Keep server running
try:
    reva_launcher.waitForShutdown()
except KeyboardInterrupt:
    reva_launcher.shutdown()
```

## Docker Deployment

Example Dockerfile for headless deployment:

```dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    openjdk-21-jdk \
    python3 \
    python3-pip \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra
WORKDIR /opt
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4_build/ghidra_11.4_PUBLIC_20241105.zip \
    && unzip ghidra_11.4_PUBLIC_20241105.zip \
    && mv ghidra_11.4_PUBLIC /opt/ghidra \
    && rm ghidra_11.4_PUBLIC_20241105.zip

ENV GHIDRA_INSTALL_DIR=/opt/ghidra

# Install ReVa
WORKDIR /opt/reva
COPY . .
RUN pip3 install -r requirements-headless.txt
RUN gradle buildExtension

# Expose MCP server port
EXPOSE 8080

# Run headless server
CMD ["python3", "reva_headless.py", "--host", "0.0.0.0", "--port", "8080"]
```

Build and run:
```bash
docker build -t reva-headless .
docker run -p 8080:8080 reva-headless
```

## API Reference

### HeadlessRevaLauncher Java Class

Located in `reva.server.HeadlessRevaLauncher`

#### Constructors

```java
// Default constructor (localhost:8080)
public HeadlessRevaLauncher()

// Custom host and port
public HeadlessRevaLauncher(String serverHost, int serverPort)
```

#### Methods

```java
// Launch the MCP server
public void launch()

// Open a Ghidra project
public Project openProject(String projectPath, String projectName) throws IOException

// Open and register a program
public Program openProgram(String programPath) throws IOException

// Close a program
public void closeProgram(Program program)

// Close the current project
public void closeProject()

// Shutdown the server
public void shutdown()

// Check if server is ready
public boolean isServerReady()

// Block until shutdown
public void waitForShutdown()

// Get the server manager
public HeadlessMcpServerManager getServerManager()

// Get current project
public Project getProject()

// Get open programs
public List<Program> getOpenPrograms()
```

### HeadlessMcpServerManager Java Class

Located in `reva.server.HeadlessMcpServerManager`

#### Constructors

```java
// Default constructor (localhost:8080)
public HeadlessMcpServerManager()

// Custom host and port
public HeadlessMcpServerManager(String serverHost, int serverPort)
```

#### Methods

```java
// Start the MCP server
public void startServer()

// Check if server is ready
public boolean isServerReady()

// Shutdown the server
public void shutdown()

// Register a program with MCP tools
public void registerProgram(Program program)

// Unregister a program
public void unregisterProgram(Program program)

// Get server configuration
public int getServerPort()
public String getServerHost()

// Block until shutdown
public void waitForShutdown()
```

## Troubleshooting

### pyghidra Import Errors

If you see errors importing ReVa classes after starting pyghidra:

1. Ensure the extension is built: `gradle buildExtension`
2. Check that `GHIDRA_INSTALL_DIR` is set correctly
3. Verify the classpath includes the build directory:
   ```python
   launcher.add_classpaths('/path/to/reva/build/classes/java/main')
   ```

### Server Fails to Start

1. Check that port is not already in use:
   ```bash
   lsof -i :8080
   ```

2. Verify Ghidra installation:
   ```bash
   ls -la $GHIDRA_INSTALL_DIR
   ```

3. Run with verbose logging:
   ```bash
   python3 reva_headless.py --verbose
   ```

### Project/Program Loading Issues

1. Verify project path and name:
   ```bash
   ls -la ~/ghidra_projects/MyProject.rep/
   ```

2. Check program path format (must start with `/`):
   ```bash
   --programs /binary.exe  # Correct
   --programs binary.exe   # Wrong
   ```

3. Ensure project is a valid Ghidra project (has `.rep` directory)

## Comparison: GUI vs Headless Mode

| Feature | GUI Mode | Headless Mode |
|---------|----------|---------------|
| Requires GUI | Yes | No |
| Installation | Ghidra extension | Python + pyghidra |
| Startup | Via Ghidra plugin system | Via Python script |
| Resource usage | Higher (GUI overhead) | Lower (no GUI) |
| Use case | Interactive analysis | Automation, CI/CD |
| Program management | Via Ghidra GUI | Programmatic |
| Configuration | Ghidra options | Command-line args |
| Multiple projects | Via GUI switching | Code-based switching |

## Advanced Usage

### Custom Classpath Configuration

Add additional JARs to the classpath:

```python
import pyghidra
import glob

launcher = pyghidra.launcher.HeadlessPyGhidraLauncher()

# Add ReVa classes
launcher.add_classpaths('/path/to/reva/build/classes/java/main')

# Add all JARs from lib directory
for jar in glob.glob('/path/to/reva/lib/*.jar'):
    launcher.add_classpaths(jar)

launcher.start()
```

### JVM Configuration

Configure JVM options:

```python
launcher = pyghidra.launcher.HeadlessPyGhidraLauncher()
launcher.add_vmargs('-Xmx4G')  # Set max heap to 4GB
launcher.add_vmargs('-Dlog4j2.formatMsgNoLookups=true')
launcher.start()
```

### Multi-Project Support

Work with multiple projects:

```python
from reva.server import HeadlessRevaLauncher

launcher = HeadlessRevaLauncher()
launcher.launch()

# Open first project
project1 = launcher.openProject('/projects', 'Project1')
prog1 = launcher.openProgram('/binary1.exe')

# Do work...

# Close first project
launcher.closeProject()

# Open second project
project2 = launcher.openProject('/projects', 'Project2')
prog2 = launcher.openProgram('/binary2.exe')

# Server continues running across project switches
```

## Integration Examples

### CI/CD Pipeline

```yaml
# .github/workflows/analysis.yml
name: Binary Analysis

on: [push]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Ghidra
        uses: antoniovazquezblanco/setup-ghidra@v2.0.5

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install ReVa
        run: |
          pip install pyghidra
          gradle buildExtension

      - name: Run Analysis
        run: |
          python3 reva_headless.py \
            --project-dir ./test-project \
            --project-name TestProject \
            --programs /test-binary.exe &

          # Wait for server
          sleep 5

          # Run your MCP-based analysis
          # ...
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  reva:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./projects:/projects
    command: >
      python3 reva_headless.py
      --host 0.0.0.0
      --port 8080
      --project-dir /projects
      --project-name MyProject
```

## Testing

ReVa includes comprehensive tests for headless mode to ensure reliability and correctness.

### Running Tests

#### Quick Smoke Test

Verify basic functionality in ~30 seconds:

```bash
python3 tests/smoke_test.py
```

This tests:
- Server startup
- MCP endpoint accessibility
- Tool listing
- Basic tool invocation
- Graceful shutdown

#### Java Integration Tests

Test Java components:

```bash
# Test headless launcher
gradle test --tests "*HeadlessRevaLauncherIntegrationTest"

# Test all headless components
gradle test --tests "*Headless*"
```

#### Python End-to-End Tests

Test the complete stack including MCP protocol:

```bash
# Using pytest
pytest tests/test_headless_e2e.py -v

# Using unittest
python3 tests/test_headless_e2e.py
```

#### All Tests

Run the complete test suite:

```bash
# Install test dependencies
pip install -r requirements-test.txt

# Run all tests
pytest tests/ -v

# Run Java tests
gradle test --tests "*Headless*"
```

### Test Coverage

The test suite covers:

1. **Server Lifecycle**
   - Startup and initialization
   - Graceful shutdown
   - Restart capability
   - Error handling

2. **MCP Protocol**
   - Tool listing
   - Resource listing
   - Tool invocation
   - Error responses

3. **Program Management**
   - Program registration
   - Multiple programs
   - Program unregistration

4. **Performance**
   - Startup time
   - Response time
   - Resource usage

5. **Error Handling**
   - Invalid requests
   - Port conflicts
   - Malformed data

### Continuous Integration

Tests run automatically on GitHub Actions for every push and pull request. See `.github/workflows/headless-tests.yml` for configuration.

View test results: https://github.com/cyberkaida/reverse-engineering-assistant/actions

## References

- [PyGhidra Documentation](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra)
- [Ghidra Headless Mode](https://ghidra-sre.org/GhidraHeadless.html)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [Test Documentation](tests/README.md)

## Contributing

If you encounter issues with headless mode, please report them at:
https://github.com/cyberkaida/reverse-engineering-assistant/issues

When contributing:
1. Add tests for new features
2. Ensure smoke test passes
3. Update documentation
4. Follow existing code patterns
