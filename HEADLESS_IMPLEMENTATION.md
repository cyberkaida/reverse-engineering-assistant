# Headless Mode Implementation Summary

This document summarizes the implementation of headless mode support for ReVa.

## Problem Statement

The original ReVa implementation required Ghidra's GUI to function because:
1. The MCP server was started via a Ghidra plugin (`RevaApplicationPlugin`)
2. Plugin initialization required Ghidra's GUI framework
3. Program management was tied to GUI tool lifecycle
4. No standalone entry point existed

This prevented ReVa from being used in:
- Automated workflows
- CI/CD pipelines
- Docker containers
- Remote headless servers

## Solution Overview

We implemented a **dual-mode architecture** that supports both GUI and headless operation:

### Architecture

**GUI Mode (Original):**
```
Ghidra GUI → Plugin System → RevaApplicationPlugin → McpServerManager → MCP Server
```

**Headless Mode (New):**
```
pyghidra → HeadlessRevaLauncher → HeadlessMcpServerManager → MCP Server
```

## Implementation Details

### New Components

#### 1. HeadlessMcpServerManager (`src/main/java/reva/server/HeadlessMcpServerManager.java`)

A standalone MCP server manager that operates without plugin infrastructure:

- **No Plugin Dependencies**: Doesn't require `PluginTool`, `FrontEndService`, or plugin lifecycle
- **Direct Initialization**: Directly creates and configures MCP server
- **Program Management**: Uses `RevaProgramManager` for program registration
- **Configuration**: Simple constructor-based configuration (host, port)
- **Resource Management**: Same tool and resource providers as GUI mode

Key differences from `McpServerManager`:
- No `PluginTool` dependency
- No `ConfigManager` (uses constructor parameters)
- No multi-tool tracking (headless is single-tenant)
- Simplified lifecycle (no config change listeners)

#### 2. HeadlessRevaLauncher (`src/main/java/reva/server/HeadlessRevaLauncher.java`)

Entry point for headless operation with project/program management:

- **Server Lifecycle**: Manages `HeadlessMcpServerManager` startup/shutdown
- **Project Management**: Opens/closes Ghidra projects programmatically
- **Program Loading**: Loads programs and registers them with MCP server
- **Programmatic API**: Provides Java API for integration
- **Main Method**: Can be run standalone (though pyghidra is recommended)

Key features:
- `openProject(projectPath, projectName)` - Opens Ghidra projects
- `openProgram(programPath)` - Loads and registers programs
- `launch()` - Starts the MCP server
- `shutdown()` - Graceful cleanup

#### 3. Python Launcher (`reva_headless.py`)

Command-line interface using pyghidra:

- **Environment Setup**: Configures pyghidra with ReVa classpath
- **CLI Interface**: Comprehensive command-line arguments
- **Signal Handling**: Graceful shutdown on SIGINT/SIGTERM
- **Project Loading**: Automatic project and program loading
- **Error Handling**: Detailed error messages and logging

Usage:
```bash
python3 reva_headless.py --host 127.0.0.1 --port 8080
python3 reva_headless.py --project-dir /projects --project-name MyProject --programs /binary.exe
```

### Supporting Files

#### 4. requirements-headless.txt

Python dependencies for headless mode:
```
pyghidra>=1.0.0
```

#### 5. Updated Setup Script (`.claude/setup-environment.sh`)

Enhanced to install:
- Python 3 and pip
- pyghidra package
- Environment configuration for headless mode

#### 6. Documentation

- **HEADLESS.md**: Comprehensive headless mode guide
  - Installation instructions
  - Usage examples
  - API reference
  - Troubleshooting
  - Docker deployment examples
  - CI/CD integration examples

- **README.md**: Updated with headless mode section

## Key Design Decisions

### 1. Separation of Concerns

Rather than modifying the existing `McpServerManager` to work in both modes, we created separate managers:

**Rationale:**
- Keeps GUI mode unchanged and stable
- Avoids complex conditional logic
- Clear separation between GUI and headless concerns
- Easier to maintain and test

**Trade-off:**
- Some code duplication (initialization, provider registration)
- Two server managers to maintain
- Acceptable given the architectural differences

### 2. pyghidra as Primary Interface

We use pyghidra rather than Ghidra's native headless analyzer:

**Advantages:**
- Modern Python interface
- Better integration with automation tools
- Easier JVM configuration
- Active development by NSA

**Considerations:**
- Requires Python environment
- Additional dependency
- Well worth it for the improved developer experience

### 3. Program Management

Headless mode uses the existing `RevaProgramManager`:

**Approach:**
- Programs are registered directly via `RevaProgramManager.registerProgram()`
- No tool-level tracking (headless is single-tenant)
- Same program resolution as GUI mode

**Benefits:**
- Reuses existing infrastructure
- Consistent program identification across modes
- Minimal changes to tool providers

### 4. Configuration

Headless mode uses constructor parameters instead of `ConfigManager`:

**Rationale:**
- No Ghidra options system in headless mode
- Command-line args are more appropriate
- Simpler configuration model
- No persistent state needed

**Implementation:**
```java
new HeadlessMcpServerManager("127.0.0.1", 8080)
```

vs GUI mode:
```java
new McpServerManager(pluginTool)  // reads from Ghidra options
```

## Compatibility

### Shared Components

The following components work in both modes:
- All tool providers (`tools/*`)
- All resource providers (`resources/*`)
- Utility classes (`util/*`)
- `RevaProgramManager`
- MCP server infrastructure

### Mode-Specific Components

**GUI Only:**
- `RevaApplicationPlugin`
- `RevaPlugin`
- `ConfigManager` (with Ghidra options)
- `McpServerManager` (with plugin dependencies)

**Headless Only:**
- `HeadlessMcpServerManager`
- `HeadlessRevaLauncher`
- `reva_headless.py`

## Testing Strategy

### Unit Tests

Existing unit tests continue to work without modification.

### Integration Tests

Two types of integration tests:

1. **GUI Integration Tests** (existing)
   - Use Ghidra's GUI test framework
   - Require `java.awt.headless=false`
   - Test plugin lifecycle

2. **Headless Integration Tests** (future work)
   - Use pyghidra for Ghidra initialization
   - Can run with `java.awt.headless=true`
   - Test server lifecycle and program loading

### Recommended Test Addition

```python
# test_headless_mode.py
import pyghidra
import os

def test_headless_server_startup():
    pyghidra.start()
    from reva.server import HeadlessRevaLauncher

    launcher = HeadlessRevaLauncher()
    launcher.launch()

    assert launcher.isServerReady()

    launcher.shutdown()
```

## Deployment Scenarios

### 1. Docker Container

```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y openjdk-21-jdk python3 python3-pip
RUN pip3 install pyghidra
COPY . /opt/reva
WORKDIR /opt/reva
RUN gradle buildExtension
CMD ["python3", "reva_headless.py", "--host", "0.0.0.0"]
```

### 2. CI/CD Pipeline

```yaml
- name: Run ReVa Analysis
  run: |
    python3 reva_headless.py --project-dir ./analysis --project-name Test &
    sleep 5
    # Run MCP-based analysis
```

### 3. Remote Server

```bash
# Run as systemd service
python3 reva_headless.py --host 0.0.0.0 --port 8080
```

## Future Enhancements

### 1. Headless Integration Tests

Add comprehensive integration tests for headless mode using pyghidra.

### 2. API Server Mode

Extend headless mode to expose a REST API in addition to MCP:
```python
python3 reva_headless.py --enable-rest-api
```

### 3. Multi-Project Support

Enhance launcher to manage multiple projects simultaneously:
```python
launcher.switchProject('Project2')
```

### 4. Performance Optimization

Optimize headless mode for batch processing:
- Pre-load multiple programs
- Parallel analysis support
- Result caching

### 5. Configuration File Support

Add YAML/JSON configuration file support:
```bash
python3 reva_headless.py --config reva.yml
```

## Migration Path

Users can choose their preferred mode:

**For Interactive Analysis:**
- Continue using GUI mode
- Full Ghidra integration
- Visual feedback

**For Automation:**
- Switch to headless mode
- No GUI overhead
- Scriptable workflows

**Both modes can coexist** - same MCP tools, same capabilities, different entry points.

## Conclusion

The headless mode implementation provides:

✅ **Zero GUI Dependency**: Runs without Ghidra GUI
✅ **pyghidra Integration**: Modern Python interface
✅ **Backward Compatibility**: GUI mode unchanged
✅ **Code Reuse**: Shared tool and resource providers
✅ **Comprehensive Documentation**: HEADLESS.md with examples
✅ **Production Ready**: Docker and CI/CD examples

The implementation maintains architectural consistency while enabling new use cases for automated reverse engineering workflows.
