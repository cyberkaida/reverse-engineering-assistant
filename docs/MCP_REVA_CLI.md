# mcp-reva CLI - stdio MCP Bridge

## Overview

`mcp-reva` is a command-line tool that provides stdio MCP transport for ReVa, enabling seamless integration with Claude CLI. It automatically manages Ghidra projects, imports binaries, and bridges stdio communication to ReVa's StreamableHTTP server.

## Features

- **Stdio MCP Transport**: Communicates with Claude CLI via stdin/stdout
- **Automatic Project Management**: Creates and manages Ghidra projects in `.reva/projects/`
- **Auto-Import Binaries**: Automatically finds and imports binaries from current directory
- **Random Port Allocation**: Avoids port conflicts by using random available ports
- **Clean Shutdown**: Gracefully handles SIGINT, SIGTERM, and SIGHUP signals
- **Zero Configuration**: Works out-of-the-box with sensible defaults

## Installation

```bash
# Install with uv
uv sync

# Verify installation
uv run mcp-reva --version
```

## Usage

### With Claude CLI

Add ReVa as an MCP server to Claude:

```bash
claude mcp add ReVa -- mcp-reva
```

Or with a custom configuration file:

```bash
claude mcp add ReVa -- mcp-reva --config ~/.reva-config.properties
```

### Command Line Options

```bash
usage: mcp-reva [-h] [--config CONFIG] [--verbose] [--version]

options:
  -h, --help            show this help message and exit
  --config CONFIG       Path to ReVa configuration file
  --verbose, -v         Enable verbose logging
  --version             show program's version number and exit
```

### Standalone Testing

You can run `mcp-reva` standalone for testing:

```bash
# Start the server (reads from stdin, writes to stdout)
uv run mcp-reva --verbose

# In another terminal, send JSON-RPC messages:
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | uv run mcp-reva
```

## Project Management

### Automatic Project Creation

`mcp-reva` automatically creates and manages Ghidra projects in `.reva/projects/` within your current working directory:

```
your-project/
├── .reva/
│   └── projects/
│       └── your-project/
│           ├── your-project.gpr     # Ghidra project file
│           ├── your-project.rep/    # Project repository
│           └── ...
├── binary1.exe                       # Auto-imported
├── binary2.elf                       # Auto-imported
└── ...
```

### Project Naming

- Project name is derived from the current directory name
- Special characters are sanitized to underscores
- If directory name starts with `.` or is empty, uses `default_project`

### Auto-Import Behavior

`mcp-reva` automatically scans the current directory for binaries and imports them:

**Supported Extensions:**
- Executables: `.exe`, `.dll`, `.so`, `.dylib`, `.elf`
- Firmware: `.bin`, `.img`, `.rom`
- Mobile: `.apk`, `.dex`, `.jar`

**Detection:**
- Files with supported extensions
- Executable files (Unix `+x` permission) without extensions

### Directory Structure

```
.reva/
└── projects/
    └── <project-name>/
        ├── <project-name>.gpr       # Project file
        ├── <project-name>.rep/      # Repository directory
        ├── <project-name>.lock      # Lock file
        └── ...
```

**Note:** Add `.reva/` to your `.gitignore` to avoid committing Ghidra project files.

## Architecture

### Component Flow

```
┌──────────────┐
│ Claude CLI   │
└──────┬───────┘
       │ stdio (JSON-RPC)
       ▼
┌──────────────────────────┐
│  mcp-reva                │
│                          │
│  ┌────────────────────┐  │
│  │ StdioBridge        │  │
│  │ - Read stdin       │  │
│  │ - Write stdout     │  │
│  └─────┬──────────────┘  │
│        │ HTTP (MCP)       │
│  ┌─────▼──────────────┐  │
│  │ ReVaLauncher       │  │
│  │ - PyGhidra init    │  │
│  │ - Random port      │  │
│  │ - Java server      │  │
│  └────────────────────┘  │
│                          │
│  ┌────────────────────┐  │
│  │ ProjectManager     │  │
│  │ - Create project   │  │
│  │ - Import binaries  │  │
│  └────────────────────┘  │
└──────────┬───────────────┘
           │ StreamableHTTP (random port)
           ▼
┌──────────────────────────┐
│ ReVa Java Server         │
│ - McpServerManager       │
│ - All MCP tools          │
│ - Ghidra integration     │
└──────────────────────────┘
```

### Components

1. **StdioBridge** (`stdio_bridge.py`)
   - Reads JSON-RPC messages from stdin
   - Forwards to ReVa HTTP server using MCP StreamableHTTP client
   - Writes responses to stdout
   - Handles all MCP methods: initialize, tools/list, tools/call, resources/list, etc.

2. **ReVaLauncher** (`launcher.py`)
   - Initializes PyGhidra
   - Creates ReVa headless launcher with random port
   - Manages server lifecycle

3. **ProjectManager** (`project_manager.py`)
   - Creates `.reva/projects/` directory structure
   - Opens or creates Ghidra project
   - Auto-detects and imports binaries
   - Handles cleanup on shutdown

4. **Main CLI** (`__main__.py`)
   - Argument parsing
   - Signal handling (SIGINT, SIGTERM, SIGHUP)
   - Orchestrates all components
   - Clean shutdown coordination

## Configuration

### Default Configuration

`mcp-reva` works with zero configuration using sensible defaults:

- **Port**: Random available port
- **Host**: 127.0.0.1 (localhost only)
- **Project**: `.reva/projects/<current-dir-name>/`
- **Auto-import**: Enabled

### Custom Configuration File

You can provide a ReVa configuration file for advanced settings:

```properties
# config/reva-mcp.properties

# Server configuration (port will be overridden to random)
reva.server.options.server.enabled=true
reva.server.options.debug.mode=false

# Decompiler settings
reva.server.options.max.decompiler.search.functions=1000
reva.server.options.decompiler.timeout.seconds=10
```

Usage:

```bash
mcp-reva --config config/reva-mcp.properties
```

**Note:** The port setting in the config file is ignored - `mcp-reva` always uses a random available port to avoid conflicts.

## Logging

### Normal Mode

In normal mode, `mcp-reva` only logs to stderr (never stdout, which is reserved for MCP protocol):

```
Initializing project manager...
Project opened: my-project
Found 2 potential binaries
Importing binary: binary1.exe
Successfully imported: binary1.exe
Importing binary: binary2.elf
Successfully imported: binary2.elf
Auto-imported 2 binaries
Initializing PyGhidra...
Using default configuration
Starting ReVa MCP server...
Using random port: 54321
ReVa server ready on port 54321
Starting stdio<->HTTP bridge on port 54321...
Bridge ready - forwarding stdio<->HTTP
```

### Verbose Mode

Enable verbose mode for debugging:

```bash
mcp-reva --verbose
```

Additional output includes:
- MCP session initialization details
- Available tools listing
- Detailed error traces
- Bridge message handling

## Signal Handling

`mcp-reva` handles signals gracefully:

- **SIGINT** (Ctrl+C): Clean shutdown
- **SIGTERM**: Clean shutdown
- **SIGHUP**: Clean shutdown (Unix only)

### Shutdown Process

1. Stop stdio bridge
2. Clean up project (release programs)
3. Close Ghidra project
4. Stop ReVa server
5. Exit

## Troubleshooting

### Issue: Command not found

```bash
$ mcp-reva
zsh: command not found: mcp-reva
```

**Solution:**
```bash
# Install package
uv sync

# Run with uv
uv run mcp-reva
```

### Issue: PyGhidra initialization fails

```
Error: PyGhidra modules not available
```

**Solution:**
Ensure PyGhidra is installed and GHIDRA_INSTALL_DIR is set:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
uv sync
```

### Issue: No binaries imported

```
No binaries found in current directory
```

**Solution:**
This is normal if there are no binary files in the current directory. You can:
1. Place binaries in the directory before starting
2. Import them later via MCP tools (`import-file`, etc.)
3. Open existing programs from the project

### Issue: Port already in use

This should never happen with `mcp-reva` since it uses random port allocation. If it does:

```bash
# Check for stuck processes
ps aux | grep mcp-reva

# Kill stuck processes
pkill -f mcp-reva
```

### Issue: Project already open error

```
Error: Project is already open
```

**Solution:**
```bash
# Clean up lock files
rm .reva/projects/*/project.lock

# Or use a different directory
cd /path/to/different/project
mcp-reva
```

## Examples

### Example 1: Quick Analysis with Claude

```bash
# Navigate to directory with binaries
cd ~/malware-samples/

# Add ReVa to Claude
claude mcp add ReVa -- mcp-reva

# Use Claude to analyze
claude chat
> Use ReVa to list all functions in the imported programs
> Decompile the main function
> Find all string references
```

### Example 2: Multiple Projects

```bash
# Project 1
cd ~/project1/
claude mcp add ReVa-Project1 -- mcp-reva

# Project 2 (different directory)
cd ~/project2/
claude mcp add ReVa-Project2 -- mcp-reva

# Each gets its own .reva/projects/ directory
```

### Example 3: Custom Configuration

```bash
# Create config file
cat > ~/.reva-analysis.properties <<EOF
reva.server.options.debug.mode=true
reva.server.options.max.decompiler.search.functions=5000
reva.server.options.decompiler.timeout.seconds=30
EOF

# Use config
claude mcp add ReVa -- mcp-reva --config ~/.reva-analysis.properties
```

## Development

### Running from Source

```bash
# Clone repository
git clone https://github.com/your-org/reverse-engineering-assistant.git
cd reverse-engineering-assistant

# Install dependencies
uv sync

# Run directly
uv run mcp-reva --help
```

### Testing

```bash
# Unit tests
uv run pytest tests/

# Integration test
cd test-project/
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | uv run mcp-reva
```

## See Also

- [ReVa Documentation](../README.md)
- [Headless Mode Guide](../src/main/java/reva/headless/CLAUDE.md)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [Claude CLI Documentation](https://docs.claude.com/)
