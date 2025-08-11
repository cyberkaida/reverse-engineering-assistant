# Reverse Engineering Assistant CLI

Command line tool for headless reverse engineering with Ghidra and ReVa MCP server.

## Installation

```bash
pip install reverse-engineering-assistant
```

## Usage

### Analyze a single binary

```bash
reva /path/to/binary
```

### Analyze multiple binaries

```bash
reva /path/to/binary1 /path/to/binary2 /path/to/binary3
```

### Options

- `--ghidra-path`: Path to Ghidra installation (default: auto-detect or GHIDRA_INSTALL_DIR)
- `--project-dir`: Directory for Ghidra project files (default: temp directory, or REVA_PROJECT_TEMP_DIR env var)
- `--project-name`: Name for the Ghidra project (default: reva_session_<pid>)
- `--port`: MCP server port (default: 8080)
- `--auto-analyze`: Run analysis on all files upfront (default: lazy analysis)
- `--verbose`: Enable verbose logging

### Project Directory Behavior

By default, ReVa creates a temporary project directory that is automatically cleaned up on exit. You can control this behavior:

1. **Default**: Uses `/tmp/reva_projects_<pid>` and cleans up on exit
2. **Environment Variable**: Set `REVA_PROJECT_TEMP_DIR` to specify a custom temp location (still cleans up on exit)
3. **Explicit Directory**: Use `--project-dir` to specify a permanent location (will NOT be cleaned up)
4. **Project Name**: Use `--project-name` to specify a custom project name (useful for persistent projects)

### Examples

```bash
# Analyze a binary with verbose output
reva --verbose --ghidra-path /opt/ghidra /path/to/malware.exe

# Analyze multiple binaries with upfront analysis
reva --auto-analyze /path/to/lib1.so /path/to/lib2.so

# Use a persistent project directory and custom name
reva --project-dir ~/ghidra_projects --project-name malware_analysis /path/to/sample.exe

# Set custom temp directory via environment
export REVA_PROJECT_TEMP_DIR=/data/temp
reva /path/to/binary
```

Once running, the MCP server will be available at `http://localhost:8080` for client connections.

Press Ctrl+C to exit and clean up resources.

## Analysis Workflows

### Lazy Analysis (Default)

By default, ReVa uses **lazy analysis** for faster startup and efficient resource usage:

- **Quick startup**: Files are imported without analysis, allowing immediate metadata access
- **On-demand analysis**: Use the `analyze-program` MCP tool when deeper analysis is needed
- **Efficient for triage**: Perfect for "What is this file?" questions that don't need full analysis

```bash
# Quick triage - no upfront analysis time
reva-claude malware.exe -- "What type of file is this and what architecture?"

# Progressive analysis - start simple, then analyze as needed
reva-claude suspicious.dll -- "Does this look like malware? Analyze if suspicious."
```

### Upfront Analysis

For workflows requiring immediate deep analysis, use the `--auto-analyze` flag:

```bash
# Full analysis upfront
reva-claude --auto-analyze complex.exe -- "Comprehensive security analysis"

# Regular reva command (always does analysis)
reva binary.exe  # Analysis happens during startup
```

### Manual Analysis Control

Use the `analyze-program` MCP tool for fine-grained control:

```json
{
  "tool": "analyze-program",
  "arguments": {
    "programPath": "/malware.exe",
    "force": false
  }
}
```

**Tool features:**
- Checks if analysis was already run
- Provides hints when re-analysis might be needed
- Returns analysis statistics (functions found, time taken, etc.)
- Use `"force": true` to re-analyze if needed

## Programmatic API

ReVa can also be used programmatically in Python scripts for automated analysis:

### Basic Usage

```python
from reverse_engineering_assistant import ReVaSession

# Analyze a binary with automatic resource cleanup
with ReVaSession(['malware.exe']) as reva:
    print(f"Server URL: {reva.server_url}")
    print(f"Programs loaded: {list(reva.programs.keys())}")
    
    # Server is now ready for MCP client connections
    # Your analysis code here...
```

### Advanced Configuration

```python
from reverse_engineering_assistant import ReVaSession, find_free_port

# Custom configuration
with ReVaSession(
    binaries=['app.exe', 'lib.dll'],
    port=find_free_port(),  # Auto-assign random port
    project_dir='/tmp/my_analysis',  # Custom project directory
    project_name='custom_analysis',
    auto_analyze=False,  # Lazy analysis (default: False for efficiency)
    quiet=True,  # Suppress console output (default)
    ghidra_path='/opt/ghidra'  # Custom Ghidra installation
) as reva:
    # Multiple programs loaded
    for name, program in reva.programs.items():
        print(f"Loaded: {name} at {program.getImageBase()}")
    
    # Use reva.server_url for MCP client connections
    mcp_client = create_mcp_client(reva.server_url)
    # ... rest of your analysis
```

### Manual Session Management

```python
from reverse_engineering_assistant import ReVaSession

# Manual management (not recommended - use context manager when possible)
session = ReVaSession(['binary.exe'], quiet=True)
try:
    session.start()  # Initialize everything
    
    # Use session.server_url and session.programs
    analyze_with_reva(session.server_url)
    
finally:
    session.shutdown()  # Always cleanup
```

### API Reference

#### ReVaSession

**Constructor:**
```python
ReVaSession(
    binaries: List[str],          # List of binary paths to analyze
    *,                            # Keyword-only arguments below
    ghidra_path: Optional[str] = None,      # Path to Ghidra installation
    project_dir: Optional[str] = None,       # Project directory (temp if None)
    project_name: Optional[str] = None,      # Project name (auto-generated if None) 
    port: Optional[int] = None,              # MCP server port (auto-assigned if None)
    auto_analyze: bool = True,               # Run Ghidra analysis on import
    quiet: bool = True                       # Suppress console output
)
```

**Properties:**
- `server_url: Optional[str]` - MCP server URL (available after start())
- `programs: Dict[str, Program]` - Loaded Ghidra programs by name
- `port: int` - MCP server port
- `ghidra_path: str` - Path to Ghidra installation

**Methods:**
- `start()` - Initialize PyGhidra, load binaries, start MCP server
- `shutdown()` - Clean up all resources
- Context manager support (`__enter__`/`__exit__`)

#### Utilities

- `find_free_port() -> int` - Find a random available port

### Error Handling

```python
from reverse_engineering_assistant import ReVaSession

try:
    with ReVaSession(['missing.exe']) as reva:
        # ... analysis code
        pass
except RuntimeError as e:
    print(f"ReVa session failed: {e}")
except FileNotFoundError as e:
    print(f"Binary not found: {e}")
```

### Integration Examples

#### With MCP Client
```python
from reverse_engineering_assistant import ReVaSession
import requests

with ReVaSession(['malware.exe']) as reva:
    # Use HTTP MCP client
    response = requests.post(f"{reva.server_url}/mcp/message", json={
        "method": "tools/list"
    })
    tools = response.json()
    print(f"Available tools: {tools}")
```

#### Batch Analysis
```python
from reverse_engineering_assistant import ReVaSession
import os

binaries = [f for f in os.listdir('/samples') if f.endswith('.exe')]

for binary in binaries:
    with ReVaSession([f'/samples/{binary}'], project_name=f'analysis_{binary}') as reva:
        print(f"Analyzing {binary} on {reva.server_url}")
        # Your analysis logic here
        # Project will be automatically cleaned up
```

## Requirements

- Python 3.8+
- Ghidra 11.3+ installed
- Java 17+ (for Ghidra)

## Development

```bash
git clone https://github.com/cyberkaida/reverse-engineering-assistant.git
cd reverse-engineering-assistant/cli
pip install -e ".[dev]"
```