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
- `--no-analysis`: Skip auto-analysis phase
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

# Analyze multiple binaries without auto-analysis
reva --no-analysis /path/to/lib1.so /path/to/lib2.so

# Use a persistent project directory and custom name
reva --project-dir ~/ghidra_projects --project-name malware_analysis /path/to/sample.exe

# Set custom temp directory via environment
export REVA_PROJECT_TEMP_DIR=/data/temp
reva /path/to/binary
```

Once running, the MCP server will be available at `http://localhost:8080` for client connections.

Press Ctrl+C to exit and clean up resources.

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