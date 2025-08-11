# Python CLI Development Guidelines

## Overview
The Python CLI (`reva`) provides headless PyGhidra analysis capabilities for ReVa. It integrates with the Java ReVa extension to provide MCP server functionality without requiring the Ghidra GUI.

## Development Workflow
- Do not set the `ANTHROPIC_API_KEY` variable, Claude Code will get this from our configuration

### Java-Python Integration
- It is OK to change the ReVa Java components to make them compatible with the Python component. Aim for the cleanest implementation.
- The Python CLI depends on the ReVa Java extension being properly installed in Ghidra

### After Changing Java Code
**Critical steps when modifying Java components:**

1. **Build the extension**: `gradle buildExtension`
2. **Remove old extension**: `rm -rf ${GHIDRA_INSTALL_DIR}/Ghidra/Extensions/reverse-engineering-assistant/`
3. **Extract new extension**: Unzip `dist/ghidra_*.zip` to `${GHIDRA_INSTALL_DIR}/Ghidra/Extensions/`
4. **Run tests**: `gradle test && gradle integrationTest`
5. **Test Python CLI**: `cd cli && pytest tests/ -v`

### Python Package Development

#### Environment Setup
```bash
# Install in development mode
cd cli && uv pip install -e .

# Install development dependencies
uv pip install pytest black flake8 mypy
```

#### Testing
```bash
# Run Python tests
pytest tests/ -v

# Test CLI functionality
reva --help
reva --version

# Test package building
python -m build
python -m twine check dist/*
```

#### Key Components
- `cli.py` - Main CLI entry point and PyGhidra integration
- `claude_integration.py` - Claude Code SDK integration for seamless workflow
- `pyproject.toml` - Package configuration and dependencies

#### PyGhidra Integration Patterns
The CLI must properly:
1. Initialize PyGhidra environment
2. Create or reuse Ghidra projects
3. Import and analyze binaries
4. Start ReVa MCP server in headless mode
5. Handle cleanup on exit

#### Version Synchronization
- Python package version should match Java extension version
- Update `pyproject.toml` version when releasing
- Ensure compatibility requirements match (e.g., ReVa extension v4.4.0+)

## Environment Variables
- `GHIDRA_INSTALL_DIR` - Path to Ghidra installation
- `REVA_PROJECT_TEMP_DIR` - Default directory for temporary projects

## Common Issues
- **Extension not found**: Ensure ReVa extension is properly installed in Ghidra
- **PyGhidra import errors**: Check Ghidra installation path and Python environment
- **Port conflicts**: Use `--port` option or check for other services on port 8080
- **Project cleanup**: Temporary projects are cleaned up on exit unless `--project-dir` specified
