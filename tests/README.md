# ReVa Headless Integration Tests

Professional pytest suite for testing ReVa's headless mode with PyGhidra.

## Overview

These integration tests verify that ReVa components work together in headless Ghidra mode:

- **PyGhidra Integration**: Ghidra can be initialized without GUI
- **Launcher Lifecycle**: RevaHeadlessLauncher can start/stop servers
- **MCP Tool Connectivity**: Tools are registered and accessible
- **Configuration Loading**: Property files are parsed correctly

## Test Structure

```
tests/
├── __init__.py              # Package documentation
├── conftest.py              # Pytest fixtures (shared across all tests)
├── helpers.py               # Utility functions (MCP requests, program creation)
├── requirements.txt         # Python dependencies
├── README.md                # This file
├── test_pyghidra.py         # PyGhidra integration tests
├── test_launcher.py         # Launcher lifecycle tests
├── test_mcp_tools.py        # MCP tool connectivity tests
└── test_config.py           # Configuration loading tests
```

## Fixtures

Shared fixtures are defined in `conftest.py`:

### Session-Scoped Fixtures (Created Once)

- **`ghidra_initialized`**: Initializes PyGhidra once for entire test session (expensive: 10-30s)
- **`test_program`**: Creates a test program with memory and strings (reused across tests)

### Function-Scoped Fixtures (Per Test)

- **`server`**: Starts a RevaHeadlessLauncher, waits for ready, stops after test
- **`mcp_client`**: Helper object with `call_tool(name, args)` method

## Running Tests

### Prerequisites

```bash
# Install dependencies
pip install -r tests/requirements.txt

# Ensure GHIDRA_INSTALL_DIR is set
export GHIDRA_INSTALL_DIR=/path/to/ghidra

# Build and install ReVa extension
gradle buildExtension
# Install the extension from dist/*.zip to Ghidra
```

### Run All Tests

```bash
pytest tests/ -v
```

### Run Specific Test Module

```bash
pytest tests/test_launcher.py -v
pytest tests/test_mcp_tools.py -v
```

### Run Tests Matching Pattern

```bash
pytest tests/ -k "config" -v          # All config tests
pytest tests/ -k "launcher" -v        # All launcher tests
pytest tests/ -k "list_programs" -v   # Specific test names
```

### Run with Timeout

```bash
pytest tests/ -v --timeout=60
```

### Run with Different Output

```bash
pytest tests/ -v --tb=short    # Shorter tracebacks
pytest tests/ -v --tb=line     # One-line tracebacks
pytest tests/ -v -s            # Show print statements
```

## Test Details

### test_pyghidra.py

Verifies PyGhidra integration:
- PyGhidra can be imported
- Ghidra initializes in headless mode
- Test program fixture creates valid program
- ReVa classes can be imported

### test_launcher.py

Tests RevaHeadlessLauncher lifecycle:
- **Lifecycle**: Start, wait for ready, stop
- **Status**: isRunning(), isServerReady(), getPort()
- **Configuration**: Default config, custom config file
- **Edge Cases**: Invalid config files, timeouts

### test_mcp_tools.py

Tests MCP tool connectivity:
- **list-programs**: Returns program list
- **list-strings**: Accepts programPath parameter
- **list-functions**: Tool is registered
- **get-decompilation**: Tool is registered
- **Parametrized**: Verifies multiple tools are callable

### test_config.py

Tests configuration loading:
- **Default**: In-memory configuration with defaults
- **File Loading**: Properties file parsing
- **Multiple Options**: Port, host, debug settings
- **Edge Cases**: Missing files, empty files, comments

## CI Integration

The GitHub Actions workflow (`.github/workflows/test-headless.yml`) runs these tests:

- **Matrix**: Ubuntu/macOS × Python 3.9/3.11/3.12 × Ghidra 12.0/latest
- **Timeout**: 10 minutes per job
- **Artifacts**: Uploads logs and pytest cache

Workflow steps:
1. Setup Java 21
2. Setup Python
3. Install Ghidra
4. Build ReVa extension
5. Install extension to Ghidra
6. Install Python dependencies (`pip install -r tests/requirements.txt`)
7. Run pytest (`pytest tests/ -v --timeout=60 --tb=short`)
8. Upload artifacts

## Writing New Tests

### Example: Test a New Tool

```python
# tests/test_my_tool.py
import pytest
from tests.helpers import get_response_result

class TestMyTool:
    """Test my-new-tool functionality"""

    def test_tool_is_callable(self, mcp_client):
        """my-new-tool is registered and responds"""
        response = mcp_client.call_tool("my-new-tool", {
            "programPath": "/TestProgram"
        })

        assert response is not None

    def test_tool_returns_expected_format(self, mcp_client):
        """my-new-tool returns expected result structure"""
        response = mcp_client.call_tool("my-new-tool", {
            "programPath": "/TestProgram"
        })

        # get_response_result asserts no error
        result = get_response_result(response)

        # Verify expected fields
        assert "content" in result
```

### Example: Test with Custom Fixture

```python
# tests/test_custom.py
import pytest

@pytest.fixture
def custom_config(tmp_path):
    """Create a custom config file"""
    config_file = tmp_path / "custom.properties"
    config_file.write_text("reva.server.options.server.port=5555\n")
    return str(config_file)

class TestCustomConfig:
    def test_with_custom_config(self, ghidra_initialized, custom_config):
        """Server uses custom configuration"""
        from reva.headless import RevaHeadlessLauncher

        launcher = RevaHeadlessLauncher(custom_config)
        launcher.start()
        assert launcher.getPort() == 5555
        launcher.stop()
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'pyghidra'"

```bash
pip install -r tests/requirements.txt
```

### "GHIDRA_INSTALL_DIR not set"

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
```

### "Server failed to become ready within 30 seconds"

- Check that ReVa extension is installed in Ghidra
- Verify extension ZIP was built: `ls dist/*.zip`
- Check Ghidra Extensions directory contains ReVa

### "Failed to import reva.headless"

- Build the extension: `gradle buildExtension`
- Install to Ghidra: Unzip `dist/*.zip` into `$GHIDRA_INSTALL_DIR/Ghidra/Extensions/`

### Tests are slow

- PyGhidra initialization is expensive (10-30s), but happens once per session
- Use session-scoped fixtures to avoid redundant initialization
- Use `-k` to run specific tests during development

## Performance

Typical test execution times:

- **PyGhidra initialization**: 10-30 seconds (once per session)
- **Server start**: 2-5 seconds (per test using `server` fixture)
- **MCP request**: <1 second
- **Full test suite**: ~2-5 minutes (depends on test count)

## Best Practices

1. **Use fixtures**: Don't initialize PyGhidra or start servers manually
2. **Session fixtures**: Expensive operations (PyGhidra init) should be session-scoped
3. **Cleanup**: Function-scoped fixtures handle cleanup automatically
4. **Assertions**: Use `get_response_result()` helper for MCP response validation
5. **Parametrize**: Use `@pytest.mark.parametrize` for testing multiple similar cases
6. **Descriptive names**: Test names should describe what is being tested

## Related Documentation

- **Main README**: `/README.md` - Project overview
- **Headless Mode**: `/src/main/java/reva/headless/CLAUDE.md` - Java implementation
- **Python Scripts**: `/scripts/` - User-facing headless tools
- **CI Workflows**: `/.github/CI_WORKFLOWS.md` - Complete CI documentation
