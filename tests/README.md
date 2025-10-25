# ReVa Headless Mode Tests

This directory contains end-to-end tests for ReVa's headless mode.

## Test Organization

- **test_headless_e2e.py** - Comprehensive end-to-end tests covering:
  - Server lifecycle
  - MCP protocol communication
  - Error handling
  - Performance benchmarks

- **smoke_test.py** - Quick smoke test for basic functionality
  - Fast execution (~30 seconds)
  - Verifies critical functionality
  - Good for CI/CD pipelines

## Prerequisites

### Environment Setup

1. **Ghidra Installation**
   ```bash
   export GHIDRA_INSTALL_DIR=/path/to/ghidra
   ```

2. **Build ReVa Extension**
   ```bash
   gradle buildExtension
   ```

3. **Install Test Dependencies**
   ```bash
   pip install -r requirements-test.txt
   ```

## Running Tests

### Quick Smoke Test

Run the smoke test to verify basic functionality:

```bash
python3 tests/smoke_test.py
```

Expected output:
```
================================================================================
ReVa Headless Mode Smoke Test
================================================================================

1. Checking environment...
   ✓ GHIDRA_INSTALL_DIR: /opt/ghidra
   ✓ Build directory exists: build/classes/java/main

2. Starting headless server...
   Waiting for server to start... ✓
   ✓ Server started on http://127.0.0.1:18080

3. Testing MCP protocol...
   ✓ Listed 12 tools
   ✓ Tool 'list-programs' available
   ✓ Tool 'list-functions' available
   ✓ Tool 'get-decompilation' available

4. Testing tool invocation...
   ✓ Tool 'list-programs' executed successfully

5. Testing server health...
   ✓ Server responding (status: 405)

6. Shutting down server...
   ✓ Server shut down gracefully

================================================================================
✓ All smoke tests passed!
================================================================================
```

### Full End-to-End Tests

Run comprehensive tests using unittest:

```bash
python3 tests/test_headless_e2e.py
```

Or using pytest:

```bash
pytest tests/test_headless_e2e.py -v
```

### Running Specific Test Classes

```bash
# Test only server lifecycle
python3 -m unittest tests.test_headless_e2e.TestServerLifecycle

# Test only MCP protocol
python3 -m unittest tests.test_headless_e2e.TestMCPProtocol

# Test only performance
python3 -m unittest tests.test_headless_e2e.TestPerformance
```

### Parallel Test Execution

Use pytest-xdist for faster test execution:

```bash
pytest tests/ -n auto
```

### With Coverage

Generate code coverage report:

```bash
pytest tests/ --cov=reva --cov-report=html
```

## Java Integration Tests

Run Java-based headless integration tests:

```bash
# Run headless launcher tests
gradle test --tests "*HeadlessRevaLauncherIntegrationTest"

# Run all headless tests
gradle test --tests "*Headless*"
```

## Test Configuration

### Custom Port

Tests use port 18080 by default to avoid conflicts. To use a different port:

```python
# In test files, modify:
cls.test_port = 18080  # Change this
```

### Test Timeout

End-to-end tests have timeouts to prevent hanging:
- Server startup: 30 seconds
- MCP requests: 30 seconds
- Server shutdown: 5 seconds

Adjust in test files if needed for slower systems.

## Continuous Integration

### GitHub Actions

Tests can be run in GitHub Actions:

```yaml
- name: Run Headless Tests
  run: |
    export GHIDRA_INSTALL_DIR=/opt/ghidra
    gradle buildExtension
    python3 tests/smoke_test.py
```

### Docker

Run tests in Docker:

```bash
docker run --rm \
  -v $(pwd):/workspace \
  -e GHIDRA_INSTALL_DIR=/opt/ghidra \
  ghidra-dev:latest \
  python3 /workspace/tests/smoke_test.py
```

## Troubleshooting

### Port Already in Use

If port 18080 is already in use:

```bash
# Find process using the port
lsof -i :18080

# Kill the process
kill <PID>
```

### Server Fails to Start

1. **Check Ghidra installation**
   ```bash
   ls -la $GHIDRA_INSTALL_DIR
   ```

2. **Verify build**
   ```bash
   ls -la build/classes/java/main/reva/server/
   ```

3. **Check logs**
   - Server stdout/stderr is captured in test output
   - Run with verbose mode: `pytest tests/ -v -s`

### Test Hangs

1. **Kill hung processes**
   ```bash
   pkill -f reva_headless.py
   ```

2. **Clean up resources**
   ```bash
   # Remove any test artifacts
   rm -rf /tmp/ghidra_*
   ```

### Import Errors

If you get `ModuleNotFoundError`:

```bash
# Install test dependencies
pip install -r requirements-test.txt

# Verify pyghidra is installed
python3 -c "import pyghidra; print('OK')"
```

## Writing New Tests

### Test Structure

```python
class TestMyFeature(HeadlessE2ETestBase):
    """Test my new feature"""

    def test_feature_works(self):
        """Test that feature works"""
        self.start_server()

        # Your test code here
        response = self.mcp_request("tools/call", {
            "name": "my-tool",
            "arguments": {}
        })

        self.assertIn("result", response)
```

### Test Fixtures

Use setUp/tearDown for test-specific resources:

```python
def setUp(self):
    """Set up for each test"""
    super().setUp()
    self.my_resource = create_resource()

def tearDown(self):
    """Clean up after each test"""
    cleanup_resource(self.my_resource)
    super().tearDown()
```

### Asserting MCP Responses

```python
# Assert successful response
response = self.mcp_request("tools/list")
self.assertIn("result", response)
self.assertNotIn("error", response)

# Assert error response
response = self.mcp_request("invalid/method")
self.assertIn("error", response)
```

## Test Metrics

Current test coverage:
- **Java Integration Tests**: Core headless launcher functionality
- **Python E2E Tests**: Full MCP protocol stack
- **Smoke Test**: Critical path verification

Expected test execution times:
- Smoke test: ~30 seconds
- Full E2E suite: ~2-3 minutes
- Java integration tests: ~30 seconds

## Contributing

When adding new headless features:

1. Add unit tests for Java classes
2. Add integration tests for server functionality
3. Add E2E tests for client-facing behavior
4. Update smoke test if adding critical functionality

## References

- [unittest documentation](https://docs.python.org/3/library/unittest.html)
- [pytest documentation](https://docs.pytest.org/)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
