# ReVa Testing Guide

This document describes the testing infrastructure for ReVa, including both GUI and headless modes.

## Test Organization

### Test Directories

- **src/test/java/** - Unit tests (fast, no Ghidra GUI required)
- **src/test.slow/java/** - Integration tests (require Ghidra GUI)
- **tests/** - Python end-to-end tests for headless mode

### Test Types

1. **Unit Tests** - Test individual components in isolation
2. **Integration Tests** - Test components interacting with Ghidra
3. **End-to-End Tests** - Test complete workflows including MCP protocol
4. **Smoke Tests** - Quick validation of critical functionality

## Running Tests

### Prerequisites

For all tests:
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
gradle buildExtension
```

For Python tests:
```bash
pip install -r requirements-test.txt
```

### Java Tests

#### All Unit Tests
```bash
gradle test
```

#### Headless Tests Only
```bash
gradle test --tests "*Headless*"
```

#### Specific Test Class
```bash
gradle test --tests "*HeadlessRevaLauncherIntegrationTest"
```

#### With More Output
```bash
gradle test --info
```

### Python Tests

#### Quick Smoke Test (~30 seconds)
```bash
python3 tests/smoke_test.py
```

Expected output when working:
```
================================================================================
ReVa Headless Mode Smoke Test
================================================================================

1. Checking environment...
   ✓ GHIDRA_INSTALL_DIR: /opt/ghidra
   ✓ Build directory exists

2. Starting headless server...
   Waiting for server to start... ✓
   ✓ Server started on http://127.0.0.1:18080

3. Testing MCP protocol...
   ✓ Listed 12 tools
   ✓ Tool 'list-programs' available

4. Testing tool invocation...
   ✓ Tool 'list-programs' executed successfully

5. Testing server health...
   ✓ Server responding

6. Shutting down server...
   ✓ Server shut down gracefully

================================================================================
✓ All smoke tests passed!
================================================================================
```

#### Full End-to-End Suite
```bash
# Using pytest (recommended)
pytest tests/test_headless_e2e.py -v

# Using unittest
python3 tests/test_headless_e2e.py

# Specific test class
python3 -m unittest tests.test_headless_e2e.TestServerLifecycle

# With timeout
pytest tests/test_headless_e2e.py -v --timeout=300
```

#### All Python Tests
```bash
pytest tests/ -v
```

#### Parallel Execution
```bash
pytest tests/ -n auto  # Uses all CPU cores
```

#### With Coverage
```bash
pytest tests/ --cov=reva --cov-report=html
open htmlcov/index.html
```

## Test Configuration

### Test Ports

Tests use port **18080** to avoid conflicts with:
- Default ReVa port (8080)
- Other common services
- Parallel test execution

To change the test port, edit in test files:
```python
cls.test_port = 18080  # Change this
```

### Timeouts

Default timeouts:
- Server startup: 30 seconds
- MCP requests: 30 seconds
- Server shutdown: 5 seconds
- Overall test: 10 minutes (pytest)

## Continuous Integration

### GitHub Actions

Tests run automatically on:
- Push to main, develop, or claude/** branches
- Pull requests to main or develop
- Manual workflow dispatch

### Workflow Jobs

The CI pipeline includes three parallel jobs:

1. **smoke-test** - Quick validation (5 min timeout)
   ```yaml
   - Build extension
   - Run smoke test
   ```

2. **java-integration-tests** - Java tests (20 min timeout)
   ```yaml
   - Build extension
   - Run gradle test --tests "*Headless*"
   - Upload test reports
   ```

3. **python-e2e-tests** - Full E2E suite (30 min timeout)
   ```yaml
   - Build extension
   - Install test dependencies
   - Run pytest tests/test_headless_e2e.py
   - Upload test reports
   ```

### Adding the Workflow

Due to GitHub App permissions, the workflow file must be added manually:

1. Copy `.github/workflows/headless-tests.yml` to your repository
2. Commit directly to main (requires maintainer access)
3. Or create a PR from a personal fork (not via GitHub App)

The workflow is fully configured and ready to use once added.

## Test Coverage

### Current Coverage

| Component | Java Tests | Python Tests | Coverage |
|-----------|------------|--------------|----------|
| HeadlessMcpServerManager | ✓ | ✓ | High |
| HeadlessRevaLauncher | ✓ | ✓ | High |
| MCP Protocol | - | ✓ | High |
| Error Handling | ✓ | ✓ | Medium |
| Performance | ✓ | ✓ | Medium |

### Coverage Areas

1. **Server Lifecycle**
   - Startup and initialization
   - Graceful shutdown
   - Restart capability
   - Multiple instances
   - Port conflict handling

2. **Program Management**
   - Program registration
   - Program unregistration
   - Multiple programs
   - Program lifecycle

3. **MCP Protocol**
   - Tool listing
   - Resource listing
   - Tool invocation
   - Error responses
   - Malformed requests

4. **Performance**
   - Startup time
   - Response time
   - Resource usage
   - Concurrent requests

5. **Error Handling**
   - Invalid MCP methods
   - Non-existent tools
   - Malformed JSON
   - Connection failures
   - Timeout handling

## Troubleshooting

### Tests Fail to Start

**Problem**: `GHIDRA_INSTALL_DIR not set`

**Solution**:
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
# Or add to ~/.bashrc or ~/.zshrc
```

**Problem**: Build directory not found

**Solution**:
```bash
gradle buildExtension
```

### Port Already in Use

**Problem**: `Address already in use`

**Solution**:
```bash
# Find process using port
lsof -i :18080

# Kill the process
kill -9 <PID>

# Or kill all reva_headless processes
pkill -f reva_headless
```

### Tests Hang

**Problem**: Tests don't complete

**Solution**:
1. Check for stuck server processes:
   ```bash
   ps aux | grep reva_headless
   pkill -9 -f reva_headless
   ```

2. Clean up test artifacts:
   ```bash
   rm -rf /tmp/ghidra_*
   ```

3. Run with timeout:
   ```bash
   pytest tests/ --timeout=60
   ```

### Import Errors

**Problem**: `ModuleNotFoundError: No module named 'pyghidra'`

**Solution**:
```bash
pip install -r requirements-test.txt
```

**Problem**: `ModuleNotFoundError: No module named 'requests'`

**Solution**:
```bash
pip install requests
```

### Test Failures in CI

**Problem**: Tests pass locally but fail in CI

**Solution**:
1. Check GitHub Actions logs for specific error
2. Verify Ghidra version matches CI (11.4)
3. Check for timing issues (increase timeouts)
4. Verify all files are committed

## Writing New Tests

### Java Test Template

```java
package reva.server;

import static org.junit.Assert.*;
import org.junit.Test;
import reva.RevaHeadlessIntegrationTestBase;

public class MyFeatureTest extends RevaHeadlessIntegrationTestBase {

    @Test
    public void testMyFeature() {
        // Setup
        HeadlessRevaLauncher launcher = new HeadlessRevaLauncher();

        // Execute
        launcher.launch();

        // Verify
        assertTrue("Feature should work", launcher.isServerReady());

        // Cleanup
        launcher.shutdown();
    }
}
```

### Python Test Template

```python
import unittest
from tests.test_headless_e2e import HeadlessE2ETestBase

class TestMyFeature(HeadlessE2ETestBase):
    """Test my new feature"""

    def test_feature_works(self):
        """Test that feature works correctly"""
        # Start server
        self.start_server()

        # Test your feature
        response = self.mcp_request("tools/call", {
            "name": "my-tool",
            "arguments": {}
        })

        # Assertions
        self.assertIn("result", response)
        self.assertNotIn("error", response)
```

### Test Best Practices

1. **Use Descriptive Names**: Test names should describe what is being tested
2. **One Assertion Per Test**: Focus on testing one thing at a time
3. **Clean Up Resources**: Always clean up in tearDown/finally blocks
4. **Use Timeouts**: Prevent tests from hanging indefinitely
5. **Test Error Cases**: Don't just test the happy path
6. **Document Complex Tests**: Add comments explaining non-obvious logic

## Test Metrics

### Expected Execution Times

- **Smoke Test**: ~30 seconds
- **Java Unit Tests**: ~10 seconds
- **Java Integration Tests**: ~30 seconds
- **Python E2E (single)**: ~1-2 minutes
- **Python E2E (full suite)**: ~3-5 minutes
- **Full Test Suite**: ~5-10 minutes

### Performance Benchmarks

Tests include performance benchmarks:
- Server startup should be < 30 seconds
- Tool response should be < 5 seconds
- Shutdown should be < 5 seconds

If tests exceed these times, investigate performance issues.

## Contributing

When adding new features:

1. **Add Tests**: Every new feature should have tests
2. **Update Documentation**: Update this file if adding new test types
3. **Run Locally**: Verify tests pass before committing
4. **Check CI**: Ensure CI passes after pushing

### Required Tests for New Features

- **Java Features**: Add Java integration test
- **Python Features**: Add Python E2E test
- **Critical Features**: Add to smoke test
- **API Changes**: Add protocol tests

## Resources

- [JUnit 4 Documentation](https://junit.org/junit4/)
- [pytest Documentation](https://docs.pytest.org/)
- [Ghidra Test Framework](https://ghidra.re/ghidra_docs/api/)
- [MCP Protocol](https://modelcontextprotocol.io/)

## Support

For test-related issues:
1. Check this documentation
2. Review test logs
3. Check GitHub Actions workflow runs
4. Open an issue on GitHub

## Future Improvements

Potential test enhancements:
- [ ] Add coverage for all tool providers
- [ ] Add stress tests for concurrent requests
- [ ] Add memory leak detection
- [ ] Add integration with Ghidra projects
- [ ] Add performance regression tests
- [ ] Add Docker-based test environment
