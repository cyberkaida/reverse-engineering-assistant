# ReVa Headless Scripts

This directory contains Python scripts for running and testing ReVa in headless Ghidra mode.

## Prerequisites

### System Requirements
- Python 3.9+
- Java 21+
- Ghidra 11.4+ installed
- `GHIDRA_INSTALL_DIR` environment variable set

### Python Dependencies
```bash
pip install pyghidra
```

## Scripts

### `reva_headless_server.py`

Main launcher script for starting ReVa MCP server in headless mode.

**Basic Usage:**
```bash
# Start with defaults (port 8080, localhost)
python scripts/reva_headless_server.py

# Start with custom port
python scripts/reva_headless_server.py --port 9090

# Start with configuration file
python scripts/reva_headless_server.py --config config/reva-headless.properties

# Start and keep running (for long-running servers)
python scripts/reva_headless_server.py --wait

# Custom timeout for startup
python scripts/reva_headless_server.py --timeout 60
```

**Options:**
- `--port PORT` - Server port (default: 8080)
- `--host HOST` - Server host (default: 127.0.0.1)
- `--config FILE` - Configuration file path
- `--wait` - Keep server running until Ctrl+C
- `--timeout SECONDS` - Startup timeout (default: 30)

**Exit Codes:**
- `0` - Success
- `1` - Error (missing dependencies, startup failure, etc.)

### `test_headless_quick.py`

Quick smoke test to verify headless mode is working.

**Usage:**
```bash
python scripts/test_headless_quick.py
```

**What it tests:**
1. PyGhidra can be imported and initialized
2. ReVa classes can be imported
3. Server starts successfully
4. Server becomes ready within timeout
5. Server can be stopped cleanly

**Output:**
```
==========================================
ReVa Headless Quick Test
==========================================

[1/5] Importing pyghidra...
     ✓ pyghidra imported

[2/5] Initializing Ghidra...
     ✓ Ghidra initialized in 3.45s

[3/5] Importing ReVa classes...
     ✓ ReVa classes imported

[4/5] Starting ReVa MCP server...
     ✓ Server started in 1.23s

[5/5] Waiting for server to be ready...
     ✓ Server ready on port 8080
     ✓ Endpoint: http://localhost:8080/mcp/message
     ✓ Status checks passed

[*] Stopping server...
     ✓ Server stopped cleanly

==========================================
✅ All tests passed!
==========================================
```

## Configuration

### Example Configuration File

See `config/reva-headless-example.properties` for a complete example with all options documented.

**Minimal Configuration:**
```properties
reva.server.options.server.port=8080
reva.server.options.server.host=127.0.0.1
```

**Production Configuration:**
```properties
reva.server.options.server.port=8080
reva.server.options.server.host=127.0.0.1
reva.server.options.api.key.authentication.enabled=true
reva.server.options.api.key=ReVa-your-secure-api-key
reva.server.options.debug.mode=false
```

## Common Workflows

### 1. Quick Local Testing

```bash
# Terminal 1: Start server
python scripts/reva_headless_server.py --wait

# Terminal 2: Test with MCP client
# ... your MCP client commands ...

# Terminal 1: Press Ctrl+C to stop
```

### 2. Automated Testing

```bash
# Run quick smoke test
python scripts/test_headless_quick.py

# Run with pytest (if available)
pytest scripts/ -v
```

### 3. CI/CD Integration

```yaml
# GitHub Actions example
- name: Test ReVa Headless
  env:
    GHIDRA_INSTALL_DIR: /opt/ghidra
  run: |
    pip install pyghidra
    python scripts/test_headless_quick.py
```

### 4. Docker Container

```dockerfile
FROM ghidra:latest

RUN pip install pyghidra

COPY . /reva
WORKDIR /reva

CMD ["python", "scripts/reva_headless_server.py", "--wait"]
```

### 5. Background Server

```bash
# Start in background
python scripts/reva_headless_server.py --wait &
SERVER_PID=$!

# Do your work...

# Stop when done
kill $SERVER_PID
```

## Troubleshooting

### ImportError: No module named 'pyghidra'

```bash
pip install pyghidra
```

### GHIDRA_INSTALL_DIR not set

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
```

### Port already in use

```bash
# Use different port
python scripts/reva_headless_server.py --port 8081
```

### Server fails to start

1. Check Java version: `java -version` (need 21+)
2. Check Ghidra installation: `ls $GHIDRA_INSTALL_DIR`
3. Check pyghidra: `python -c "import pyghidra; pyghidra.start()"`
4. Increase timeout: `--timeout 60`

### Slow startup

First startup can be slow (3-7 seconds for Ghidra initialization + 1-2 seconds for server). Subsequent runs in the same process are faster.

**Tips:**
- Keep pyghidra session alive for multiple operations
- Use `--wait` to keep server running
- Reuse the same launcher instance

## Performance

### Typical Startup Times

| Phase | Time |
|-------|------|
| Import pyghidra | < 0.1s |
| Initialize Ghidra | 3-5s |
| Start MCP server | 1-2s |
| **Total** | **4-7s** |

### Memory Usage

| Component | Memory |
|-----------|--------|
| Base Ghidra | 200-300 MB |
| ReVa Server | 50-100 MB |
| **Total** | **250-400 MB** |

## Security Notes

1. **Default binding** - Server binds to `127.0.0.1` (localhost only)
2. **API keys** - Disabled by default, enable for production
3. **Remote access** - Only use `--host 0.0.0.0` with API key auth
4. **Configuration files** - Don't commit files with API keys
5. **HTTPS** - Use reverse proxy (nginx, caddy) for production

## Development

### Adding New Scripts

1. Create script in `scripts/`
2. Add shebang: `#!/usr/bin/env python3`
3. Add docstring explaining purpose
4. Follow existing patterns
5. Update this README

### Testing Scripts

```bash
# Run all tests
pytest scripts/ -v

# Run specific test
python scripts/test_headless_quick.py

# With coverage
pytest scripts/ --cov=scripts --cov-report=html
```

## Related Documentation

- `/HEADLESS_ARCHITECTURE.md` - Architecture overview
- `/src/main/java/reva/headless/CLAUDE.md` - Java API documentation
- `/config/reva-headless-example.properties` - Configuration reference
- `/.github/workflows/` - CI/CD examples

## Support

For issues or questions:
1. Check this README and related documentation
2. Check GitHub Issues
3. Run `test_headless_quick.py` for diagnostics
