"""
Pytest configuration and shared fixtures for ReVa headless integration tests.

Fixtures:
- ghidra_initialized: Initialize PyGhidra once for the entire test session
- test_program: Create a test program with memory and strings (reused across tests)
- server: Start and stop a ReVa headless server for each test
- mcp_client: Helper object for making MCP requests
- capture_ghidra_logs: Auto-use fixture that prints Ghidra logs on test failure

Fixture Scopes:
- session: Created once, shared across all tests (ghidra_initialized, test_program)
- function: Created for each test function (server, mcp_client, capture_ghidra_logs)
"""

import pytest
import pytest_asyncio
import sys
import os
from pathlib import Path


# ============================================================================
# Pytest Hooks
# ============================================================================

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Store test result on the node so fixtures can check outcome."""
    outcome = yield
    report = outcome.get_result()
    # Store the report for each phase (setup, call, teardown)
    setattr(item, f"_report_{report.when}", report)


@pytest.fixture(scope="session")
def ghidra_initialized():
    """
    Initialize PyGhidra once for the entire test session.

    This is an expensive operation (10-30 seconds), so we do it once
    and reuse the initialized environment for all tests.

    Scope: session (runs once at start of test session)

    Yields:
        None (side effect: PyGhidra initialized)
    """
    import pyghidra

    print("\n[Fixture] Initializing PyGhidra (one-time setup)...")
    pyghidra.start(verbose=False)
    print("[Fixture] PyGhidra initialized successfully")

    yield

    # No explicit cleanup needed - PyGhidra handles shutdown


@pytest.fixture(autouse=True)
def capture_ghidra_logs(request):
    """
    Capture Ghidra application.log entries during each test.

    On test failure, reads and prints any new log entries that were written
    during the test. This helps diagnose Java-side issues (Jetty, MCP server,
    Ghidra internals) that are otherwise invisible in pytest output.

    Only activates when Ghidra/PyGhidra is initialized (integration tests).
    Safely no-ops for unit tests that don't use Ghidra.

    Scope: function (autouse - runs for every test)
    """
    log_file = None
    start_pos = 0

    try:
        from ghidra.framework import Application
        if Application.isInitialized():
            log_file = Path(str(Application.getUserSettingsDirectory())) / "application.log"
            start_pos = log_file.stat().st_size if log_file.exists() else 0
    except Exception:
        pass  # Ghidra not available (unit tests, mocked environment)

    yield

    if log_file is None:
        return

    # After the test, check if it failed and print new log entries
    report = getattr(request.node, "_report_call", None)
    if report is not None and report.failed:
        if log_file.exists() and log_file.stat().st_size > start_pos:
            try:
                with open(log_file, "r", errors="replace") as f:
                    f.seek(start_pos)
                    new_entries = f.read()
                if new_entries.strip():
                    print(f"\n{'='*72}")
                    print(f"  Ghidra application.log entries during failed test:")
                    print(f"  {request.node.nodeid}")
                    print(f"{'='*72}")
                    # Limit output to last 200 lines to avoid flooding
                    lines = new_entries.strip().splitlines()
                    if len(lines) > 200:
                        print(f"  ... ({len(lines) - 200} lines omitted) ...")
                        lines = lines[-200:]
                    for line in lines:
                        print(f"  {line}")
                    print(f"{'='*72}\n")
            except Exception as e:
                print(f"[capture_ghidra_logs] Failed to read log: {e}")


@pytest.fixture(scope="session")
def test_program(ghidra_initialized):
    """
    Create a test program with memory and strings.

    Creates a program that is reused across multiple tests to avoid
    redundant program creation overhead.

    Program details:
    - Name: TestHeadlessProgram
    - Architecture: x86 32-bit LE
    - Memory: .text at 0x00401000 (4KB)
    - Strings: "Hello ReVa Test", "Test String 123"
    - Symbol: test_function at 0x00401000

    Scope: session (created once, shared across all tests)

    Yields:
        ProgramDB instance or None if creation failed
    """
    from tests.helpers import create_test_program

    print("\n[Fixture] Creating test program...")
    builder = create_test_program()

    if builder:
        program = builder.getProgram()
        print(f"[Fixture] Test program created: {program.getName()}")
    else:
        program = None
        print("[Fixture] WARNING: Failed to create test program")

    yield program

    # Cleanup: Dispose builder (which releases the program)
    if builder:
        try:
            builder.dispose()
            print("[Fixture] Test program builder disposed")
        except Exception as e:
            print(f"[Fixture] Warning: Failed to dispose builder: {e}")


@pytest.fixture
def server(ghidra_initialized):
    """
    Start a ReVa headless server for a test on a random port.

    Uses a random available port to avoid conflicts with other tests
    (especially launcher tests that may also bind to port 8080).

    Scope: function (new server for each test)

    Yields:
        RevaHeadlessLauncher instance (running and ready)

    Raises:
        AssertionError: If server fails to start or become ready within 30 seconds
    """
    from reva.headless import RevaHeadlessLauncher

    # Use random port to avoid conflicts with launcher tests
    launcher = RevaHeadlessLauncher(None, True)  # configFile=None, useRandomPort=True

    print(f"\n[Fixture] Starting ReVa headless server (random port)...")
    launcher.start()

    # Wait for server to be ready (30 second timeout)
    ready = launcher.waitForServer(30000)
    assert ready, "Server failed to become ready within 30 seconds"

    port = launcher.getPort()
    print(f"[Fixture] Server ready on port {port}")

    yield launcher

    # Cleanup: Stop server
    print(f"[Fixture] Stopping server...")
    launcher.stop()
    print(f"[Fixture] Server stopped")


@pytest.fixture
def mcp_client(server):
    """
    Create an MCP client helper for making requests.

    Provides a convenient interface for making MCP tool calls to the
    server started by the 'server' fixture.

    Scope: function (new client for each test)

    Yields:
        MCPClient instance with call_tool() method

    Example:
        def test_something(mcp_client):
            response = mcp_client.call_tool("list-project-files")
            assert response is not None
    """
    from tests.helpers import make_mcp_request

    class MCPClient:
        """Helper class for making MCP requests"""

        def __init__(self, port: int):
            self.port = port

        def call_tool(self, name: str, arguments: dict = None, timeout: int = 10):
            """
            Call an MCP tool.

            Args:
                name: Tool name (e.g., "list-project-files")
                arguments: Tool arguments dictionary (optional)
                timeout: Request timeout in seconds (default: 10)

            Returns:
                Parsed JSON response or None if request failed
            """
            return make_mcp_request(self.port, name, arguments, timeout)

    yield MCPClient(server.getPort())


# ============================================================================
# CLI-Specific Fixtures
# ============================================================================

@pytest.fixture
def isolated_workspace(tmp_path, monkeypatch):
    """
    Create an isolated workspace for CLI tests.

    Creates a temporary directory and changes the current working directory
    to it. This ensures CLI tests don't interfere with each other or the
    actual repository.

    Scope: function (new workspace for each test)

    Yields:
        Path: Temporary directory path (cwd is set to this path)

    Example:
        def test_cli_creates_project(isolated_workspace):
            # cwd is now tmp_path
            assert Path.cwd() == isolated_workspace
            # CLI will create .reva/ here
    """
    original_cwd = Path.cwd()
    monkeypatch.chdir(tmp_path)
    print(f"\n[Fixture] Created isolated workspace: {tmp_path}")

    yield tmp_path

    # Restore original cwd (cleanup)
    monkeypatch.chdir(original_cwd)


@pytest.fixture
def test_binary(isolated_workspace):
    """
    Create a minimal test binary for import testing.

    Generates a tiny valid executable that can be imported into Ghidra.
    The binary is created in the isolated_workspace.

    Scope: function (new binary for each test)

    Yields:
        Path: Path to the created binary file

    Example:
        def test_import_binary(test_binary):
            assert test_binary.exists()
            assert test_binary.stat().st_size > 0
    """
    from tests.helpers import create_minimal_binary

    binary_path = isolated_workspace / "test.exe"
    create_minimal_binary(binary_path)

    print(f"[Fixture] Created test binary: {binary_path} ({binary_path.stat().st_size} bytes)")

    yield binary_path


@pytest.fixture
def cli_process(isolated_workspace):
    """
    Start mcp-reva CLI as a subprocess.

    Starts the CLI in the isolated workspace and automatically terminates
    it after the test completes.

    Scope: function (new process for each test)

    Yields:
        subprocess.Popen: Running mcp-reva process

    Example:
        def test_cli_startup(cli_process):
            # Process is running
            assert cli_process.poll() is None
            # Can interact with stdin/stdout
            cli_process.stdin.write('{"jsonrpc":"2.0"}\n')
    """
    import subprocess
    import time

    print(f"\n[Fixture] Starting mcp-reva CLI subprocess...")

    proc = subprocess.Popen(
        ["uv", "run", "mcp-reva"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=isolated_workspace
    )

    # Give it a moment to start
    time.sleep(0.5)

    if proc.poll() is not None:
        # Process already exited - capture error
        _, stderr = proc.communicate()
        raise RuntimeError(f"mcp-reva failed to start: {stderr}")

    print(f"[Fixture] mcp-reva started (PID: {proc.pid})")

    yield proc

    # Cleanup: Terminate process
    print(f"[Fixture] Terminating mcp-reva (PID: {proc.pid})...")
    proc.terminate()

    try:
        proc.wait(timeout=5)
        print(f"[Fixture] Process terminated gracefully")
    except subprocess.TimeoutExpired:
        print(f"[Fixture] Process didn't terminate, killing...")
        proc.kill()
        proc.wait()


@pytest_asyncio.fixture(loop_scope="function")
async def mcp_stdio_client(isolated_workspace):
    """
    Create an MCP client that connects to mcp-reva via stdio.

    Uses the official MCP Python SDK stdio_client to spawn mcp-reva
    as a subprocess and communicate via stdin/stdout.

    Scope: function (new client for each test)

    Yields:
        ClientSession: MCP client session connected to mcp-reva

    Example:
        @pytest.mark.asyncio
        async def test_initialize(mcp_stdio_client):
            result = await mcp_stdio_client.initialize()
            assert result.serverInfo.name == "ReVa"

    Note:
        Suppresses RuntimeError from anyio cancel scope during teardown.
        This is a known pytest-asyncio/anyio compatibility issue that
        doesn't affect functionality.
    """
    from mcp.client.stdio import stdio_client, StdioServerParameters
    from mcp import ClientSession
    from pathlib import Path
    import asyncio

    # Configure mcp-reva as stdio server
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "mcp-reva"],
        cwd=str(isolated_workspace),
        env=os.environ.copy()
    )

    print(f"\n[Fixture] Starting mcp-reva via stdio_client in {isolated_workspace}...")

    try:
        # Connect to mcp-reva via stdio
        async with stdio_client(server_params) as (read_stream, write_stream):
            session = ClientSession(read_stream, write_stream)

            # Manually enter the session context
            await session.__aenter__()

            try:
                print("[Fixture] Subprocess started, waiting for initialization to complete...")

                # Give subprocess time to complete blocking initialization
                # (PyGhidra, project, server startup happens before stdio bridge starts)
                await asyncio.sleep(2)

                print("[Fixture] Initializing MCP session...")

                # Initialize the session with timeout
                try:
                    init_result = await asyncio.wait_for(
                        session.initialize(),
                        timeout=60.0  # Initialization is fast, but allow buffer for CI overhead
                    )
                    print(f"[Fixture] MCP session initialized: {init_result.serverInfo.name} v{init_result.serverInfo.version}")
                except asyncio.TimeoutError:
                    raise TimeoutError(
                        "MCP session initialization timed out after 60 seconds. "
                        "Check stderr logs for errors."
                    )

                yield session

                print("[Fixture] Closing MCP session...")
            finally:
                # Manually exit the session context
                try:
                    await session.__aexit__(None, None, None)
                except RuntimeError as e:
                    if "cancel scope" not in str(e):
                        raise
                    print(f"[Fixture] Suppressed expected cancel scope error: {e}")
                except Exception as e:
                    print(f"[Fixture] Warning: Error during session cleanup: {e}")
    except RuntimeError as e:
        # Suppress "Attempted to exit cancel scope in a different task" error
        # This is a known pytest-asyncio/anyio compatibility issue
        if "cancel scope" not in str(e):
            raise
        print(f"[Fixture] Suppressed expected cancel scope error during stdio_client cleanup")
