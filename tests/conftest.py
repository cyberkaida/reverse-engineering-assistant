"""
Pytest configuration and shared fixtures for ReVa headless integration tests.

Fixtures:
- ghidra_initialized: Initialize PyGhidra once for the entire test session
- test_program: Create a test program with memory and strings (reused across tests)
- server: Start and stop a ReVa headless server for each test
- mcp_client: Helper object for making MCP requests

Fixture Scopes:
- session: Created once, shared across all tests (ghidra_initialized, test_program)
- function: Created for each test function (server, mcp_client)
"""

import pytest
import sys
from pathlib import Path


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
    program = create_test_program()

    if program:
        print(f"[Fixture] Test program created: {program.getName()}")
    else:
        print("[Fixture] WARNING: Failed to create test program")

    yield program

    # Cleanup: Release program
    if program:
        try:
            from ghidra.program.database import ProgramDB
            if isinstance(program, ProgramDB):
                program.release(None)
                print("[Fixture] Test program released")
        except Exception as e:
            print(f"[Fixture] Warning: Failed to release test program: {e}")


@pytest.fixture
def server(ghidra_initialized):
    """
    Start a ReVa headless server for a test.

    Creates a new server instance, starts it, waits for it to become ready,
    and automatically stops it after the test completes.

    Scope: function (new server for each test)

    Yields:
        RevaHeadlessLauncher instance (running and ready)

    Raises:
        AssertionError: If server fails to start or become ready within 30 seconds
    """
    from reva.headless import RevaHeadlessLauncher

    launcher = RevaHeadlessLauncher()

    print(f"\n[Fixture] Starting ReVa headless server...")
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
            response = mcp_client.call_tool("list-open-programs")
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
                name: Tool name (e.g., "list-open-programs")
                arguments: Tool arguments dictionary (optional)
                timeout: Request timeout in seconds (default: 10)

            Returns:
                Parsed JSON response or None if request failed
            """
            return make_mcp_request(self.port, name, arguments, timeout)

    yield MCPClient(server.getPort())
