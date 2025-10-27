#!/usr/bin/env python3
"""
Quick test to check MCP server requests locally using proper MCP client.
"""
import sys
from pathlib import Path

# Add tests directory to path so we can import helpers
sys.path.insert(0, str(Path(__file__).parent / "tests"))

from helpers import make_mcp_request, get_response_result


def test_mcp_request(port):
    print(f"Testing MCP request to http://localhost:{port}/mcp/message")
    print("Using proper MCP Python SDK client\n")

    try:
        response = make_mcp_request(port, "list-programs")
        if response:
            result = get_response_result(response)
            print(f"\nSuccess! Got response:")
            print(f"Content: {result}")
            return True
        else:
            print("\nFailed: No response")
            return False

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    import pyghidra
    pyghidra.start()

    from reva.headless import RevaHeadlessLauncher

    print("Starting ReVa headless server...")
    launcher = RevaHeadlessLauncher()

    try:
        launcher.start()
        print(f"Server started on port {launcher.getPort()}")

        if launcher.waitForServer(30000):
            print("Server is ready!\n")
            success = test_mcp_request(launcher.getPort())
            sys.exit(0 if success else 1)
        else:
            print("Server failed to become ready")
            sys.exit(1)
    finally:
        launcher.stop()
        print("\nServer stopped")
