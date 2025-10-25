#!/usr/bin/env python3
"""
Smoke test for ReVa headless mode.

This is a quick test to verify basic functionality:
1. Server starts
2. MCP endpoint is accessible
3. Tools can be listed
4. Server shuts down cleanly

Usage:
    python3 tests/smoke_test.py
"""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import requests


def main():
    """Run smoke test"""
    print("=" * 80)
    print("ReVa Headless Mode Smoke Test")
    print("=" * 80)

    # Configuration
    test_port = 18080
    test_host = "127.0.0.1"
    base_url = f"http://{test_host}:{test_port}"
    mcp_endpoint = f"{base_url}/mcp/message"

    # Verify environment
    print("\n1. Checking environment...")

    ghidra_dir = os.getenv("GHIDRA_INSTALL_DIR")
    if not ghidra_dir:
        print("   ❌ GHIDRA_INSTALL_DIR not set")
        return 1

    print(f"   ✓ GHIDRA_INSTALL_DIR: {ghidra_dir}")

    project_root = Path(__file__).parent.parent
    build_dir = project_root / "build" / "classes" / "java" / "main"

    if not build_dir.exists():
        print(f"   ❌ Build directory not found: {build_dir}")
        print("   Run 'gradle buildExtension' first")
        return 1

    print(f"   ✓ Build directory exists: {build_dir}")

    # Start server
    print("\n2. Starting headless server...")

    server_process = subprocess.Popen(
        [
            sys.executable,
            str(project_root / "reva_headless.py"),
            "--host", test_host,
            "--port", str(test_port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    # Wait for server to be ready
    print("   Waiting for server to start...", end="", flush=True)
    max_wait = 30
    start_time = time.time()
    server_ready = False

    while time.time() - start_time < max_wait:
        try:
            requests.get(base_url, timeout=1)
            server_ready = True
            break
        except requests.exceptions.RequestException:
            print(".", end="", flush=True)
            time.sleep(0.5)

        # Check if process died
        if server_process.poll() is not None:
            stdout, stderr = server_process.communicate()
            print("\n   ❌ Server process died")
            print(f"   STDOUT: {stdout}")
            print(f"   STDERR: {stderr}")
            return 1

    if not server_ready:
        print("\n   ❌ Server failed to start within timeout")
        server_process.kill()
        return 1

    print(" ✓")
    print(f"   ✓ Server started on {base_url}")

    try:
        # Test MCP endpoint
        print("\n3. Testing MCP protocol...")

        # List tools
        response = requests.post(
            mcp_endpoint,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list"
            },
            headers={"Content-Type": "application/json"},
            timeout=10
        )

        if response.status_code != 200:
            print(f"   ❌ MCP request failed with status {response.status_code}")
            return 1

        data = response.json()

        if "result" not in data:
            print(f"   ❌ No result in MCP response: {data}")
            return 1

        tools = data["result"].get("tools", [])
        print(f"   ✓ Listed {len(tools)} tools")

        # Verify some expected tools
        tool_names = [tool["name"] for tool in tools]
        expected_tools = ["list-programs", "list-functions", "get-decompilation"]

        for tool_name in expected_tools:
            if tool_name in tool_names:
                print(f"   ✓ Tool '{tool_name}' available")
            else:
                print(f"   ⚠ Tool '{tool_name}' not found")

        # Call list-programs tool
        print("\n4. Testing tool invocation...")

        response = requests.post(
            mcp_endpoint,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "list-programs",
                    "arguments": {}
                }
            },
            headers={"Content-Type": "application/json"},
            timeout=10
        )

        if response.status_code != 200:
            print(f"   ❌ Tool call failed with status {response.status_code}")
            return 1

        data = response.json()

        if "result" not in data:
            print(f"   ❌ No result in tool call response: {data}")
            return 1

        print("   ✓ Tool 'list-programs' executed successfully")

        # Test server health
        print("\n5. Testing server health...")

        response = requests.get(base_url, timeout=5)
        print(f"   ✓ Server responding (status: {response.status_code})")

    finally:
        # Shutdown server
        print("\n6. Shutting down server...")

        try:
            server_process.send_signal(signal.SIGTERM)
            server_process.wait(timeout=5)
            print("   ✓ Server shut down gracefully")
        except subprocess.TimeoutExpired:
            server_process.kill()
            server_process.wait()
            print("   ⚠ Server had to be force-killed")
        except Exception as e:
            print(f"   ❌ Error during shutdown: {e}")
            server_process.kill()
            return 1

    # Success
    print("\n" + "=" * 80)
    print("✓ All smoke tests passed!")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
