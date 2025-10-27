#!/usr/bin/env python3
"""
Quick test script for ReVa headless mode

This script performs a quick smoke test to verify that:
1. PyGhidra can be initialized
2. ReVa headless launcher can start
3. Server becomes ready
4. Server can be stopped cleanly

Usage:
    python scripts/test_headless_quick.py

Requirements:
    - pyghidra installed
    - GHIDRA_INSTALL_DIR set
    - Java 21+ installed
"""

import sys
import time


def test_headless_startup():
    """Test that headless server can start and stop"""
    print("=" * 60)
    print("ReVa Headless Quick Test")
    print("=" * 60)

    try:
        # Step 1: Import pyghidra
        print("\n[1/5] Importing pyghidra...")
        try:
            import pyghidra
            print("     ✓ pyghidra imported")
        except ImportError as e:
            print(f"     ✗ Failed to import pyghidra: {e}")
            print("     Install with: pip install pyghidra")
            return False

        # Step 2: Initialize Ghidra
        print("\n[2/5] Initializing Ghidra...")
        start_time = time.time()
        pyghidra.start(verbose=False)
        init_time = time.time() - start_time
        print(f"     ✓ Ghidra initialized in {init_time:.2f}s")

        # Step 3: Import ReVa classes
        print("\n[3/5] Importing ReVa classes...")
        from reva.headless import RevaHeadlessLauncher
        print("     ✓ ReVa classes imported")

        # Step 4: Start server
        print("\n[4/5] Starting ReVa MCP server...")
        launcher = RevaHeadlessLauncher()

        start_time = time.time()
        launcher.start()
        startup_time = time.time() - start_time
        print(f"     ✓ Server started in {startup_time:.2f}s")

        # Step 5: Wait for ready
        print("\n[5/5] Waiting for server to be ready...")
        if launcher.waitForServer(30000):
            port = launcher.getPort()
            print(f"     ✓ Server ready on port {port}")
            print(f"     ✓ Endpoint: http://localhost:{port}/mcp/message")

            # Verify status
            assert launcher.isRunning(), "Server should be running"
            assert launcher.isServerReady(), "Server should be ready"
            print("     ✓ Status checks passed")

            # Clean shutdown
            print("\n[*] Stopping server...")
            launcher.stop()
            print("     ✓ Server stopped cleanly")

            # Final summary
            print("\n" + "=" * 60)
            print("✅ All tests passed!")
            print("=" * 60)
            print(f"Total initialization time: {init_time:.2f}s")
            print(f"Server startup time: {startup_time:.2f}s")
            print(f"Server endpoint: http://localhost:{port}/mcp/message")
            print("\nReVa is ready for headless operation! 🎉")
            return True

        else:
            print("     ✗ Server failed to become ready within timeout")
            return False

    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main entry point"""
    success = test_headless_startup()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
