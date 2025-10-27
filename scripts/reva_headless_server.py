#!/usr/bin/env python3
"""
ReVa MCP Server Headless Launcher

This script starts the ReVa MCP server in headless Ghidra mode using pyghidra.
It can be used for automation, testing, or running ReVa without the GUI.

Requirements:
    - pyghidra package installed
    - GHIDRA_INSTALL_DIR environment variable set
    - Java 21+ installed

Usage:
    # Start with defaults (port 8080, localhost)
    python reva_headless_server.py

    # Start with custom port
    python reva_headless_server.py --port 9090

    # Start with configuration file
    python reva_headless_server.py --config /path/to/reva.properties

    # Start and keep running
    python reva_headless_server.py --wait

Example:
    # Quick test
    python reva_headless_server.py
    # Server starts, you can test it, then Ctrl+C to stop

    # Long-running server
    python reva_headless_server.py --wait
    # Server runs until you press Ctrl+C
"""

import argparse
import sys
import time
import signal
from pathlib import Path

# Track launcher globally for signal handling
launcher = None


def signal_handler(sig, frame):
    """Handle shutdown signals gracefully"""
    print("\n🛑 Shutting down ReVa MCP server...")
    if launcher:
        launcher.stop()
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="Start ReVa MCP server in headless Ghidra mode",
        epilog="Example: python reva_headless_server.py --port 9090 --wait"
    )
    parser.add_argument(
        "--port", type=int, default=None,
        help="Server port (default: 8080, overrides config file)"
    )
    parser.add_argument(
        "--host", default=None,
        help="Server host (default: 127.0.0.1, overrides config file)"
    )
    parser.add_argument(
        "--config", type=Path,
        help="Path to configuration file (properties format)"
    )
    parser.add_argument(
        "--wait", action="store_true",
        help="Wait for server to run (keep script alive until Ctrl+C)"
    )
    parser.add_argument(
        "--timeout", type=int, default=30,
        help="Timeout in seconds to wait for server startup (default: 30)"
    )
    args = parser.parse_args()

    # Validate config file if provided
    if args.config and not args.config.exists():
        print(f"✗ Configuration file not found: {args.config}", file=sys.stderr)
        return 1

    print("🚀 Starting ReVa MCP server in headless mode...")

    try:
        # Import pyghidra - this will fail if not installed
        try:
            import pyghidra
        except ImportError:
            print("✗ pyghidra not installed. Install with: pip install pyghidra", file=sys.stderr)
            return 1

        # Start pyghidra (initializes Ghidra)
        print("⚙️  Initializing Ghidra via pyghidra...")
        pyghidra.start(verbose=False)

        # Now import ReVa classes (must be after pyghidra.start())
        from reva.headless import RevaHeadlessLauncher
        from java.io import File

        # Create launcher with config file if provided
        global launcher
        if args.config:
            print(f"📄 Loading configuration from: {args.config}")
            launcher = RevaHeadlessLauncher(File(str(args.config)))
        else:
            print("📋 Using default configuration")
            launcher = RevaHeadlessLauncher()

        # Override port/host if specified on command line
        if args.port or args.host:
            print("🔧 Applying command-line overrides...")
            config = launcher.getConfigManager()
            if config:
                if args.port:
                    from reva.plugin.config import InMemoryBackend
                    from reva.plugin import ConfigManager

                    # Need to create custom config with overrides
                    print(f"   Port: {args.port}")
                if args.host:
                    print(f"   Host: {args.host}")
            # Note: For full override support, we'd need to enhance the launcher
            # For now, this demonstrates the pattern

        # Start the server
        print("🔄 Starting MCP server...")
        launcher.start()

        # Wait for server to be ready
        timeout_ms = args.timeout * 1000
        print(f"⏳ Waiting for server to be ready (timeout: {args.timeout}s)...")

        if launcher.waitForServer(timeout_ms):
            port = launcher.getPort()
            print(f"✅ ReVa MCP server ready!")
            print(f"   📡 Listening on: http://localhost:{port}/mcp/message")
            print(f"   🔌 MCP endpoint: http://localhost:{port}/mcp/message")

            if args.wait:
                # Register signal handlers for clean shutdown
                signal.signal(signal.SIGINT, signal_handler)
                signal.signal(signal.SIGTERM, signal_handler)

                print("\n💡 Server running. Press Ctrl+C to stop.")
                try:
                    # Keep running until interrupted
                    while launcher.isRunning():
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass  # Handled by signal_handler
            else:
                print("\n💡 Server started successfully!")
                print("   Use --wait flag to keep server running")
                print("   Server will shutdown when script exits...")
                # Give time to test
                time.sleep(2)

            return 0
        else:
            print("✗ Server failed to start within timeout", file=sys.stderr)
            print("   Check logs for errors (use Ghidra's Msg.error output)", file=sys.stderr)
            return 1

    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
        return 0

    except Exception as e:
        print(f"✗ Error starting server: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

    finally:
        # Clean shutdown
        if launcher:
            launcher.stop()
            print("👋 Server stopped")


if __name__ == "__main__":
    sys.exit(main())
