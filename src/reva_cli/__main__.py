#!/usr/bin/env python3
"""
ReVa CLI - Main entry point.

Provides stdio MCP transport for ReVa, enabling integration with Claude CLI.
Usage: claude mcp add ReVa -- mcp-reva [--config PATH] [--verbose]
"""

import sys
import signal
import asyncio
import argparse
from pathlib import Path
from typing import Optional

from .launcher import ReVaLauncher
from .project_manager import ProjectManager
from .stdio_bridge import ReVaStdioBridge


class ReVaCLI:
    """Main CLI application."""

    def __init__(
        self,
        launcher: ReVaLauncher,
        project_manager: ProjectManager,
        server_port: int
    ):
        """
        Initialize ReVa CLI with pre-initialized components.

        Args:
            launcher: Pre-initialized ReVa server launcher
            project_manager: Pre-initialized project manager
            server_port: Port number where ReVa server is running
        """
        self.launcher = launcher
        self.project_manager = project_manager
        self.server_port = server_port
        self.bridge = None
        self.cleanup_done = False

    def setup_signal_handlers(self):
        """Setup signal handlers for clean shutdown."""
        def signal_handler(sig, frame):
            if not self.cleanup_done:
                print(f"\nReceived signal {sig}, shutting down gracefully...", file=sys.stderr)
                self.cleanup()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Handle SIGHUP on Unix systems
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, signal_handler)

    def cleanup(self):
        """Clean up all resources."""
        if self.cleanup_done:
            return

        self.cleanup_done = True
        print("Cleaning up resources...", file=sys.stderr)

        # Stop bridge
        if self.bridge:
            try:
                self.bridge.stop()
            except Exception as e:
                print(f"Error stopping bridge: {e}", file=sys.stderr)

        # Clean up project
        if self.project_manager:
            try:
                self.project_manager.cleanup()
            except Exception as e:
                print(f"Error cleaning up project: {e}", file=sys.stderr)

        # Stop server
        if self.launcher:
            try:
                self.launcher.stop()
            except Exception as e:
                print(f"Error stopping launcher: {e}", file=sys.stderr)

        print("Cleanup complete", file=sys.stderr)

    async def run(self):
        """Run the async stdio bridge (all initialization already done)."""
        try:
            # Setup signal handlers
            self.setup_signal_handlers()

            # Start stdio bridge
            print(f"Starting stdio bridge on port {self.server_port}...", file=sys.stderr)
            self.bridge = ReVaStdioBridge(self.server_port)

            # Run the bridge (this blocks until stopped)
            await self.bridge.run()

        except KeyboardInterrupt:
            print("\nInterrupted by user", file=sys.stderr)
        except Exception as e:
            print(f"Fatal error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            sys.exit(1)
        finally:
            self.cleanup()


def main():
    """Main entry point for mcp-reva command."""
    parser = argparse.ArgumentParser(
        description="ReVa MCP server with stdio transport for Claude CLI integration"
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to ReVa configuration file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 3.0.0"
    )

    args = parser.parse_args()

    # Validate config file if provided
    if args.config and not args.config.exists():
        print(f"Error: Configuration file not found: {args.config}", file=sys.stderr)
        sys.exit(1)

    # =========================================================================
    # BLOCKING INITIALIZATION (before async event loop)
    # =========================================================================
    # All blocking operations happen here to avoid blocking the event loop
    # This ensures the stdio bridge can start immediately when asyncio.run() is called

    try:
        # Initialize PyGhidra (blocking, 3-5 seconds)
        print("Initializing PyGhidra...", file=sys.stderr)
        import pyghidra
        pyghidra.start(verbose=args.verbose)
        print("PyGhidra initialized", file=sys.stderr)

        # Initialize project manager (blocking, <1 second)
        print("Initializing project manager...", file=sys.stderr)
        project_manager = ProjectManager()

        # Open or create project (blocking, 1-3 seconds)
        project = project_manager.open_project()
        print(f"Project opened: {project.getProject().getName()}", file=sys.stderr)
        print("Use MCP tools to import binaries into the project", file=sys.stderr)

        # Start ReVa server (blocking, 4-7 seconds)
        print("Starting ReVa server...", file=sys.stderr)
        launcher = ReVaLauncher(
            config_file=args.config,
            use_random_port=True
        )
        port = launcher.start()
        print(f"ReVa server ready on port {port}", file=sys.stderr)

    except Exception as e:
        print(f"Initialization error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

    # =========================================================================
    # ASYNC EXECUTION (stdio bridge only)
    # =========================================================================
    # Create CLI with pre-initialized components
    cli = ReVaCLI(
        launcher=launcher,
        project_manager=project_manager,
        server_port=port
    )

    # Run async event loop (stdio bridge starts immediately)
    try:
        asyncio.run(cli.run())
    except KeyboardInterrupt:
        print("\nShutdown complete", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
