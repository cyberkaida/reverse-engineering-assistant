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
from .stdio_bridge import StdioBridge


class ReVaCLI:
    """Main CLI application."""

    def __init__(self, config_file: Optional[Path] = None, verbose: bool = False):
        """
        Initialize ReVa CLI.

        Args:
            config_file: Optional configuration file path
            verbose: Enable verbose logging
        """
        self.config_file = config_file
        self.verbose = verbose
        self.launcher = None
        self.project_manager = None
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
        """Run the CLI application."""
        try:
            # Setup signal handlers
            self.setup_signal_handlers()

            # Initialize project manager
            print("Initializing project manager...", file=sys.stderr)
            self.project_manager = ProjectManager()

            # Open or create project
            project = self.project_manager.open_project()
            print(f"Project opened: {project.getName()}", file=sys.stderr)

            # Auto-import binaries from current directory
            imported_count = self.project_manager.auto_import_binaries()
            if imported_count > 0:
                print(f"Auto-imported {imported_count} binaries", file=sys.stderr)
            else:
                print("No binaries found to import (you can import them later via MCP tools)", file=sys.stderr)

            # Start ReVa server
            print("Starting ReVa server...", file=sys.stderr)
            self.launcher = ReVaLauncher(
                config_file=self.config_file,
                use_random_port=True
            )
            port = self.launcher.start()

            # Start stdio bridge
            print(f"Starting stdio bridge on port {port}...", file=sys.stderr)
            self.bridge = StdioBridge(port)

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

    # Create and run CLI
    cli = ReVaCLI(config_file=args.config, verbose=args.verbose)

    # Run async event loop
    try:
        asyncio.run(cli.run())
    except KeyboardInterrupt:
        print("\nShutdown complete", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
