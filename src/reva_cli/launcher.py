"""
Java ReVa launcher wrapper for Python CLI.

Handles PyGhidra initialization, ReVa server startup, and project management.
"""

import sys
from typing import Optional
from pathlib import Path


class ReVaLauncher:
    """Wraps ReVa headless launcher with Python-side project management."""

    def __init__(self, config_file: Optional[Path] = None, use_random_port: bool = True):
        """
        Initialize ReVa launcher.

        Args:
            config_file: Optional configuration file path
            use_random_port: Whether to use random available port (default: True)
        """
        self.config_file = config_file
        self.use_random_port = use_random_port
        self.java_launcher = None
        self.port = None

    def start(self) -> int:
        """
        Start ReVa headless server.

        Returns:
            Server port number

        Raises:
            RuntimeError: If server fails to start
        """
        try:
            # Import ReVa launcher (PyGhidra already initialized by CLI)
            from reva.headless import RevaHeadlessLauncher
            from java.io import File

            # Create launcher with random port
            if self.config_file:
                print(f"Using config file: {self.config_file}", file=sys.stderr)
                java_config_file = File(str(self.config_file))
                self.java_launcher = RevaHeadlessLauncher(java_config_file, self.use_random_port)
            else:
                print("Using default configuration", file=sys.stderr)
                # Use constructor with useRandomPort parameter
                self.java_launcher = RevaHeadlessLauncher(None, True, self.use_random_port)

            # Start server
            print("Starting ReVa MCP server...", file=sys.stderr)
            self.java_launcher.start()

            # Wait for server to be ready
            if self.java_launcher.waitForServer(30000):
                self.port = self.java_launcher.getPort()
                print(f"ReVa server ready on port {self.port}", file=sys.stderr)
                return self.port
            else:
                raise RuntimeError("Server failed to start within timeout")

        except Exception as e:
            print(f"Error starting ReVa server: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            raise

    def get_port(self) -> Optional[int]:
        """
        Get the server port.

        Returns:
            Server port number, or None if not started
        """
        return self.port

    def is_running(self) -> bool:
        """
        Check if server is running.

        Returns:
            True if server is running
        """
        if self.java_launcher:
            return self.java_launcher.isRunning()
        return False

    def stop(self):
        """Stop the ReVa server and cleanup."""
        if self.java_launcher:
            print("Stopping ReVa server...", file=sys.stderr)
            try:
                self.java_launcher.stop()
            except Exception as e:
                print(f"Error stopping server: {e}", file=sys.stderr)
            finally:
                self.java_launcher = None
                self.port = None
