"""
Java ReVa launcher wrapper for Python CLI.

Handles PyGhidra initialization, ReVa server startup, and project management.
"""

import sys
from typing import Optional
from pathlib import Path


class ReVaLauncher:
    """Wraps ReVa headless launcher with Python-side project management.

    Note: Stdio mode uses ephemeral projects in temp directories.
    Projects are created per-session and cleaned up on exit.
    """

    def __init__(self, config_file: Optional[Path] = None, use_random_port: bool = True,
                 api_key: Optional[str] = None):
        """
        Initialize ReVa launcher.

        Args:
            config_file: Optional configuration file path
            use_random_port: Whether to use random available port (default: True)
            api_key: Optional API key; when set, the Java server enables API key
                auth with this exact key.
        """
        self.config_file = config_file
        self.use_random_port = use_random_port
        self.api_key = api_key
        self.java_launcher = None
        self.port = None
        self.temp_project_dir = None

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
            from .project_manager import ProjectManager
            import tempfile

            # Stdio mode: ephemeral projects in temp directory (session-scoped, auto-cleanup)
            # Keeps working directory clean - no .reva creation in cwd
            self.temp_project_dir = Path(tempfile.mkdtemp(prefix="reva_project_"))
            project_manager = ProjectManager()
            project_name = project_manager.get_project_name()

            # Use temp directory for the project (not .reva/projects)
            projects_dir = self.temp_project_dir

            # Convert to Java File objects
            java_project_location = File(str(projects_dir))

            print(f"Project location: {projects_dir}/{project_name}", file=sys.stderr)

            # Create launcher with project parameters + optional API key.
            # Always use the full 6-arg constructor so the api_key is threaded
            # through regardless of whether a config file was supplied.
            if self.config_file:
                print(f"Using config file: {self.config_file}", file=sys.stderr)
                java_config_file = File(str(self.config_file))
            else:
                print("Using default configuration", file=sys.stderr)
                java_config_file = None

            self.java_launcher = RevaHeadlessLauncher(
                java_config_file,
                True,                 # autoInitializeGhidra
                self.use_random_port,
                java_project_location,
                project_name,
                self.api_key          # str or None (JPype maps None -> Java null)
            )

            # Start server
            print("Starting ReVa MCP server...", file=sys.stderr)
            self.java_launcher.start()

            # Wait for server to be ready. 60s rather than 30s because under
            # full-suite load the Jetty bind + initial servlet wiring can
            # exceed 30s on contended hosts (observed flake in CI-like runs).
            startup_timeout_ms = 60000
            if self.java_launcher.waitForServer(startup_timeout_ms):
                self.port = self.java_launcher.getPort()
                print(f"ReVa server ready on port {self.port}", file=sys.stderr)
                return self.port
            else:
                raise RuntimeError(
                    f"Server failed to start within {startup_timeout_ms / 1000:.0f}s"
                )

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

        # Clean up temporary project directory
        if self.temp_project_dir and self.temp_project_dir.exists():
            try:
                import shutil
                shutil.rmtree(self.temp_project_dir)
                print(f"Cleaned up temporary project directory: {self.temp_project_dir}", file=sys.stderr)
            except Exception as e:
                print(f"Error cleaning up temporary directory: {e}", file=sys.stderr)
            finally:
                self.temp_project_dir = None
