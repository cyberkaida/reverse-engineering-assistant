#!/usr/bin/env python3
"""
Command line interface for running PyGhidra analysis with ReVa MCP server.
"""

import os
import sys
import time
import signal
import socket
import argparse
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra.base.project import GhidraProject
    from ghidra.program.model.listing import Program
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text
import requests

console = Console()


def find_free_port() -> int:
    """Find a random free port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        port: int = s.getsockname()[1]
        return port


class DummyProgress:
    """Dummy progress context manager for quiet mode."""
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        pass
    
    def add_task(self, *args, **kwargs):
        return None
    
    def update(self, *args, **kwargs):
        pass
    
    def remove_task(self, *args, **kwargs):
        pass


class ReVaSession:
    """A session for reverse engineering analysis using PyGhidra and ReVa MCP server.
    
    Can be used as a context manager for automatic resource management:
    
        with ReVaSession(['binary.exe']) as reva:
            server_url = reva.server_url
            programs = reva.programs
    
    Or manually managed:
    
        reva = ReVaSession(['binary.exe'])
        reva.start()
        # ... use reva.server_url, reva.programs
        reva.shutdown()
    """
    
    def __init__(self, binaries: Optional[List[str]] = None, *, ghidra_path: Optional[str] = None, project_dir: Optional[str] = None, 
                 project_name: Optional[str] = None, port: Optional[int] = None, auto_analyze: bool = False, 
                 quiet: bool = True) -> None:
        """Initialize a ReVa analysis session.
        
        Args:
            binaries: Optional list of binary paths to pre-load (can be None for dynamic loading)
            ghidra_path: Path to Ghidra installation (auto-detected if None)
            project_dir: Project directory (temp if None)
            project_name: Project name (auto-generated if None)
            port: MCP server port (auto-assigned if None)
            auto_analyze: Run Ghidra analysis on import (default: False for lazy analysis)
            quiet: Suppress console output
            
        Raises:
            ValueError: If binary paths are invalid
            FileNotFoundError: If any specified binary file doesn't exist
            RuntimeError: If Ghidra installation cannot be found
        """
        # Validate binaries if provided
        self.binaries = []
        if binaries:
            for binary_path in binaries:
                path = Path(binary_path)
                if not path.exists():
                    raise FileNotFoundError(f"Binary not found: {binary_path}")
                if not path.is_file():
                    raise ValueError(f"Path is not a file: {binary_path}")
                # Basic path traversal protection
                try:
                    resolved = path.resolve(strict=True)
                except (OSError, RuntimeError) as e:
                    raise ValueError(f"Invalid path: {binary_path}: {e}")
            self.binaries = binaries
        self.ghidra_path = ghidra_path or self._find_ghidra()
        self.project_dir = self._determine_project_dir(project_dir)
        self.project_name = project_name or f"reva_session_{os.getpid()}_{int(time.time() * 1000000) % 1000000}"
        self.port = port or find_free_port()
        self.auto_analyze = auto_analyze
        self.quiet = quiet
        
        # State variables
        self.project: Optional['GhidraProject'] = None  # GhidraProject instance
        self.programs: dict[str, 'Program'] = {}  # Map of program name to Program object
        self.pyghidra_started = False
        self.cleanup_project = project_dir is None  # Only cleanup if using temp dir
        self.server_url: Optional[str] = None
        self._started = False
    
    def __enter__(self) -> 'ReVaSession':
        """Enter the context manager and start the ReVa session."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit the context manager and cleanup resources."""
        self.shutdown()
        return None
    
    def start(self) -> None:
        """Start the ReVa session by initializing PyGhidra, importing binaries, and starting the MCP server."""
        if self._started:
            return
        
        try:
            # Initialize PyGhidra
            self.initialize_pyghidra()
            
            # Open or create project
            self.open_project()
            
            # Import programs if any were specified
            if self.binaries:
                self.import_programs(self.binaries, run_analysis=self.auto_analyze)
                
                if not self.programs:
                    raise RuntimeError("No programs were successfully imported")
            # If no binaries provided, start with empty project (programs can be loaded via MCP tools)
            
            # Initialize ReVa MCP server
            self.initialize_reva(self.port)
            
            # Wait for MCP server to be ready
            self.wait_for_mcp_server(self.port)
            
            self._started = True
            
            if not self.quiet:
                self.display_ready_message(self.port)
                
        except Exception:
            # Clean up on failure
            self.shutdown()
            raise
        
    def _find_ghidra(self) -> str:
        """Auto-detect Ghidra installation path."""
        # Check GHIDRA_INSTALL_DIR environment variable first
        if "GHIDRA_INSTALL_DIR" in os.environ:
            ghidra_path = os.environ["GHIDRA_INSTALL_DIR"]
            if Path(ghidra_path).exists():
                return ghidra_path
        
        # Common installation paths
        common_paths = [
            os.path.expanduser("~/.local/opt/ghidra_11.4_PUBLIC"),
            os.path.expanduser("~/.local/opt/ghidra"),
            "/opt/ghidra",
            "/usr/local/ghidra",
            os.path.expanduser("~/ghidra"),
            os.path.expanduser("~/Applications/ghidra"),
            "/Applications/ghidra"
        ]
        
        for path in common_paths:
            if Path(path).exists():
                # Look for support/analyzeHeadless script as a verification
                analyze_script = Path(path) / "support" / "analyzeHeadless"
                if analyze_script.exists():
                    return path
        
        raise RuntimeError(
            "Could not find Ghidra installation. Please specify --ghidra-path or set GHIDRA_INSTALL_DIR"
        )
    
    def _determine_project_dir(self, project_dir: Optional[str]) -> Path:
        """Determine the project directory for analysis databases."""
        if project_dir:
            # Use explicitly provided directory
            path = Path(project_dir)
        elif "REVA_PROJECT_TEMP_DIR" in os.environ:
            # Use environment variable
            path = Path(os.environ["REVA_PROJECT_TEMP_DIR"])
        else:
            # Use temp directory with unique name
            import tempfile
            path = Path(tempfile.gettempdir()) / f"reva_projects_{os.getpid()}"
        
        # Create directory if it doesn't exist
        path.mkdir(parents=True, exist_ok=True)
        return path
    
    def initialize_pyghidra(self) -> None:
        """Initialize PyGhidra with the Ghidra installation."""
        if not self.quiet:
            console.print(f"[blue]Initializing PyGhidra with Ghidra at: {self.ghidra_path}")
        
        # Set GHIDRA_INSTALL_DIR for PyGhidra
        os.environ["GHIDRA_INSTALL_DIR"] = self.ghidra_path
        
        try:
            import pyghidra
            pyghidra.start()
            self.pyghidra_started = True
            if not self.quiet:
                console.print("[green]✓ PyGhidra initialized successfully")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize PyGhidra: {e}")
    
    def open_project(self) -> None:
        """Open or create a Ghidra project."""
        if not self.pyghidra_started:
            raise RuntimeError("PyGhidra must be initialized first")
        
        if not self.quiet:
            console.print(f"[dim]Opening project: {self.project_dir / self.project_name}")
        
        try:
            from ghidra.base.project import GhidraProject
            
            # Check if project exists
            project_path = self.project_dir / f"{self.project_name}.rep"
            
            if project_path.exists():
                # Open existing project
                self.project = GhidraProject.openProject(
                    str(self.project_dir),
                    self.project_name
                )
                if not self.quiet:
                    console.print(f"[green]✓ Opened existing project: {self.project_name}")
            else:
                # Create new project
                self.project = GhidraProject.createProject(
                    str(self.project_dir),
                    self.project_name,
                    False  # not temporary
                )
                if not self.quiet:
                    console.print(f"[green]✓ Created new project: {self.project_name}")
                
        except Exception as e:
            raise RuntimeError(f"Failed to open/create project: {e}")
    
    def import_programs(self, binary_paths: List[str], run_analysis: bool = True) -> None:
        """Import programs into the project."""
        if not self.project:
            raise RuntimeError("Project must be opened first")
        
        from java.io import File
        from ghidra.base.project import GhidraProject
        
        if not self.quiet:
            progress_ctx = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console
            )
        else:
            progress_ctx = None
        
        with progress_ctx if progress_ctx else DummyProgress() as progress:
            
            for binary_path in binary_paths:
                binary = Path(binary_path)
                if not binary.exists():
                    if not self.quiet:
                        console.print(f"[red]Warning: Binary not found: {binary_path}")
                    continue
                
                if not self.quiet:
                    task = progress.add_task(f"Importing {binary.name}...", total=None)
                else:
                    task = None
                
                try:
                    # Import the program using GhidraProject
                    binary_file = File(str(binary))
                    program = self.project.importProgram(binary_file)
                    
                    if program:
                        # Store the program
                        self.programs[program.getName()] = program
                        
                        if not self.quiet and task is not None:
                            progress.update(task, description=f"✓ Imported {binary.name}")
                        
                        # Analyze if requested
                        if run_analysis:
                            if not self.quiet and task is not None:
                                progress.update(task, description=f"Analyzing {binary.name}...")
                            GhidraProject.analyze(program)
                            if not self.quiet and task is not None:
                                progress.update(task, description=f"✓ Analyzed {binary.name}")
                        
                        # Log successful import (don't use Msg.info due to Java interop issues)
                        if not self.quiet:
                            console.print(f"[dim]Imported program: {program.getName()}")
                    else:
                        if not self.quiet:
                            console.print(f"[red]Failed to import {binary.name}")
                        
                except Exception as e:
                    if not self.quiet:
                        console.print(f"[red]Error importing {binary.name}: {e}")
                
                if not self.quiet and task is not None:
                    progress.remove_task(task)
        
        if not self.quiet:
            console.print(f"[green]Successfully imported {len(self.programs)} program(s)")
    
    def initialize_reva(self, port: int = 8080) -> None:
        """Initialize ReVa MCP server with the imported programs."""
        if not self.programs:
            raise RuntimeError("No programs are imported")
        
        if not self.quiet:
            console.print(f"[blue]Initializing ReVa MCP server on port {port}...")
        
        try:
            from reva.plugin import ReVaPyGhidraSupport
            
            # Initialize ReVa with all imported programs
            ReVaPyGhidraSupport.initializeWithPrograms(list(self.programs.values()))
            
            # Get the server URL
            server_url = ReVaPyGhidraSupport.getMcpServerUrl()
            
            if server_url:
                self.server_url = server_url
                if not self.quiet:
                    console.print(f"[green]✓ ReVa MCP server started at: {server_url}")
                    
                    # Print session information
                    session_info = ReVaPyGhidraSupport.getSessionInfo()
                    console.print("\n[dim]Session Information:[/dim]")
                    for line in session_info.split('\n'):
                        if line.strip():
                            console.print(f"  {line}")
            else:
                if not self.quiet:
                    console.print("[yellow]Warning: MCP server URL not available")
                
        except ImportError as e:
            raise RuntimeError(f"ReVa extension not available: {e}")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize ReVa: {e}")
    
    def wait_for_mcp_server(self, port: int, timeout: int = 30) -> None:
        """Wait for MCP server to become available."""
        start_time = time.time()
        
        if not self.quiet:
            progress_ctx = Progress(
                SpinnerColumn(),
                TextColumn("Waiting for MCP server to start..."),
                TimeElapsedColumn(),
                console=console
            )
        else:
            progress_ctx = DummyProgress()
        
        with progress_ctx as progress:
            task = progress.add_task("Starting...", total=None) if not self.quiet else None
            
            while time.time() - start_time < timeout:
                try:
                    response = requests.get(f"http://localhost:{port}/", timeout=2)
                    # MCP server responds with specific status
                    if not self.quiet and task is not None:
                        progress.update(task, description="✓ MCP server is ready!")
                    time.sleep(0.5)  # Brief pause to show success
                    return
                except (requests.exceptions.RequestException, requests.exceptions.ConnectionError):
                    pass
                
                time.sleep(1)
            
            if not self.quiet:
                console.print(f"[yellow]Note: MCP server may still be starting up...")
    
    def display_ready_message(self, port: int) -> None:
        """Display the server ready message."""
        panel = Panel(
            Text.assemble(
                ("MCP Server Ready! 🚀\n\n", "bold green"),
                ("Transport Type: ", ""),
                ("HTTP", "bold cyan"),
                ("\nServer URL: ", ""),
                (f"http://localhost:{port}/mcp/message", "bold blue"),
                ("\n\nProject: ", ""),
                (f"{self.project_dir / self.project_name}", "dim"),
                ("\nPrograms loaded: ", ""),
                (str(len(self.programs)), "bold yellow"),
                ("\n\nConnect your MCP client to start analysis.\n", ""),
                ("Press ", ""), ("Ctrl+C", "bold red"), (" to stop the server.", "")
            ),
            title="ReVa PyGhidra Analysis",
            border_style="green"
        )
        if not self.quiet:
            console.print(panel)
    
    def keep_alive(self) -> None:
        """Keep the process alive until interrupted."""
        def signal_handler(signum: int, frame: object) -> None:
            if not self.quiet:
                console.print("\n[yellow]Received interrupt signal. Shutting down gracefully...")
            self.shutdown()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            if not self.quiet:
                console.print("\n[dim]Server is running. Press Ctrl+C to stop...[/dim]")
            while True:
                time.sleep(1)
                
                # Check if programs are still valid
                invalid_programs = []
                for name, program in self.programs.items():
                    if program.isClosed():
                        invalid_programs.append(name)
                
                if invalid_programs:
                    if not self.quiet:
                        console.print(f"[yellow]Warning: {len(invalid_programs)} program(s) have been closed")
                    for name in invalid_programs:
                        del self.programs[name]
                
                if not self.programs:
                    if not self.quiet:
                        console.print("[red]All programs have been closed. Exiting...")
                    break
                    
        except KeyboardInterrupt:
            if not self.quiet:
                console.print("\n[yellow]Interrupted. Shutting down...")
            self.shutdown()
    
    def shutdown(self) -> None:
        """Shutdown PyGhidra and cleanup resources.
        
        This method is defensive and will attempt to clean up all resources
        even if some operations fail. Safe to call multiple times.
        """
        # Check if we have the _started attribute (defensive against partial initialization)
        if not hasattr(self, '_started'):
            return
        
        if not self._started:
            return
        
        # Use getattr for defensive access to attributes that might not exist
        quiet = getattr(self, 'quiet', False)
        
        if not quiet:
            console.print("[blue]Shutting down...")
        
        # Track if any cleanup was successful
        cleanup_performed = False
        
        # Cleanup ReVa MCP server
        try:
            from reva.plugin import ReVaPyGhidraSupport
            
            if not quiet:
                console.print("[blue]Cleaning up ReVa resources...")
            ReVaPyGhidraSupport.cleanup()
            cleanup_performed = True
            
        except ImportError:
            # ReVa plugin not available (might not be in PyGhidra context)
            pass
        except Exception as e:
            if not quiet:
                console.print(f"[yellow]Warning during ReVa cleanup: {e}")
        
        # Close the project (this handles closing all programs)
        project = getattr(self, 'project', None)
        if project:
            try:
                if not quiet:
                    console.print("[blue]Closing project...")
                project.close()
                self.project = None  # Clear reference after closing
                cleanup_performed = True
                if not quiet:
                    console.print("[green]✓ Project closed")
            except Exception as e:
                if not quiet:
                    console.print(f"[yellow]Warning closing project: {e}")
        
        # Clear program references
        if hasattr(self, 'programs'):
            try:
                self.programs.clear()
                cleanup_performed = True
            except Exception:
                pass  # Ignore errors clearing dict
        
        # Clean up project directory if it's a temp directory
        cleanup_project = getattr(self, 'cleanup_project', False)
        project_dir = getattr(self, 'project_dir', None)
        
        if cleanup_project and project_dir and project_dir.exists():
            try:
                import shutil
                if not quiet:
                    console.print(f"[blue]Cleaning up temporary project directory: {project_dir}")
                shutil.rmtree(project_dir)
                cleanup_performed = True
                if not quiet:
                    console.print("[green]✓ Temporary project directory removed")
            except PermissionError as e:
                if not quiet:
                    console.print(f"[yellow]Warning: Permission denied cleaning project directory: {e}")
            except Exception as e:
                if not quiet:
                    console.print(f"[yellow]Warning: Could not clean up project directory: {e}")
        
        # Mark session as no longer started only if we did some cleanup
        if cleanup_performed:
            self._started = False


def main() -> None:
    """
    Run PyGhidra analysis with ReVa MCP server.
    
    Examples:
    
      reva malware.exe
      
      reva --verbose lib1.so lib2.so
      
      reva --ghidra-path /opt/ghidra --port 9090 binary.elf
    """
    parser = argparse.ArgumentParser(
        description='Run PyGhidra analysis with ReVa MCP server',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('binaries', nargs='*', help='Binary files to pre-load (optional - binaries can be loaded dynamically via MCP tools)')
    parser.add_argument('--ghidra-path', help='Path to Ghidra installation')
    parser.add_argument('--project-dir', help='Directory for Ghidra project files (defaults to temp dir, or REVA_PROJECT_TEMP_DIR env var)')
    parser.add_argument('--project-name', help='Name for the Ghidra project (defaults to reva_session_<pid>)')
    parser.add_argument('--port', type=int, default=8080, help='MCP server port (default: 8080)')
    parser.add_argument('--auto-analyze', action='store_true', help='Run analysis on all files upfront (default: lazy analysis)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        console.print("[dim]Verbose logging enabled")
        # Enable Ghidra logging
        os.environ["PYGHIDRA_DEBUG"] = "1"
    
    console.print(f"[bold green]ReVa PyGhidra Analysis Tool")
    if args.binaries:
        console.print(f"[dim]Pre-loading {len(args.binaries)} binary(ies)")
    else:
        console.print(f"[dim]Starting with empty project - binaries can be loaded via MCP tools")
    
    # Show analysis mode
    if args.auto_analyze:
        console.print(f"[dim]Analysis: Upfront analysis enabled")
    else:
        console.print(f"[dim]Analysis: Lazy analysis (use analyze-program MCP tool when needed)")
    
    session = None
    try:
        # Initialize session
        session = ReVaSession(
            binaries=list(args.binaries) if args.binaries else None,
            ghidra_path=args.ghidra_path,
            project_dir=args.project_dir,
            project_name=args.project_name,
            port=args.port,
            auto_analyze=args.auto_analyze,
            quiet=False  # CLI users expect output
        )
        console.print(f"[blue]Using Ghidra at: {session.ghidra_path}")
        
        # Start the session
        session.start()
        
        # Keep alive until interrupted
        session.keep_alive()
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user")
    except Exception as e:
        console.print(f"[red]Error: {e}")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)
    finally:
        if session:
            session.shutdown()


if __name__ == '__main__':
    main()