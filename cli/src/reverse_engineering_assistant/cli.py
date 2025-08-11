#!/usr/bin/env python3
"""
Command line interface for running PyGhidra analysis with ReVa MCP server.
"""

import os
import sys
import time
import signal
from pathlib import Path
from typing import List, Optional, Tuple
import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text
import requests

console = Console()


class PyGhidraReVaRunner:
    """Manages PyGhidra execution with ReVa extension using proper project management."""
    
    def __init__(self, ghidra_path: Optional[str] = None, project_dir: Optional[str] = None, project_name: Optional[str] = None):
        self.ghidra_path = ghidra_path or self._find_ghidra()
        self.project_dir = self._determine_project_dir(project_dir)
        self.project_name = project_name or f"reva_session_{os.getpid()}"
        self.project = None  # GhidraProject instance
        self.programs = {}  # Map of program name to Program object
        self.pyghidra_started = False
        self.cleanup_project = project_dir is None  # Only cleanup if using temp dir
        
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
        
        raise click.ClickException(
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
        console.print(f"[blue]Initializing PyGhidra with Ghidra at: {self.ghidra_path}")
        
        # Set GHIDRA_INSTALL_DIR for PyGhidra
        os.environ["GHIDRA_INSTALL_DIR"] = self.ghidra_path
        
        try:
            import pyghidra
            pyghidra.start()
            self.pyghidra_started = True
            console.print("[green]✓ PyGhidra initialized successfully")
        except Exception as e:
            raise click.ClickException(f"Failed to initialize PyGhidra: {e}")
    
    def open_project(self) -> None:
        """Open or create a Ghidra project."""
        if not self.pyghidra_started:
            raise click.ClickException("PyGhidra must be initialized first")
        
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
                console.print(f"[green]✓ Opened existing project: {self.project_name}")
            else:
                # Create new project
                self.project = GhidraProject.createProject(
                    str(self.project_dir),
                    self.project_name,
                    False  # not temporary
                )
                console.print(f"[green]✓ Created new project: {self.project_name}")
                
        except Exception as e:
            raise click.ClickException(f"Failed to open/create project: {e}")
    
    def import_programs(self, binary_paths: List[str], run_analysis: bool = True) -> None:
        """Import programs into the project."""
        if not self.project:
            raise click.ClickException("Project must be opened first")
        
        from java.io import File
        from ghidra.base.project import GhidraProject
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            for binary_path in binary_paths:
                binary = Path(binary_path)
                if not binary.exists():
                    console.print(f"[red]Warning: Binary not found: {binary_path}")
                    continue
                
                task = progress.add_task(f"Importing {binary.name}...", total=None)
                
                try:
                    # Import the program using GhidraProject
                    binary_file = File(str(binary))
                    program = self.project.importProgram(binary_file)
                    
                    if program:
                        # Store the program
                        self.programs[program.getName()] = program
                        
                        progress.update(task, description=f"✓ Imported {binary.name}")
                        
                        # Analyze if requested
                        if run_analysis:
                            progress.update(task, description=f"Analyzing {binary.name}...")
                            GhidraProject.analyze(program)
                            progress.update(task, description=f"✓ Analyzed {binary.name}")
                        
                        # Log successful import (don't use Msg.info due to Java interop issues)
                        console.print(f"[dim]Imported program: {program.getName()}")
                    else:
                        console.print(f"[red]Failed to import {binary.name}")
                        
                except Exception as e:
                    console.print(f"[red]Error importing {binary.name}: {e}")
                
                progress.remove_task(task)
        
        console.print(f"[green]Successfully imported {len(self.programs)} program(s)")
    
    def initialize_reva(self, port: int = 8080) -> None:
        """Initialize ReVa MCP server with the imported programs."""
        if not self.programs:
            raise click.ClickException("No programs are imported")
        
        console.print(f"[blue]Initializing ReVa MCP server on port {port}...")
        
        try:
            from reva.plugin import ReVaPyGhidraSupport
            
            # Initialize ReVa with all imported programs
            ReVaPyGhidraSupport.initializeWithPrograms(list(self.programs.values()))
            
            # Get the server URL
            server_url = ReVaPyGhidraSupport.getMcpServerUrl()
            
            if server_url:
                console.print(f"[green]✓ ReVa MCP server started at: {server_url}")
                
                # Print session information
                session_info = ReVaPyGhidraSupport.getSessionInfo()
                console.print("\n[dim]Session Information:[/dim]")
                for line in session_info.split('\n'):
                    if line.strip():
                        console.print(f"  {line}")
            else:
                console.print("[yellow]Warning: MCP server URL not available")
                
        except ImportError as e:
            raise click.ClickException(f"ReVa extension not available: {e}")
        except Exception as e:
            raise click.ClickException(f"Failed to initialize ReVa: {e}")
    
    def wait_for_mcp_server(self, port: int, timeout: int = 30) -> None:
        """Wait for MCP server to become available."""
        start_time = time.time()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("Waiting for MCP server to start..."),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Starting...", total=None)
            
            while time.time() - start_time < timeout:
                try:
                    response = requests.get(f"http://localhost:{port}/", timeout=2)
                    # MCP server responds with specific status
                    progress.update(task, description="✓ MCP server is ready!")
                    time.sleep(0.5)  # Brief pause to show success
                    return
                except (requests.exceptions.RequestException, requests.exceptions.ConnectionError):
                    pass
                
                time.sleep(1)
            
            console.print(f"[yellow]Note: MCP server may still be starting up...")
    
    def display_ready_message(self, port: int) -> None:
        """Display the server ready message."""
        panel = Panel(
            Text.assemble(
                ("MCP Server Ready! 🚀\n\n", "bold green"),
                (f"Server URL: ", ""),
                (f"http://localhost:{port}", "bold blue"),
                ("\n\nProject: ", ""),
                (f"{self.project_dir / self.project_name}", "dim"),
                ("\n\nPrograms loaded: ", ""),
                (str(len(self.programs)), "bold yellow"),
                ("\n\nConnect your MCP client to start analysis.\n", ""),
                ("Press ", ""), ("Ctrl+C", "bold red"), (" to stop the server.", "")
            ),
            title="ReVa PyGhidra Analysis",
            border_style="green"
        )
        console.print(panel)
    
    def keep_alive(self) -> None:
        """Keep the process alive until interrupted."""
        def signal_handler(signum, frame):
            console.print("\n[yellow]Received interrupt signal. Shutting down gracefully...")
            self.shutdown()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            console.print("\n[dim]Server is running. Press Ctrl+C to stop...[/dim]")
            while True:
                time.sleep(1)
                
                # Check if programs are still valid
                invalid_programs = []
                for name, program in self.programs.items():
                    if program.isClosed():
                        invalid_programs.append(name)
                
                if invalid_programs:
                    console.print(f"[yellow]Warning: {len(invalid_programs)} program(s) have been closed")
                    for name in invalid_programs:
                        del self.programs[name]
                
                if not self.programs:
                    console.print("[red]All programs have been closed. Exiting...")
                    break
                    
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted. Shutting down...")
            self.shutdown()
    
    def shutdown(self) -> None:
        """Shutdown PyGhidra and cleanup resources."""
        console.print("[blue]Shutting down...")
        
        try:
            from reva.plugin import ReVaPyGhidraSupport
            
            # Cleanup ReVa
            console.print("[blue]Cleaning up ReVa resources...")
            ReVaPyGhidraSupport.cleanup()
            
        except Exception as e:
            console.print(f"[yellow]Warning during ReVa cleanup: {e}")
        
        # Close the project (this handles closing all programs)
        if self.project:
            try:
                console.print("[blue]Closing project...")
                self.project.close()
                console.print("[green]✓ Project closed")
            except Exception as e:
                console.print(f"[yellow]Warning closing project: {e}")
        
        # Clear program references
        self.programs.clear()
        
        # Clean up project directory if it's a temp directory
        if self.cleanup_project and self.project_dir.exists():
            try:
                import shutil
                console.print(f"[blue]Cleaning up temporary project directory: {self.project_dir}")
                shutil.rmtree(self.project_dir)
                console.print("[green]✓ Temporary project directory removed")
            except Exception as e:
                console.print(f"[yellow]Warning: Could not clean up project directory: {e}")


@click.command()
@click.argument('binaries', nargs=-1, required=True, type=click.Path(exists=True))
@click.option('--ghidra-path', help='Path to Ghidra installation')
@click.option('--project-dir', help='Directory for Ghidra project files (defaults to temp dir, or REVA_PROJECT_TEMP_DIR env var)')
@click.option('--project-name', help='Name for the Ghidra project (defaults to reva_session_<pid>)')
@click.option('--port', default=8080, help='MCP server port (default: 8080)')
@click.option('--no-analysis', is_flag=True, help='Skip auto-analysis phase')
@click.option('--verbose', is_flag=True, help='Enable verbose logging')
def main(
    binaries: Tuple[str, ...],
    ghidra_path: Optional[str],
    project_dir: Optional[str],
    project_name: Optional[str],
    port: int,
    no_analysis: bool,
    verbose: bool
) -> None:
    """
    Run PyGhidra analysis with ReVa MCP server.
    
    BINARIES: One or more binary files to analyze
    
    Examples:
    
      reva malware.exe
      
      reva --verbose lib1.so lib2.so
      
      reva --ghidra-path /opt/ghidra --port 9090 binary.elf
    """
    if verbose:
        console.print("[dim]Verbose logging enabled")
        # Enable Ghidra logging
        os.environ["PYGHIDRA_DEBUG"] = "1"
    
    console.print(f"[bold green]ReVa PyGhidra Analysis Tool")
    console.print(f"[dim]Analyzing {len(binaries)} binary(ies)")
    
    runner = None
    try:
        # Initialize runner
        runner = PyGhidraReVaRunner(ghidra_path, project_dir, project_name)
        console.print(f"[blue]Using Ghidra at: {runner.ghidra_path}")
        
        # Initialize PyGhidra
        runner.initialize_pyghidra()
        
        # Open or create project
        runner.open_project()
        
        # Import programs
        runner.import_programs(list(binaries), run_analysis=not no_analysis)
        
        if not runner.programs:
            console.print("[red]No programs were successfully imported. Exiting.")
            return
        
        # Initialize ReVa MCP server
        runner.initialize_reva(port)
        
        # Wait for MCP server to be ready
        runner.wait_for_mcp_server(port)
        
        # Display ready message
        runner.display_ready_message(port)
        
        # Keep alive until interrupted
        runner.keep_alive()
        
    except click.ClickException:
        raise  # Re-raise click exceptions
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user")
    except Exception as e:
        console.print(f"[red]Error: {e}")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)
    finally:
        if runner:
            runner.shutdown()


if __name__ == '__main__':
    main()