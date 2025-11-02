"""
Project management for ReVa CLI.

Handles creation and management of Ghidra projects in .reva/projects/
within the current working directory, similar to how .git or .vscode work.
"""

import os
import sys
from pathlib import Path
from typing import Optional, Tuple


class ProjectManager:
    """Manages Ghidra project creation and lifecycle for ReVa CLI."""

    def __init__(self, projects_dir: Optional[Path] = None):
        """
        Initialize project manager.

        Args:
            projects_dir: Custom projects directory, defaults to .reva/projects/ in current directory
        """
        if projects_dir is None:
            self.projects_dir = Path.cwd() / ".reva" / "projects"
        else:
            self.projects_dir = Path(projects_dir)

        self.projects_dir.mkdir(parents=True, exist_ok=True)
        self.project = None
        self._opened_programs = []

    def get_project_name(self) -> str:
        """
        Get project name based on current working directory.

        Returns:
            Project name derived from current directory name
        """
        cwd = Path.cwd()
        # Use current directory name as project name
        project_name = cwd.name

        # Sanitize project name for Ghidra
        # Remove invalid characters and replace with underscores
        sanitized = "".join(c if c.isalnum() or c in "._-" else "_" for c in project_name)

        # Ensure name is not empty
        if not sanitized or sanitized.startswith("."):
            sanitized = "default_project"

        return sanitized

    def get_or_create_project(self) -> Tuple[str, Path]:
        """
        Get or create Ghidra project for current working directory.

        Returns:
            Tuple of (project_name, project_directory_path)
        """
        project_name = self.get_project_name()
        project_path = self.projects_dir / project_name

        # Create project directory if it doesn't exist
        project_path.mkdir(parents=True, exist_ok=True)

        return project_name, project_path

    def open_project(self) -> "Project":
        """
        Open or create Ghidra project using PyGhidra.

        Returns:
            Ghidra Project instance

        Raises:
            ImportError: If Ghidra/PyGhidra not available
        """
        try:
            from ghidra.framework.model import ProjectLocator
            from ghidra.framework.project import DefaultProjectManager
            from ghidra.util.task import TaskMonitor
        except ImportError as e:
            raise ImportError(
                "Ghidra modules not available. Ensure PyGhidra is installed and Ghidra is initialized."
            ) from e

        project_name, project_path = self.get_or_create_project()

        # Create project locator
        project_locator = ProjectLocator(str(project_path), project_name)

        # Get project manager
        project_manager = DefaultProjectManager.getProjectManager()

        # Try to open existing project or create new one
        if project_locator.getProjectDir().exists() and project_locator.getMarkerFile().exists():
            print(f"Opening existing project: {project_name}", file=sys.stderr)
            self.project = project_manager.openProject(project_locator, None, False)
        else:
            print(f"Creating new project: {project_name} at {project_path}", file=sys.stderr)
            self.project = project_manager.createProject(project_locator, None, False)

        return self.project

    def import_binary(self, binary_path: Path, program_name: Optional[str] = None):
        """
        Import a binary file into the opened project.

        Args:
            binary_path: Path to binary file to import
            program_name: Optional custom program name, defaults to binary filename

        Returns:
            Imported Program instance, or None if import fails
        """
        if not self.project:
            raise RuntimeError("No project opened. Call open_project() first.")

        try:
            from ghidra.app.util.opinion import Loader
            from ghidra.app.util.importer import AutoImporter
            from ghidra.util.task import TaskMonitor
            from ghidra.program.model.listing import Program
        except ImportError as e:
            raise ImportError(
                "Ghidra import modules not available"
            ) from e

        if not binary_path.exists():
            print(f"Warning: Binary not found: {binary_path}", file=sys.stderr)
            return None

        if program_name is None:
            program_name = binary_path.name

        try:
            print(f"Importing binary: {binary_path} as {program_name}", file=sys.stderr)

            # Import the binary
            imported_programs = AutoImporter.importByUsingBestGuess(
                str(binary_path),
                self.project.getProjectData().getRootFolder(),
                None,  # Use default loaders
                None,  # No custom loader args
                None,  # No custom loader args
                TaskMonitor.DUMMY
            )

            if imported_programs:
                program = imported_programs[0]
                self._opened_programs.append(program)
                print(f"Successfully imported: {program_name}", file=sys.stderr)
                return program
            else:
                print(f"Failed to import: {binary_path}", file=sys.stderr)
                return None

        except Exception as e:
            print(f"Error importing binary {binary_path}: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            return None

    def find_binaries_in_cwd(self) -> list:
        """
        Find potential binary files in current working directory.

        Returns:
            List of Path objects for potential binaries
        """
        cwd = Path.cwd()
        binaries = []

        # Common binary extensions to look for
        binary_extensions = {
            # Executables
            ".exe", ".dll", ".so", ".dylib", ".elf",
            # Firmware
            ".bin", ".img", ".rom",
            # Mobile
            ".apk", ".dex", ".jar"
        }

        # Look for files with common binary extensions
        for file_path in cwd.iterdir():
            if file_path.is_file():
                # Check extension
                if file_path.suffix.lower() in binary_extensions:
                    binaries.append(file_path)
                # Check if file is executable (Unix-like systems)
                elif os.access(file_path, os.X_OK) and not file_path.suffix:
                    binaries.append(file_path)

        return binaries

    def auto_import_binaries(self) -> int:
        """
        Automatically find and import binaries from current working directory.

        Returns:
            Number of binaries successfully imported
        """
        binaries = self.find_binaries_in_cwd()

        if not binaries:
            print("No binaries found in current directory", file=sys.stderr)
            return 0

        print(f"Found {len(binaries)} potential binaries", file=sys.stderr)
        imported_count = 0

        for binary_path in binaries:
            program = self.import_binary(binary_path)
            if program:
                imported_count += 1

        return imported_count

    def cleanup(self):
        """Clean up opened programs and close project."""
        # Release opened programs
        for program in self._opened_programs:
            try:
                if program and not program.isClosed():
                    program.release(None)
            except Exception as e:
                print(f"Error releasing program: {e}", file=sys.stderr)

        self._opened_programs.clear()

        # Close project
        if self.project:
            try:
                self.project.close()
            except Exception as e:
                print(f"Error closing project: {e}", file=sys.stderr)
            finally:
                self.project = None
