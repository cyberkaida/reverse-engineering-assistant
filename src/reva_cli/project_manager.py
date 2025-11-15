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

        # Don't create directory here - defer until first tool use (lazy initialization)
        self.project = None
        self._opened_programs = []
        self._initialized = False

    def _ensure_initialized(self):
        """
        Ensure the project directory exists and project is opened.

        This implements lazy initialization - the .reva directory and Ghidra project
        are only created when first needed (e.g., when importing a binary).
        """
        if self._initialized:
            return

        # Create projects directory
        self.projects_dir.mkdir(parents=True, exist_ok=True)

        # Open/create the Ghidra project
        self.open_project()

        self._initialized = True

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
            Ghidra Project instance (GhidraProject wrapper)

        Raises:
            ImportError: If Ghidra/PyGhidra not available
        """
        try:
            from ghidra.base.project import GhidraProject
            from ghidra.framework.model import ProjectLocator
        except ImportError as e:
            raise ImportError(
                "Ghidra modules not available. Ensure PyGhidra is installed and Ghidra is initialized."
            ) from e

        project_name, project_path = self.get_or_create_project()

        # Use GhidraProject (PyGhidra's approach) - handles protected constructor properly
        project_locator = ProjectLocator(str(project_path), project_name)

        # Try to open existing project or create new one
        if project_locator.getProjectDir().exists() and project_locator.getMarkerFile().exists():
            print(f"Opening existing project: {project_name}", file=sys.stderr)
            self.project = GhidraProject.openProject(str(project_path), project_name, True)
        else:
            print(f"Creating new project: {project_name} at {project_path}", file=sys.stderr)
            project_path.mkdir(parents=True, exist_ok=True)
            self.project = GhidraProject.createProject(str(project_path), project_name, False)

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
        # Ensure project is initialized (lazy initialization on first use)
        self._ensure_initialized()

        if not binary_path.exists():
            print(f"Warning: Binary not found: {binary_path}", file=sys.stderr)
            return None

        if program_name is None:
            program_name = binary_path.name

        try:
            print(f"Importing binary: {binary_path} as {program_name}", file=sys.stderr)

            # Use GhidraProject's importProgram method (auto-detects language/loader)
            program = self.project.importProgram(str(binary_path))

            if program:
                # Save with custom name if specified
                if program_name != binary_path.name:
                    self.project.saveAs(program, "/", program_name, True)

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
