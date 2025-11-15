"""
Unit tests for CLI ProjectManager.

Tests the project management functionality including:
- .reva/projects/ directory creation
- Project name sanitization
- Binary discovery and auto-import
- Project lifecycle management

These are unit tests that don't require real Ghidra integration.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Mark all tests in this file as CLI unit tests
pytestmark = [pytest.mark.cli, pytest.mark.unit]


class TestProjectManagerInit:
    """Test ProjectManager initialization and directory creation."""

    def test_creates_reva_directory_in_cwd(self, isolated_workspace):
        """ProjectManager creates .reva/projects/ on first use (lazy initialization)"""
        from reva_cli.project_manager import ProjectManager

        pm = ProjectManager()

        # Should NOT create directory on init (lazy initialization)
        assert not (isolated_workspace / ".reva").exists()

        # Manually trigger initialization (normally done by import_binary)
        pm.projects_dir.mkdir(parents=True, exist_ok=True)

        # Now directory should exist
        assert (isolated_workspace / ".reva").exists()
        assert (isolated_workspace / ".reva" / "projects").exists()
        assert (isolated_workspace / ".reva" / "projects").is_dir()

    def test_accepts_custom_projects_dir(self, tmp_path):
        """ProjectManager accepts custom project directory (lazy initialization)"""
        from reva_cli.project_manager import ProjectManager

        custom_dir = tmp_path / "custom_projects"
        pm = ProjectManager(projects_dir=custom_dir)

        # Should NOT create directory on init (lazy initialization)
        assert not custom_dir.exists()
        assert pm.projects_dir == custom_dir

        # Manually trigger directory creation
        pm.projects_dir.mkdir(parents=True, exist_ok=True)

        # Now directory should exist
        assert custom_dir.exists()
        assert custom_dir.is_dir()


class TestProjectNaming:
    """Test project name generation and sanitization."""

    def test_project_name_from_cwd(self, isolated_workspace, monkeypatch):
        """Project name is derived from current directory name"""
        from reva_cli.project_manager import ProjectManager

        # Create a named directory
        project_dir = isolated_workspace / "my_awesome_project"
        project_dir.mkdir()
        monkeypatch.chdir(project_dir)

        pm = ProjectManager()
        name = pm.get_project_name()

        assert name == "my_awesome_project"

    def test_sanitizes_special_characters(self, isolated_workspace, monkeypatch):
        """Special characters in directory name are sanitized"""
        from reva_cli.project_manager import ProjectManager

        # Create directory with special chars
        project_dir = isolated_workspace / "my-project!@#$%"
        project_dir.mkdir()
        monkeypatch.chdir(project_dir)

        pm = ProjectManager()
        name = pm.get_project_name()

        # Should replace special chars with underscores
        assert all(c.isalnum() or c in "._-" for c in name)
        assert "my" in name and "project" in name

    def test_sanitizes_spaces(self, isolated_workspace, monkeypatch):
        """Spaces in directory name are sanitized"""
        from reva_cli.project_manager import ProjectManager

        project_dir = isolated_workspace / "my cool project"
        project_dir.mkdir()
        monkeypatch.chdir(project_dir)

        pm = ProjectManager()
        name = pm.get_project_name()

        assert " " not in name
        assert "my" in name and "cool" in name

    def test_handles_dot_prefix(self, isolated_workspace, monkeypatch):
        """Directories starting with dot get default name"""
        from reva_cli.project_manager import ProjectManager

        project_dir = isolated_workspace / ".hidden_project"
        project_dir.mkdir()
        monkeypatch.chdir(project_dir)

        pm = ProjectManager()
        name = pm.get_project_name()

        # Should use default name instead
        assert name == "default_project"


class TestProjectManagerCleanup:
    """Test cleanup and resource management."""

    def test_cleanup_without_project(self, isolated_workspace):
        """Cleanup succeeds even without opened project"""
        from reva_cli.project_manager import ProjectManager

        pm = ProjectManager()
        # Should not raise
        pm.cleanup()

    @patch('reva_cli.project_manager.ProjectManager.open_project')
    def test_cleanup_releases_programs(self, mock_open_project, isolated_workspace):
        """Cleanup releases opened programs"""
        from reva_cli.project_manager import ProjectManager

        # Create mock program
        mock_program = Mock()
        mock_program.isClosed.return_value = False

        pm = ProjectManager()
        pm._opened_programs = [mock_program]

        pm.cleanup()

        # Should have called release
        mock_program.release.assert_called_once()

    @patch('reva_cli.project_manager.ProjectManager.open_project')
    def test_cleanup_closes_project(self, mock_open_project, isolated_workspace):
        """Cleanup closes the project"""
        from reva_cli.project_manager import ProjectManager

        mock_project = Mock()

        pm = ProjectManager()
        pm.project = mock_project

        pm.cleanup()

        # Should have called close
        mock_project.close.assert_called_once()

    @patch('reva_cli.project_manager.ProjectManager.open_project')
    def test_cleanup_handles_errors_gracefully(self, mock_open_project, isolated_workspace, capsys):
        """Cleanup continues even if individual cleanup steps fail"""
        from reva_cli.project_manager import ProjectManager

        # Create program that raises on release
        mock_program = Mock()
        mock_program.isClosed.return_value = False
        mock_program.release.side_effect = Exception("Test error")

        pm = ProjectManager()
        pm._opened_programs = [mock_program]

        # Should not raise
        pm.cleanup()

        # Should have printed error to stderr
        captured = capsys.readouterr()
        assert "error" in captured.err.lower() or "Error" in captured.err
