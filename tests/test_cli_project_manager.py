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
        """ProjectManager creates .reva/projects/ in current directory"""
        from src.reva_cli.project_manager import ProjectManager

        pm = ProjectManager()

        # Should create .reva/projects/ in current directory
        assert (isolated_workspace / ".reva").exists()
        assert (isolated_workspace / ".reva" / "projects").exists()
        assert (isolated_workspace / ".reva" / "projects").is_dir()

    def test_accepts_custom_projects_dir(self, tmp_path):
        """ProjectManager accepts custom project directory"""
        from src.reva_cli.project_manager import ProjectManager

        custom_dir = tmp_path / "custom_projects"
        pm = ProjectManager(projects_dir=custom_dir)

        assert custom_dir.exists()
        assert custom_dir.is_dir()
        assert pm.projects_dir == custom_dir


class TestProjectNaming:
    """Test project name generation and sanitization."""

    def test_project_name_from_cwd(self, isolated_workspace, monkeypatch):
        """Project name is derived from current directory name"""
        from src.reva_cli.project_manager import ProjectManager

        # Create a named directory
        project_dir = isolated_workspace / "my_awesome_project"
        project_dir.mkdir()
        monkeypatch.chdir(project_dir)

        pm = ProjectManager()
        name = pm.get_project_name()

        assert name == "my_awesome_project"

    def test_sanitizes_special_characters(self, isolated_workspace, monkeypatch):
        """Special characters in directory name are sanitized"""
        from src.reva_cli.project_manager import ProjectManager

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
        from src.reva_cli.project_manager import ProjectManager

        project_dir = isolated_workspace / "my cool project"
        project_dir.mkdir()
        monkeypatch.chdir(project_dir)

        pm = ProjectManager()
        name = pm.get_project_name()

        assert " " not in name
        assert "my" in name and "cool" in name

    def test_handles_dot_prefix(self, isolated_workspace, monkeypatch):
        """Directories starting with dot get default name"""
        from src.reva_cli.project_manager import ProjectManager

        project_dir = isolated_workspace / ".hidden_project"
        project_dir.mkdir()
        monkeypatch.chdir(project_dir)

        pm = ProjectManager()
        name = pm.get_project_name()

        # Should use default name instead
        assert name == "default_project"


class TestBinaryDiscovery:
    """Test binary file discovery in current directory."""

    def test_finds_exe_files(self, isolated_workspace):
        """Finds .exe files in current directory"""
        from src.reva_cli.project_manager import ProjectManager

        # Create test files
        (isolated_workspace / "program.exe").touch()
        (isolated_workspace / "other.txt").touch()

        pm = ProjectManager()
        binaries = pm.find_binaries_in_cwd()

        assert len(binaries) == 1
        assert binaries[0].name == "program.exe"

    def test_finds_elf_files(self, isolated_workspace):
        """Finds .elf files in current directory"""
        from src.reva_cli.project_manager import ProjectManager

        (isolated_workspace / "binary.elf").touch()
        (isolated_workspace / "readme.md").touch()

        pm = ProjectManager()
        binaries = pm.find_binaries_in_cwd()

        assert len(binaries) == 1
        assert binaries[0].name == "binary.elf"

    def test_finds_various_extensions(self, isolated_workspace):
        """Finds binaries with various extensions"""
        from src.reva_cli.project_manager import ProjectManager

        extensions = [".exe", ".dll", ".so", ".dylib", ".bin", ".img", ".apk", ".dex", ".jar"]
        for ext in extensions:
            (isolated_workspace / f"file{ext}").touch()

        pm = ProjectManager()
        binaries = pm.find_binaries_in_cwd()

        assert len(binaries) == len(extensions)

    def test_finds_executable_without_extension(self, isolated_workspace):
        """Finds executable files without extension (Unix +x)"""
        from src.reva_cli.project_manager import ProjectManager

        # Create executable file
        exec_file = isolated_workspace / "my_program"
        exec_file.touch()
        exec_file.chmod(0o755)  # Make executable

        # Create non-executable file
        normal_file = isolated_workspace / "readme"
        normal_file.touch()

        pm = ProjectManager()
        binaries = pm.find_binaries_in_cwd()

        # Should find the executable
        assert any(b.name == "my_program" for b in binaries)
        # Should not find the normal file
        assert not any(b.name == "readme" for b in binaries)

    def test_empty_directory_finds_nothing(self, isolated_workspace):
        """Empty directory returns empty list"""
        from src.reva_cli.project_manager import ProjectManager

        pm = ProjectManager()
        binaries = pm.find_binaries_in_cwd()

        assert binaries == []

    def test_ignores_directories(self, isolated_workspace):
        """Ignores directories even if they match extensions"""
        from src.reva_cli.project_manager import ProjectManager

        # Create a directory with .exe name (weird but possible)
        (isolated_workspace / "folder.exe").mkdir()
        # Create a real file
        (isolated_workspace / "real.exe").touch()

        pm = ProjectManager()
        binaries = pm.find_binaries_in_cwd()

        assert len(binaries) == 1
        assert binaries[0].name == "real.exe"


class TestProjectManagerCleanup:
    """Test cleanup and resource management."""

    def test_cleanup_without_project(self, isolated_workspace):
        """Cleanup succeeds even without opened project"""
        from src.reva_cli.project_manager import ProjectManager

        pm = ProjectManager()
        # Should not raise
        pm.cleanup()

    @patch('src.reva_cli.project_manager.ProjectManager.open_project')
    def test_cleanup_releases_programs(self, mock_open_project, isolated_workspace):
        """Cleanup releases opened programs"""
        from src.reva_cli.project_manager import ProjectManager

        # Create mock program
        mock_program = Mock()
        mock_program.isClosed.return_value = False

        pm = ProjectManager()
        pm._opened_programs = [mock_program]

        pm.cleanup()

        # Should have called release
        mock_program.release.assert_called_once()

    @patch('src.reva_cli.project_manager.ProjectManager.open_project')
    def test_cleanup_closes_project(self, mock_open_project, isolated_workspace):
        """Cleanup closes the project"""
        from src.reva_cli.project_manager import ProjectManager

        mock_project = Mock()

        pm = ProjectManager()
        pm.project = mock_project

        pm.cleanup()

        # Should have called close
        mock_project.close.assert_called_once()

    @patch('src.reva_cli.project_manager.ProjectManager.open_project')
    def test_cleanup_handles_errors_gracefully(self, mock_open_project, isolated_workspace, capsys):
        """Cleanup continues even if individual cleanup steps fail"""
        from src.reva_cli.project_manager import ProjectManager

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
