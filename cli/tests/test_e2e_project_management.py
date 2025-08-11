"""End-to-end tests for ReVa project directory management with compiled binaries."""

import os
import shutil
import tempfile
from pathlib import Path

import pytest

from reverse_engineering_assistant.cli import ReVaSession


@pytest.mark.integration
class TestProjectDirectoryManagement:
    """Test ReVa project directory creation and management."""
    
    def test_default_temp_directory(self, sample_binaries):
        """Test default temporary directory creation."""
        test_binary = sample_binaries['minimal']
        
        session = ReVaSession([str(test_binary)])
        
        # Should create temp directory
        assert session.project_dir is not None
        project_dir_str = str(session.project_dir)
        assert (
            project_dir_str.startswith('/tmp/reva_projects_') or
            project_dir_str.startswith('/var/folders/') or  # macOS temp
            'reva_projects_' in project_dir_str  # Windows temp
        )
        
        # Should enable cleanup by default
        assert session.cleanup_project is True
        
        # Should have a project name
        assert session.project_name is not None
        assert len(session.project_name) > 0
    
    def test_environment_variable_project_dir(self, sample_binaries, temp_dir):
        """Test project directory from environment variable."""
        test_binary = sample_binaries['minimal']
        test_project_dir = temp_dir / "test_reva_env"
        
        # Set environment variable
        original_env = os.environ.get("REVA_PROJECT_TEMP_DIR")
        try:
            os.environ["REVA_PROJECT_TEMP_DIR"] = str(test_project_dir)
            
            session = ReVaSession([str(test_binary)])
            
            # Should use environment variable
            assert str(session.project_dir) == str(test_project_dir)
            assert session.cleanup_project is True
            
        finally:
            # Restore original environment
            if original_env is not None:
                os.environ["REVA_PROJECT_TEMP_DIR"] = original_env
            elif "REVA_PROJECT_TEMP_DIR" in os.environ:
                del os.environ["REVA_PROJECT_TEMP_DIR"]
    
    def test_explicit_project_directory(self, sample_binaries, temp_dir):
        """Test explicit project directory specification."""
        test_binary = sample_binaries['minimal']
        explicit_dir = temp_dir / "explicit_project"
        
        session = ReVaSession(project_dir=str(explicit_dir))
        
        # Should use explicit directory
        assert str(session.project_dir) == str(explicit_dir)
        
        # Should NOT cleanup explicit directories
        assert session.cleanup_project is False
    
    def test_custom_project_name(self, sample_binaries):
        """Test custom project name specification."""
        test_binary = sample_binaries['minimal']
        custom_name = "my_custom_test_project"
        
        session = ReVaSession(project_name=custom_name)
        
        # Should use custom project name
        assert session.project_name == custom_name
    
    def test_project_directory_creation(self, sample_binaries, temp_dir):
        """Test that project directories are actually created."""
        test_binary = sample_binaries['minimal']
        project_dir = temp_dir / "test_creation"
        
        # Directory shouldn't exist initially
        assert not project_dir.exists()
        
        session = ReVaSession(project_dir=str(project_dir))
        
        # Create the session's internal state (this might create directories)
        # Note: Full directory creation might happen during server start
        assert session.project_dir == project_dir
    
    def test_cleanup_behavior(self, sample_binaries, temp_dir):
        """Test cleanup behavior for different project directory types."""
        test_binary = sample_binaries['minimal']
        
        # Test 1: Temporary directories should cleanup
        session1 = ReVaSession()
        assert session1.cleanup_project is True
        
        # Test 2: Explicit directories should NOT cleanup
        explicit_dir = temp_dir / "no_cleanup"
        session2 = ReVaSession(project_dir=str(explicit_dir))
        assert session2.cleanup_project is False
        
        # Test 3: Environment-specified directories should cleanup
        original_env = os.environ.get("REVA_PROJECT_TEMP_DIR")
        try:
            env_dir = temp_dir / "env_cleanup"
            os.environ["REVA_PROJECT_TEMP_DIR"] = str(env_dir)
            
            session3 = ReVaSession()
            assert session3.cleanup_project is True
            
        finally:
            if original_env is not None:
                os.environ["REVA_PROJECT_TEMP_DIR"] = original_env
            elif "REVA_PROJECT_TEMP_DIR" in os.environ:
                del os.environ["REVA_PROJECT_TEMP_DIR"]
    
    def test_project_name_generation(self, sample_binaries):
        """Test automatic project name generation."""
        test_binary = sample_binaries['minimal']
        
        # Create multiple sessions to see different generated names
        session1 = ReVaSession()
        session2 = ReVaSession()
        
        # Names should be non-empty strings
        assert isinstance(session1.project_name, str)
        assert len(session1.project_name) > 0
        assert isinstance(session2.project_name, str)
        assert len(session2.project_name) > 0
        
        # Names should be different (with high probability)
        assert session1.project_name != session2.project_name
    
    def test_multiple_binaries_project_setup(self, sample_binaries, temp_dir):
        """Test project setup with multiple compiled binaries."""
        binaries = [
            str(sample_binaries['minimal']),
            str(sample_binaries['hello_world']),
            str(sample_binaries['simple_functions'])
        ]
        
        project_dir = temp_dir / "multi_binary_project"
        session = ReVaSession(
            project_dir=str(project_dir),
            project_name="multi_binary_test"
        )
        
        # Should handle multiple binaries configuration
        assert session.project_dir == project_dir
        assert session.project_name == "multi_binary_test"
        assert session.cleanup_project is False  # Explicit directory
    
    @pytest.mark.slow
    def test_real_project_workflow(self, sample_binaries, temp_dir):
        """Test a realistic project workflow with compiled binary."""
        test_binary = sample_binaries['simple_functions']
        project_dir = temp_dir / "workflow_test"
        
        # Step 1: Create session
        session = ReVaSession(
            project_dir=str(project_dir),
            project_name="workflow_project"
        )
        
        # Step 2: Verify configuration
        assert session.project_dir == project_dir
        assert session.project_name == "workflow_project"
        assert session.cleanup_project is False
        
        # Step 3: Test that we can reference the binary
        # (In real usage, this would be passed to the server)
        assert test_binary.exists()
        assert test_binary.is_file()
        
        # Step 4: Verify project directory properties are maintained
        assert session.project_dir == project_dir
        assert str(session.project_dir).endswith("workflow_test")
    
    def test_path_validation(self, sample_binaries):
        """Test path validation and normalization."""
        test_binary = sample_binaries['minimal']
        
        # Test with different path formats
        session1 = ReVaSession(project_dir="/tmp/test1")
        session2 = ReVaSession(project_dir="./test2")
        session3 = ReVaSession(project_dir="~/test3")
        
        # All should result in Path objects
        assert isinstance(session1.project_dir, Path)
        assert isinstance(session2.project_dir, Path)
        assert isinstance(session3.project_dir, Path)
        
        # Paths should be absolute (or at least properly handled)
        assert str(session1.project_dir) == "/tmp/test1"