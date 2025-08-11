"""Tests for the CLI module."""

import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from click.testing import CliRunner

from reverse_engineering_assistant.cli import PyGhidraReVaRunner, main


class TestPyGhidraReVaRunner:
    """Tests for PyGhidraReVaRunner class."""
    
    def test_init_with_custom_ghidra_path(self):
        """Test initialization with custom Ghidra path."""
        runner = PyGhidraReVaRunner(ghidra_path="/custom/ghidra")
        assert runner.ghidra_path == "/custom/ghidra"
        assert runner.programs == []
        assert runner.pyghidra_started is False
    
    @patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": "/env/ghidra"})
    @patch("pathlib.Path.exists")
    def test_find_ghidra_from_env(self, mock_exists):
        """Test finding Ghidra from environment variable."""
        mock_exists.return_value = True
        
        runner = PyGhidraReVaRunner()
        assert runner.ghidra_path == "/env/ghidra"
    
    def test_find_ghidra_from_common_paths(self):
        """Test finding Ghidra from common installation paths."""
        def exists_side_effect(self):
            path_str = str(self)
            return path_str in ["/opt/ghidra", "/opt/ghidra/support/analyzeHeadless"]
        
        with patch.dict(os.environ, {}, clear=True):  # Clear GHIDRA_INSTALL_DIR
            with patch.object(Path, "exists", exists_side_effect):
                runner = PyGhidraReVaRunner()
                assert runner.ghidra_path == "/opt/ghidra"
    
    @patch("pathlib.Path.exists")
    def test_find_ghidra_not_found(self, mock_exists):
        """Test exception when Ghidra is not found."""
        mock_exists.return_value = False
        
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(Exception):  # Should raise ClickException
                PyGhidraReVaRunner()
    
    @patch("pyghidra.start")
    def test_initialize_pyghidra(self, mock_start):
        """Test PyGhidra initialization."""
        runner = PyGhidraReVaRunner(ghidra_path="/test/ghidra")
        
        # Mock the pyghidra module
        with patch.dict("sys.modules", {"pyghidra": Mock(start=mock_start)}):
            runner.initialize_pyghidra()
            
            assert runner.pyghidra_started is True
            assert os.environ["GHIDRA_INSTALL_DIR"] == "/test/ghidra"
            mock_start.assert_called_once()
    
    def test_open_programs_without_pyghidra_initialized(self):
        """Test that open_programs requires PyGhidra to be initialized."""
        runner = PyGhidraReVaRunner(ghidra_path="/test/ghidra")
        
        with pytest.raises(Exception):  # Should raise ClickException
            runner.open_programs(["/path/to/binary"])
    
    @patch("pyghidra.open_program")
    @patch("pyghidra.start")
    def test_open_programs_success(self, mock_start, mock_open_program):
        """Test successful program opening."""
        runner = PyGhidraReVaRunner(ghidra_path="/test/ghidra")
        
        # Create a mock program
        mock_program = Mock()
        mock_program.isClosed.return_value = False
        mock_program.getName.return_value = "test.exe"
        mock_open_program.return_value.__enter__.return_value = mock_program
        mock_open_program.return_value.__exit__.return_value = None
        
        # Initialize PyGhidra first
        with patch.dict("sys.modules", {"pyghidra": Mock(start=mock_start, open_program=mock_open_program)}):
            runner.pyghidra_started = True
            
            # Create a temporary file to simulate binary
            with tempfile.NamedTemporaryFile(suffix=".exe") as temp_file:
                runner.open_programs([temp_file.name], run_analysis=False)
                
                assert len(runner.programs) == 1
                mock_program.addConsumer.assert_called_once_with(runner)
    
    def test_initialize_reva_no_programs(self):
        """Test that initialize_reva requires programs to be open."""
        runner = PyGhidraReVaRunner(ghidra_path="/test/ghidra")
        
        with pytest.raises(Exception):  # Should raise ClickException
            runner.initialize_reva()
    
    @patch("reva.plugin.ReVaPyGhidraSupport")
    def test_initialize_reva_success(self, mock_reva_support):
        """Test successful ReVa initialization."""
        runner = PyGhidraReVaRunner(ghidra_path="/test/ghidra")
        
        # Add a mock program
        mock_program = Mock()
        runner.programs = [mock_program]
        
        # Setup mock ReVa support
        mock_reva_support.getMcpServerUrl.return_value = "http://localhost:8080"
        mock_reva_support.getSessionInfo.return_value = "Session info"
        
        with patch.dict("sys.modules", {"reva.plugin": Mock(ReVaPyGhidraSupport=mock_reva_support)}):
            runner.initialize_reva(port=8080)
            
            mock_reva_support.initializeWithPrograms.assert_called_once_with([mock_program])
    
    @patch("pyghidra.shutdown")
    @patch("reva.plugin.ReVaPyGhidraSupport")
    def test_shutdown(self, mock_reva_support, mock_shutdown):
        """Test shutdown method."""
        runner = PyGhidraReVaRunner(ghidra_path="/test/ghidra")
        runner.pyghidra_started = True
        
        # Add a mock program
        mock_program = Mock()
        mock_program.isClosed.return_value = False
        runner.programs = [mock_program]
        
        with patch.dict("sys.modules", {
            "pyghidra": Mock(shutdown=mock_shutdown),
            "reva.plugin": Mock(ReVaPyGhidraSupport=mock_reva_support)
        }):
            runner.shutdown()
            
            mock_reva_support.cleanup.assert_called_once()
            mock_program.removeConsumer.assert_called_once_with(runner)
            mock_program.release.assert_called_once_with(runner)
            mock_shutdown.assert_called_once()


class TestCLICommands:
    """Tests for CLI commands."""
    
    def test_main_command_no_binaries(self):
        """Test main command with no binaries specified."""
        runner = CliRunner()
        result = runner.invoke(main, [])
        
        assert result.exit_code != 0
        assert "Missing argument" in result.output or "Usage:" in result.output
    
    def test_main_command_help(self):
        """Test main command help output."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        
        assert result.exit_code == 0
        assert "Run PyGhidra analysis" in result.output
        assert "--ghidra-path" in result.output
        assert "--port" in result.output
        assert "--no-analysis" in result.output
    
    def test_main_command_nonexistent_binary(self):
        """Test main command with nonexistent binary."""
        runner = CliRunner()
        result = runner.invoke(main, ["/nonexistent/binary.exe"])
        
        assert result.exit_code != 0
        # Should fail because the binary doesn't exist
    
    @patch("reverse_engineering_assistant.cli.PyGhidraReVaRunner")
    def test_main_command_with_options(self, mock_runner_class):
        """Test main command with various options."""
        mock_runner = Mock()
        mock_runner_class.return_value = mock_runner
        mock_runner.ghidra_path = "/test/ghidra"
        mock_runner.programs = [Mock()]  # Simulate successful program opening
        
        runner = CliRunner()
        
        with tempfile.NamedTemporaryFile(suffix=".exe") as temp_binary:
            result = runner.invoke(main, [
                "--ghidra-path", "/custom/ghidra",
                "--port", "9090", 
                "--no-analysis",
                "--verbose",
                temp_binary.name
            ])
            
            # Should create runner with custom ghidra path
            mock_runner_class.assert_called_once_with("/custom/ghidra")
            # Should call initialization methods
            mock_runner.initialize_pyghidra.assert_called_once()
            mock_runner.open_programs.assert_called_once()


class TestIntegration:
    """Integration tests (require more setup)."""
    
    @pytest.mark.skipif(
        not os.environ.get("GHIDRA_INSTALL_DIR"), 
        reason="Requires GHIDRA_INSTALL_DIR environment variable"
    )
    def test_with_real_ghidra_path(self):
        """Test with real Ghidra installation (if available)."""
        ghidra_path = os.environ.get("GHIDRA_INSTALL_DIR")
        
        try:
            runner = PyGhidraReVaRunner(ghidra_path=ghidra_path)
            assert Path(runner.ghidra_path).exists()
            assert (Path(runner.ghidra_path) / "support" / "analyzeHeadless").exists()
        except Exception as e:
            pytest.skip(f"Could not initialize with Ghidra: {e}")


if __name__ == "__main__":
    pytest.main([__file__])