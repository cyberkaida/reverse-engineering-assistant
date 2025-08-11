"""Tests for CLI functionality with ReVaSession."""

import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import argparse

from reverse_engineering_assistant.cli import ReVaSession, main


class TestReVaSessionBasicFunctionality:
    """Tests for ReVaSession basic functionality."""
    
    def test_init_with_binaries(self):
        """Test initialization with binaries."""
        binaries = ['/bin/ls', '/bin/cat']
        session = ReVaSession(binaries)
        assert session.binaries == binaries
        assert session.programs == {}
        assert session.pyghidra_started is False
        assert session._started is False
    
    def test_init_with_custom_ghidra_path(self):
        """Test initialization with custom Ghidra path."""
        session = ReVaSession(['/bin/ls'], ghidra_path="/custom/ghidra")
        assert session.ghidra_path == "/custom/ghidra"
    
    @patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": "/env/ghidra"})
    @patch("pathlib.Path.exists")
    def test_find_ghidra_from_env(self, mock_exists):
        """Test finding Ghidra from environment variable."""
        mock_exists.return_value = True
        
        session = ReVaSession(['/bin/ls'])
        assert session.ghidra_path == "/env/ghidra"
    
    def test_find_ghidra_not_found(self):
        """Test exception when Ghidra is not found."""
        # Need to mock the binary validation first
        with patch('pathlib.Path.exists') as mock_exists:
            # First call checks if binary exists (return True)
            # Subsequent calls check for Ghidra paths (return False)
            mock_exists.side_effect = [True, True, False, False, False, False, False, False, False, False]
            
            with patch('pathlib.Path.is_file') as mock_is_file:
                mock_is_file.return_value = True
                
                with patch.dict(os.environ, {}, clear=True):
                    with pytest.raises(RuntimeError):
                        ReVaSession(['/bin/ls'])
    
    def test_shutdown_when_not_started(self):
        """Test shutdown when session was never started."""
        session = ReVaSession(['/bin/ls'])
        # Should not raise any exception
        session.shutdown()
        assert session._started is False


class TestReVaSessionMockedFunctionality:
    """Tests for ReVaSession with mocked dependencies."""
    
    @patch('reverse_engineering_assistant.cli.ReVaSession.initialize_pyghidra')
    @patch('reverse_engineering_assistant.cli.ReVaSession.open_project')
    @patch('reverse_engineering_assistant.cli.ReVaSession.import_programs')
    @patch('reverse_engineering_assistant.cli.ReVaSession.initialize_reva')
    @patch('reverse_engineering_assistant.cli.ReVaSession.wait_for_mcp_server')
    def test_start_method_calls(self, mock_wait, mock_reva, mock_import, mock_project, mock_pyghidra):
        """Test that start method calls all required methods."""
        session = ReVaSession(['/bin/ls'])
        # Mock programs to avoid "no programs imported" error
        session.programs = {'ls': Mock()}
        
        session.start()
        
        mock_pyghidra.assert_called_once()
        mock_project.assert_called_once()
        mock_import.assert_called_once_with(['/bin/ls'], run_analysis=False)
        mock_reva.assert_called_once()
        mock_wait.assert_called_once()
        assert session._started is True
    
    @patch('reverse_engineering_assistant.cli.ReVaSession.start')
    @patch('reverse_engineering_assistant.cli.ReVaSession.shutdown')
    def test_context_manager(self, mock_shutdown, mock_start):
        """Test context manager functionality."""
        session = ReVaSession(['/bin/ls'])
        
        with session as ctx_session:
            assert ctx_session is session
            mock_start.assert_called_once()
        
        mock_shutdown.assert_called_once()


class TestMainCommand:
    """Tests for main CLI command."""
    
    @patch('reverse_engineering_assistant.cli.ReVaSession')
    def test_main_with_basic_args(self, mock_session_class):
        """Test main function with basic arguments."""
        mock_session = Mock()
        mock_session.ghidra_path = "/test/ghidra"
        mock_session_class.return_value = mock_session
        
        # Mock sys.argv to simulate command line arguments
        test_args = ['reva', '/bin/ls']
        
        with patch('sys.argv', test_args):
            with patch('argparse.ArgumentParser.parse_args') as mock_parse:
                mock_args = Mock()
                mock_args.binaries = ['/bin/ls']
                mock_args.ghidra_path = None
                mock_args.project_dir = None
                mock_args.project_name = None
                mock_args.port = 8080
                mock_args.auto_analyze = False
                mock_args.verbose = False
                mock_parse.return_value = mock_args
                
                try:
                    main()
                except SystemExit:
                    pass  # main() calls sys.exit(), which is expected
                
                # Verify session was created with correct parameters
                mock_session_class.assert_called_once()
                call_args = mock_session_class.call_args
                assert call_args.kwargs['binaries'] == ['/bin/ls']
                assert call_args.kwargs['port'] == 8080
                # Check auto_analyze - should match the CLI argument
                expected_auto_analyze = mock_args.auto_analyze
                actual_auto_analyze = call_args.kwargs.get('auto_analyze')
                assert actual_auto_analyze == expected_auto_analyze
                assert call_args.kwargs['quiet'] is False  # CLI users expect output


if __name__ == "__main__":
    pytest.main([__file__])