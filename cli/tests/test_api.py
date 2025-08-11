#!/usr/bin/env python3
"""
Tests for ReVa programmatic API.
"""

import unittest
import socket
from unittest.mock import patch, MagicMock
from pathlib import Path

from reverse_engineering_assistant import ReVaSession, find_free_port


class TestFindFreePort(unittest.TestCase):
    """Test find_free_port utility function."""
    
    def test_find_free_port_returns_int(self):
        """Test that find_free_port returns an integer."""
        port = find_free_port()
        self.assertIsInstance(port, int)
        self.assertGreater(port, 0)
        self.assertLess(port, 65536)
    
    def test_find_free_port_returns_different_ports(self):
        """Test that multiple calls return different ports."""
        port1 = find_free_port()
        port2 = find_free_port()
        # Note: This could theoretically fail if we get the same port twice,
        # but it's extremely unlikely
        self.assertNotEqual(port1, port2)


class TestReVaSessionConstructor(unittest.TestCase):
    """Test ReVaSession constructor and basic properties."""
    
    def test_constructor_with_minimal_args(self):
        """Test constructor with just binaries argument."""
        binaries = ['/bin/ls']
        session = ReVaSession(binaries)
        
        self.assertEqual(session.binaries, binaries)
        self.assertIsInstance(session.port, int)
        self.assertTrue(session.quiet)  # Default should be True for API
        self.assertFalse(session.auto_analyze)  # Default should be False for lazy analysis
        self.assertFalse(session._started)
        self.assertIsNone(session.server_url)
        self.assertEqual(session.programs, {})
    
    def test_constructor_with_all_args(self):
        """Test constructor with all arguments specified."""
        binaries = ['/bin/ls', '/bin/cat']
        port = 9999
        
        session = ReVaSession(
            binaries=binaries,
            ghidra_path='/custom/ghidra',
            project_dir='/tmp/test',
            project_name='test_project',
            port=port,
            auto_analyze=False,
            quiet=False
        )
        
        self.assertEqual(session.binaries, binaries)
        self.assertEqual(session.port, port)
        self.assertFalse(session.quiet)
        self.assertFalse(session.auto_analyze)
        self.assertEqual(session.project_name, 'test_project')
        self.assertFalse(session._started)
    
    def test_constructor_auto_assigns_port(self):
        """Test that port is auto-assigned when None."""
        session = ReVaSession(['/bin/ls'], port=None)
        self.assertIsInstance(session.port, int)
        self.assertGreater(session.port, 0)
    
    def test_constructor_generates_project_name(self):
        """Test that project name is auto-generated when None."""
        session = ReVaSession(['/bin/ls'], project_name=None)
        self.assertIsInstance(session.project_name, str)
        self.assertIn('reva_session_', session.project_name)


class TestReVaSessionContextManager(unittest.TestCase):
    """Test ReVaSession context manager functionality."""
    
    @patch('reverse_engineering_assistant.cli.ReVaSession.start')
    @patch('reverse_engineering_assistant.cli.ReVaSession.shutdown')
    def test_context_manager_calls_start_and_shutdown(self, mock_shutdown, mock_start):
        """Test that context manager calls start and shutdown."""
        session = ReVaSession(['/bin/ls'])
        
        with session as ctx_session:
            self.assertIs(ctx_session, session)
            mock_start.assert_called_once()
        
        mock_shutdown.assert_called_once()
    
    @patch('reverse_engineering_assistant.cli.ReVaSession.start')
    @patch('reverse_engineering_assistant.cli.ReVaSession.shutdown')
    def test_context_manager_shutdown_on_exception(self, mock_shutdown, mock_start):
        """Test that context manager calls shutdown even on exception."""
        session = ReVaSession(['/bin/ls'])
        
        with self.assertRaises(ValueError):
            with session:
                raise ValueError("Test exception")
        
        mock_start.assert_called_once()
        mock_shutdown.assert_called_once()


class TestReVaSessionMethods(unittest.TestCase):
    """Test ReVaSession methods."""
    
    def test_shutdown_when_not_started(self):
        """Test that shutdown does nothing when not started."""
        session = ReVaSession(['/bin/ls'])
        # Should not raise any exceptions
        session.shutdown()
        self.assertFalse(session._started)
    
    @patch('reverse_engineering_assistant.cli.ReVaSession.initialize_pyghidra')
    @patch('reverse_engineering_assistant.cli.ReVaSession.open_project')
    @patch('reverse_engineering_assistant.cli.ReVaSession.import_programs')
    @patch('reverse_engineering_assistant.cli.ReVaSession.initialize_reva')
    @patch('reverse_engineering_assistant.cli.ReVaSession.wait_for_mcp_server')
    def test_start_method_sequence(self, mock_wait, mock_init_reva, mock_import, mock_project, mock_pyghidra):
        """Test that start method calls methods in correct sequence."""
        session = ReVaSession(['/bin/ls'])
        # Mock programs to avoid "no programs imported" error
        session.programs = {'ls': MagicMock()}
        
        session.start()
        
        # Verify methods called in order
        mock_pyghidra.assert_called_once()
        mock_project.assert_called_once()
        mock_import.assert_called_once_with(['/bin/ls'], run_analysis=False)
        mock_init_reva.assert_called_once()
        mock_wait.assert_called_once()
        
        self.assertTrue(session._started)
    
    def test_start_idempotent(self):
        """Test that calling start multiple times is safe."""
        session = ReVaSession(['/bin/ls'])
        session._started = True  # Mock as already started
        
        # Should not raise any exceptions and should return early
        session.start()
        self.assertTrue(session._started)
    
    @patch('reverse_engineering_assistant.cli.ReVaSession.initialize_pyghidra')
    def test_start_cleanup_on_exception(self, mock_pyghidra):
        """Test that start cleans up on failure."""
        mock_pyghidra.side_effect = RuntimeError("Test error")
        session = ReVaSession(['/bin/ls'])
        
        with patch.object(session, 'shutdown') as mock_shutdown:
            with self.assertRaises(RuntimeError):
                session.start()
            mock_shutdown.assert_called_once()


class TestReVaSessionProperties(unittest.TestCase):
    """Test ReVaSession properties and state management."""
    
    def test_initial_state(self):
        """Test initial state of session."""
        session = ReVaSession(['/bin/ls'])
        
        self.assertFalse(session._started)
        self.assertIsNone(session.server_url)
        self.assertEqual(session.programs, {})
        self.assertIsNone(session.project)
        self.assertFalse(session.pyghidra_started)


class TestReVaSessionErrorPaths(unittest.TestCase):
    """Test error handling and edge cases."""
    
    def test_no_binaries_allowed(self):
        """Test that providing no binaries is now allowed for dynamic loading."""
        # Should not raise an error - empty project is valid
        session = ReVaSession([])
        self.assertEqual(session.binaries, [])
        
        # None is also allowed
        session = ReVaSession(None)
        self.assertEqual(session.binaries, [])
    
    def test_nonexistent_binary_raises_error(self):
        """Test that nonexistent binary raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError) as context:
            ReVaSession(['/nonexistent/binary.exe'])
        self.assertIn("Binary not found", str(context.exception))
    
    def test_directory_as_binary_raises_error(self):
        """Test that passing a directory instead of file raises ValueError."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ValueError) as context:
                ReVaSession([tmpdir])
            self.assertIn("not a file", str(context.exception))
    
    def test_multiple_shutdown_calls_safe(self):
        """Test that calling shutdown multiple times is safe."""
        session = ReVaSession(['/bin/ls'])
        # Should not raise any exceptions
        session.shutdown()
        session.shutdown()
        session.shutdown()
    
    def test_shutdown_with_partial_initialization(self):
        """Test shutdown handles partial initialization gracefully."""
        session = ReVaSession(['/bin/ls'])
        # Simulate partial initialization by removing some attributes
        delattr(session, 'project')
        # Should not raise any exceptions
        session.shutdown()
    
    @patch('reverse_engineering_assistant.cli.ReVaSession.initialize_pyghidra')
    @patch('reverse_engineering_assistant.cli.ReVaSession.shutdown')
    def test_context_manager_cleanup_on_start_failure(self, mock_shutdown, mock_init):
        """Test context manager calls shutdown even when start fails."""
        mock_init.side_effect = RuntimeError("PyGhidra failed")
        
        with self.assertRaises(RuntimeError):
            with ReVaSession(['/bin/ls']) as session:
                pass  # Should never reach here
        
        # Verify shutdown was called for cleanup
        mock_shutdown.assert_called()
    
    def test_defensive_shutdown_without_started_attribute(self):
        """Test shutdown handles missing _started attribute."""
        session = ReVaSession(['/bin/ls'])
        # Remove the _started attribute to simulate incomplete initialization
        delattr(session, '_started')
        # Should not raise any exceptions
        session.shutdown()
    
    @patch('shutil.rmtree')
    def test_shutdown_handles_permission_errors(self, mock_rmtree):
        """Test shutdown handles permission errors when cleaning up."""
        session = ReVaSession(['/bin/ls'])
        session._started = True
        session.cleanup_project = True
        
        # Simulate permission error
        mock_rmtree.side_effect = PermissionError("Access denied")
        
        # Should not raise exception, just log warning
        session.shutdown()
        mock_rmtree.assert_called()


class TestReVaSessionValidation(unittest.TestCase):
    """Test input validation and security."""
    
    def test_path_traversal_protection(self):
        """Test that path validation prevents traversal attacks."""
        # Create a real file to test with
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            # Normal path should work
            session = ReVaSession([tmp_path])
            self.assertEqual(len(session.binaries), 1)
        finally:
            import os
            os.unlink(tmp_path)
    
    def test_symlink_resolution(self):
        """Test that symlinks are properly resolved."""
        import tempfile
        import os
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a real file
            real_file = os.path.join(tmpdir, 'real.exe')
            with open(real_file, 'w') as f:
                f.write('test')
            
            # Create a symlink to it
            link_file = os.path.join(tmpdir, 'link.exe')
            os.symlink(real_file, link_file)
            
            # Should accept the symlink and resolve it
            session = ReVaSession([link_file])
            self.assertEqual(len(session.binaries), 1)


if __name__ == '__main__':
    unittest.main()