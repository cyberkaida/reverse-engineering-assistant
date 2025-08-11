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
        self.assertTrue(session.auto_analyze)  # Default should be True
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
        mock_import.assert_called_once_with(['/bin/ls'], run_analysis=True)
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


if __name__ == '__main__':
    unittest.main()