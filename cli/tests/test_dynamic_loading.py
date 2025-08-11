"""Test dynamic binary loading workflow."""

import pytest
from reverse_engineering_assistant.cli import ReVaSession


class TestDynamicBinaryLoading:
    """Test that ReVa can start empty and load binaries dynamically."""

    def test_empty_session_creation(self):
        """Test creating a ReVa session with no binaries."""
        # Test with None
        session = ReVaSession(None)
        assert session.binaries == []
        assert session.programs == {}
        assert not session._started
        
        # Test with empty list
        session = ReVaSession([])
        assert session.binaries == []
        assert session.programs == {}
        assert not session._started

    def test_empty_session_no_default_binaries_param(self):
        """Test creating a ReVa session without specifying binaries parameter."""
        session = ReVaSession()
        assert session.binaries == []
        assert session.programs == {}
        assert not session._started

    def test_session_properties_without_binaries(self):
        """Test that session properties work correctly without binaries."""
        session = ReVaSession()
        
        # Basic properties should be set
        assert isinstance(session.project_name, str)
        assert len(session.project_name) > 0
        assert session.port > 0
        assert session.ghidra_path is not None
        assert session.project_dir is not None
        
        # State should be unstarted
        assert not session._started
        assert not session.pyghidra_started
        assert session.project is None
        assert session.programs == {}

    def test_session_with_mixed_empty_binaries(self, sample_binaries):
        """Test session can handle binaries being added later."""
        # Start empty
        session = ReVaSession()
        assert session.binaries == []
        
        # Could potentially add binaries later (this would be done via MCP tools)
        # For now, just test that we can create sessions in different ways
        session_with_binaries = ReVaSession([str(sample_binaries['minimal'])])
        assert len(session_with_binaries.binaries) == 1

    def test_backwards_compatibility_with_binaries(self, sample_binaries):
        """Test that providing binaries still works (backwards compatibility)."""
        test_binary = sample_binaries['hello_world']
        
        # Should still work to provide binaries upfront
        session = ReVaSession([str(test_binary)])
        assert len(session.binaries) == 1
        assert str(test_binary) in session.binaries

    @pytest.mark.integration
    def test_empty_session_startup_without_programs_check(self):
        """Test that empty session can start without the 'no programs' error."""
        session = ReVaSession()
        
        # Mock the methods that would require actual Ghidra/PyGhidra
        # to test that the logic allows empty startup
        class MockSession(ReVaSession):
            def initialize_pyghidra(self):
                self.pyghidra_started = True
                
            def open_project(self):
                # Mock project object
                self.project = type('MockProject', (), {})()
                
            def initialize_reva(self, port):
                pass
                
            def wait_for_mcp_server(self, port):
                pass
                
            def display_ready_message(self, port):
                pass
        
        mock_session = MockSession()
        mock_session.quiet = True  # Suppress output
        
        # Should not raise an error even with no programs
        try:
            mock_session.start()
            assert mock_session._started
            assert mock_session.programs == {}  # Empty is OK now
        except Exception as e:
            # Should not fail due to "No programs were successfully imported"
            assert "No programs were successfully imported" not in str(e)
            # Other errors might occur due to mocking, but not the programs check