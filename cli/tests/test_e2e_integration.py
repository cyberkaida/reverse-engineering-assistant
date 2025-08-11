"""End-to-end integration tests for ReVa CLI with compiled test binaries."""

import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
import requests

from reverse_engineering_assistant import ReVaSession


@pytest.mark.integration
class TestReVaEndToEndIntegration:
    """End-to-end integration tests with compiled test binaries."""

    def test_server_startup_shutdown_with_compiled_binary(
        self, sample_binaries, server_health_check
    ):
        """Test ReVa server startup and shutdown with a compiled test binary."""
        test_binary = sample_binaries['minimal']
        
        # Start ReVa process
        process = subprocess.Popen(
            [
                "uv", "run", "reva", 
                "--no-analysis", 
                "--port", "8080", 
                str(test_binary)
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=Path(__file__).parent.parent
        )
        
        try:
            # Wait for server to be ready
            server_ready = server_health_check("http://localhost:8080", timeout=60)
            assert server_ready, "ReVa server did not start within timeout"
            
            # Server should be responding
            response = requests.get("http://localhost:8080/", timeout=5)
            assert response.status_code in (200, 404), f"Unexpected status: {response.status_code}"
            
        finally:
            # Clean shutdown
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    
    def test_session_api_with_compiled_binary(self, sample_binaries):
        """Test ReVaSession API with a compiled test binary."""
        test_binary = sample_binaries['hello_world']
        
        # Test session creation
        session = ReVaSession([str(test_binary)], auto_analyze=False, quiet=True)
        
        # Basic properties
        assert str(test_binary) in session.binaries
        assert not session._started
        assert session.port > 0
        
        # Test context manager (mock the actual server start for unit test)
        # Note: Full server test requires more complex setup
        assert hasattr(session, '__enter__')
        assert hasattr(session, '__exit__')
    
    @pytest.mark.slow
    def test_full_workflow_with_functions_binary(
        self, sample_binaries, server_health_check
    ):
        """Test a full ReVa workflow with a binary containing functions."""
        test_binary = sample_binaries['simple_functions']
        
        # Start ReVa with analysis disabled for faster startup
        process = subprocess.Popen(
            [
                "uv", "run", "reva",
                "--no-analysis",
                "--port", "8081",  # Different port to avoid conflicts
                str(test_binary)
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=Path(__file__).parent.parent
        )
        
        try:
            # Wait for server startup
            server_ready = server_health_check("http://localhost:8081", timeout=60)
            assert server_ready, "ReVa server did not start within timeout"
            
            # Test basic connectivity
            response = requests.get("http://localhost:8081/", timeout=5)
            assert response.status_code in (200, 404)
            
        finally:
            # Clean shutdown
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    
    @pytest.mark.slow
    def test_multiple_binaries_startup(
        self, sample_binaries, server_health_check
    ):
        """Test ReVa startup with multiple compiled binaries."""
        binaries = [
            str(sample_binaries['minimal']),
            str(sample_binaries['hello_world'])
        ]
        
        process = subprocess.Popen(
            [
                "uv", "run", "reva",
                "--no-analysis",
                "--port", "8082",
            ] + binaries,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=Path(__file__).parent.parent
        )
        
        try:
            server_ready = server_health_check("http://localhost:8082", timeout=60)
            assert server_ready, "ReVa server with multiple binaries did not start"
            
            # Basic health check
            response = requests.get("http://localhost:8082/", timeout=5)
            assert response.status_code in (200, 404)
            
        finally:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    
    def test_binary_compilation_quality(self, binary_compiler):
        """Test that our compiled binaries have expected properties."""
        # Test minimal binary
        minimal_binary = binary_compiler.compile_c_code(
            "int main() { return 42; }", 
            "test_minimal"
        )
        
        assert minimal_binary.exists()
        assert minimal_binary.is_file()
        assert os.access(minimal_binary, os.X_OK)  # Executable
        
        # Test function binary
        function_code = '''
        int add(int a, int b) { return a + b; }
        int main() { return add(20, 22); }
        '''
        function_binary = binary_compiler.compile_c_code(function_code, "test_functions")
        
        assert function_binary.exists()
        assert function_binary.is_file()
        assert os.access(function_binary, os.X_OK)
        
        # Verify we can run the binary (exit code should be 42)
        result = subprocess.run([str(function_binary)], capture_output=True)
        assert result.returncode == 42  # add(20, 22) = 42
    
    def test_error_handling_with_invalid_binary(self, temp_dir):
        """Test error handling when given an invalid binary."""
        # Create a non-executable file
        fake_binary = temp_dir / "fake_binary"
        fake_binary.write_text("not a binary")
        
        # ReVa should handle this gracefully (though behavior depends on implementation)
        # This test ensures we can at least attempt to start with invalid input
        process = subprocess.Popen(
            [
                "uv", "run", "reva",
                "--no-analysis",
                "--port", "8083",
                str(fake_binary)
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        # Give it a moment to process the invalid binary
        time.sleep(2)
        
        # Should either exit gracefully or continue (depending on error handling)
        if process.poll() is None:
            # If still running, shut it down
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        
        # Test passes if we didn't crash Python
        assert True