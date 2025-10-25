#!/usr/bin/env python3
"""
End-to-end tests for ReVa headless mode.

These tests verify the complete headless workflow including:
- Server startup via Python launcher
- MCP client connection
- Tool invocation
- Program management
- Server shutdown

Requirements:
- pyghidra
- requests (for HTTP client)
- GHIDRA_INSTALL_DIR environment variable
"""

import json
import os
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path

import requests


class HeadlessE2ETestBase(unittest.TestCase):
    """Base class for headless end-to-end tests"""

    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests"""
        cls.test_port = 18080
        cls.test_host = "127.0.0.1"
        cls.base_url = f"http://{cls.test_host}:{cls.test_port}"
        cls.mcp_endpoint = f"{cls.base_url}/mcp/message"

        # Verify GHIDRA_INSTALL_DIR is set
        if not os.getenv("GHIDRA_INSTALL_DIR"):
            raise unittest.SkipTest("GHIDRA_INSTALL_DIR not set")

        # Verify build exists
        cls.project_root = Path(__file__).parent.parent
        cls.build_dir = cls.project_root / "build" / "classes" / "java" / "main"

        if not cls.build_dir.exists():
            raise unittest.SkipTest(f"Build directory not found: {cls.build_dir}")

    def setUp(self):
        """Set up for each test"""
        self.server_process = None

    def tearDown(self):
        """Clean up after each test"""
        self.stop_server()

    def start_server(self, args=None, wait_for_ready=True):
        """
        Start the headless server

        Args:
            args: Additional command-line arguments
            wait_for_ready: Whether to wait for server to be ready
        """
        cmd = [
            sys.executable,
            str(self.project_root / "reva_headless.py"),
            "--host", self.test_host,
            "--port", str(self.test_port),
        ]

        if args:
            cmd.extend(args)

        # Start server process
        self.server_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=os.environ.copy()
        )

        if wait_for_ready:
            # Wait for server to be ready
            max_wait = 30  # 30 seconds
            start_time = time.time()

            while time.time() - start_time < max_wait:
                try:
                    response = requests.get(
                        self.base_url,
                        timeout=1
                    )
                    # Any response means server is up
                    return True
                except requests.exceptions.RequestException:
                    time.sleep(0.5)

                # Check if process died
                if self.server_process.poll() is not None:
                    stdout, stderr = self.server_process.communicate()
                    raise RuntimeError(
                        f"Server process died:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
                    )

            raise TimeoutError("Server failed to start within timeout")

        return True

    def stop_server(self):
        """Stop the headless server"""
        if self.server_process:
            try:
                # Send SIGTERM for graceful shutdown
                self.server_process.send_signal(signal.SIGTERM)

                # Wait up to 5 seconds for graceful shutdown
                try:
                    self.server_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't stop gracefully
                    self.server_process.kill()
                    self.server_process.wait()

            except Exception as e:
                print(f"Error stopping server: {e}", file=sys.stderr)

            finally:
                self.server_process = None

    def mcp_request(self, method, params=None):
        """
        Make an MCP request to the server

        Args:
            method: MCP method name (e.g., "tools/list", "tools/call")
            params: Method parameters

        Returns:
            Response JSON
        """
        request_data = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
        }

        if params:
            request_data["params"] = params

        response = requests.post(
            self.mcp_endpoint,
            json=request_data,
            headers={"Content-Type": "application/json"},
            timeout=30
        )

        response.raise_for_status()
        return response.json()


class TestServerLifecycle(HeadlessE2ETestBase):
    """Test server startup and shutdown"""

    def test_server_starts(self):
        """Test that server starts successfully"""
        self.start_server()

        # Verify server is reachable
        response = requests.get(self.base_url, timeout=5)
        self.assertIn(response.status_code, [200, 404, 405])

    def test_server_stops_gracefully(self):
        """Test that server stops gracefully on SIGTERM"""
        self.start_server()

        # Verify server is running
        response = requests.get(self.base_url, timeout=5)
        self.assertIn(response.status_code, [200, 404, 405])

        # Stop server
        self.stop_server()

        # Verify server is no longer accessible
        with self.assertRaises(requests.exceptions.RequestException):
            requests.get(self.base_url, timeout=2)

    def test_server_restartable(self):
        """Test that server can be restarted"""
        # Start server
        self.start_server()
        response = requests.get(self.base_url, timeout=5)
        self.assertIn(response.status_code, [200, 404, 405])

        # Stop server
        self.stop_server()

        # Restart server
        self.start_server()
        response = requests.get(self.base_url, timeout=5)
        self.assertIn(response.status_code, [200, 404, 405])


class TestMCPProtocol(HeadlessE2ETestBase):
    """Test MCP protocol communication"""

    def test_list_tools(self):
        """Test that we can list available tools"""
        self.start_server()

        # Make MCP request to list tools
        response = self.mcp_request("tools/list")

        self.assertIn("result", response)
        result = response["result"]
        self.assertIn("tools", result)

        tools = result["tools"]
        self.assertIsInstance(tools, list)
        self.assertGreater(len(tools), 0, "Should have at least one tool")

        # Verify tool structure
        for tool in tools:
            self.assertIn("name", tool)
            self.assertIn("description", tool)

        # Verify some expected tools exist
        tool_names = [tool["name"] for tool in tools]
        self.assertIn("list-programs", tool_names)
        self.assertIn("list-functions", tool_names)

    def test_list_resources(self):
        """Test that we can list available resources"""
        self.start_server()

        # Make MCP request to list resources
        response = self.mcp_request("resources/list")

        self.assertIn("result", response)
        result = response["result"]
        self.assertIn("resources", result)

        # Resources list may be empty without programs loaded
        self.assertIsInstance(result["resources"], list)

    def test_call_list_programs_tool(self):
        """Test calling the list-programs tool"""
        self.start_server()

        # Call list-programs tool
        response = self.mcp_request("tools/call", {
            "name": "list-programs",
            "arguments": {}
        })

        self.assertIn("result", response)
        result = response["result"]
        self.assertIn("content", result)

        # Content should be a list with at least one item
        content = result["content"]
        self.assertIsInstance(content, list)
        self.assertGreater(len(content), 0)

        # First content item should be text
        first_content = content[0]
        self.assertIn("type", first_content)
        self.assertEqual(first_content["type"], "text")
        self.assertIn("text", first_content)

        # Parse the JSON response
        programs_data = json.loads(first_content["text"])
        self.assertIn("programs", programs_data)


class TestErrorHandling(HeadlessE2ETestBase):
    """Test error handling in headless mode"""

    def test_invalid_mcp_method(self):
        """Test handling of invalid MCP method"""
        self.start_server()

        response = self.mcp_request("invalid/method")

        # Should get an error response
        self.assertIn("error", response)

    def test_invalid_tool_name(self):
        """Test calling a non-existent tool"""
        self.start_server()

        response = self.mcp_request("tools/call", {
            "name": "nonexistent-tool",
            "arguments": {}
        })

        # Should get an error response
        self.assertIn("error", response)

    def test_malformed_json(self):
        """Test handling of malformed JSON request"""
        self.start_server()

        # Send malformed JSON
        response = requests.post(
            self.mcp_endpoint,
            data="{ this is not valid json }",
            headers={"Content-Type": "application/json"},
            timeout=5
        )

        # Should get error response
        self.assertEqual(response.status_code, 400)


class TestPerformance(HeadlessE2ETestBase):
    """Performance tests for headless mode"""

    def test_startup_time(self):
        """Test that server starts within reasonable time"""
        start_time = time.time()
        self.start_server()
        end_time = time.time()

        startup_time = end_time - start_time
        print(f"Server startup time: {startup_time:.2f}s")

        # Server should start within 30 seconds
        self.assertLess(startup_time, 30.0,
                       f"Server took too long to start: {startup_time:.2f}s")

    def test_tool_response_time(self):
        """Test that tools respond quickly"""
        self.start_server()

        # Measure response time for list-programs
        start_time = time.time()
        self.mcp_request("tools/call", {
            "name": "list-programs",
            "arguments": {}
        })
        end_time = time.time()

        response_time = end_time - start_time
        print(f"Tool response time: {response_time:.2f}s")

        # Should respond within 5 seconds
        self.assertLess(response_time, 5.0,
                       f"Tool took too long to respond: {response_time:.2f}s")


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestServerLifecycle))
    suite.addTests(loader.loadTestsFromTestCase(TestMCPProtocol))
    suite.addTests(loader.loadTestsFromTestCase(TestErrorHandling))
    suite.addTests(loader.loadTestsFromTestCase(TestPerformance))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Return exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())
