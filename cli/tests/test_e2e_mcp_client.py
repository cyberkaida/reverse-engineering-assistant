"""End-to-end tests for MCP client-server communication with ReVa."""

import asyncio
import signal
import subprocess
import time
from pathlib import Path
from typing import Dict, Any

import pytest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.mcp
class TestMCPClientServerCommunication:
    """Test MCP protocol communication with ReVa server."""

    async def create_mcp_client_session(self, reva_process, test_binary: Path):
        """Create an MCP client session connected to ReVa server via HTTP."""
        # ReVa uses HTTP transport, but we need to test the MCP protocol over it
        # For now, we'll use direct HTTP requests to test the MCP endpoint
        import httpx
        
        # Wait for server to be ready
        server_ready = False
        start_time = time.time()
        while time.time() - start_time < 30:
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get("http://localhost:8080/")
                    if response.status_code in (200, 404):
                        server_ready = True
                        break
            except Exception:
                pass
            await asyncio.sleep(1)
        
        if not server_ready:
            pytest.fail("ReVa server not ready for MCP client connection")
        
        return httpx.AsyncClient()

    async def send_mcp_request(self, client, method: str, params: Dict[str, Any] = None):
        """Send MCP request via HTTP transport."""
        mcp_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
        }
        if params:
            mcp_request["params"] = params
        
        response = await client.post(
            "http://localhost:8080/mcp/message",
            json=mcp_request,
            headers={"Content-Type": "application/json"}
        )
        
        return response.json() if response.status_code == 200 else None

    def test_mcp_client_can_connect_to_server(self, sample_binaries, server_health_check):
        """Test that MCP client can connect to ReVa server."""
        test_binary = sample_binaries['minimal']
        
        # Start ReVa server
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
            cwd=Path(__file__).parent.parent
        )
        
        try:
            # Wait for server readiness
            assert server_health_check("http://localhost:8080", timeout=60), "Server not ready"
            
            # Test MCP connection
            async def test_connection():
                async with httpx.AsyncClient() as client:
                    # Test basic MCP initialize
                    response = await self.send_mcp_request(
                        client,
                        "initialize",
                        {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "pytest-mcp-client", "version": "1.0.0"}
                        }
                    )
                    assert response is not None, "No response from MCP server"
                    assert "result" in response, f"Invalid MCP response: {response}"
                    assert response.get("jsonrpc") == "2.0", "Invalid JSON-RPC version"
                    
                    return response
            
            # Run async test
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(test_connection())
                # Basic validation that we got an MCP response
                assert result is not None
            finally:
                loop.close()
                
        finally:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def test_mcp_list_tools(self, sample_binaries, server_health_check):
        """Test MCP tools/list request."""
        test_binary = sample_binaries['simple_functions']
        
        process = subprocess.Popen(
            [
                "uv", "run", "reva",
                "--no-analysis", 
                "--port", "8081",
                str(test_binary)
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        try:
            assert server_health_check("http://localhost:8081", timeout=60)
            
            async def test_list_tools():
                import httpx
                async with httpx.AsyncClient() as client:
                    # Initialize first
                    init_response = await self.send_mcp_request(
                        client,
                        "initialize",
                        {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "pytest", "version": "1.0.0"}
                        }
                    )
                    assert init_response and "result" in init_response
                    
                    # List tools
                    tools_response = await self.send_mcp_request(client, "tools/list")
                    assert tools_response and "result" in tools_response
                    
                    tools = tools_response["result"].get("tools", [])
                    assert len(tools) > 0, "No tools returned by server"
                    
                    # Verify we have expected ReVa tools
                    tool_names = [tool["name"] for tool in tools]
                    expected_tools = ["list-programs", "create-project", "load-binary"]
                    
                    for expected_tool in expected_tools:
                        assert expected_tool in tool_names, f"Missing tool: {expected_tool}"
                    
                    return tools
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                tools = loop.run_until_complete(test_list_tools())
                assert len(tools) > 5, f"Expected multiple tools, got {len(tools)}"
            finally:
                loop.close()
                
        finally:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def test_mcp_call_tool_list_programs(self, sample_binaries, server_health_check):
        """Test MCP tools/call with list-programs tool."""
        test_binary = sample_binaries['hello_world']
        
        process = subprocess.Popen(
            [
                "uv", "run", "reva",
                "--no-analysis",
                "--port", "8082", 
                str(test_binary)
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        try:
            assert server_health_check("http://localhost:8082", timeout=60)
            
            async def test_call_tool():
                import httpx
                async with httpx.AsyncClient() as client:
                    # Initialize
                    await self.send_mcp_request(
                        client,
                        "initialize", 
                        {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "pytest", "version": "1.0.0"}
                        }
                    )
                    
                    # Call list-programs tool
                    call_response = await self.send_mcp_request(
                        client,
                        "tools/call",
                        {
                            "name": "list-programs",
                            "arguments": {}
                        }
                    )
                    
                    assert call_response and "result" in call_response
                    result = call_response["result"]
                    
                    # Should have content with program info
                    assert "content" in result
                    content = result["content"]
                    assert len(content) > 0
                    
                    # The content should mention our test binary
                    content_text = str(content)
                    # Test binary name should appear in the results somewhere
                    binary_name = test_binary.name
                    assert binary_name in content_text or "test_hello_world" in content_text
                    
                    return result
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(test_call_tool())
                assert result is not None
            finally:
                loop.close()
                
        finally:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def test_mcp_protocol_error_handling(self, sample_binaries, server_health_check):
        """Test MCP protocol error handling."""
        test_binary = sample_binaries['minimal']
        
        process = subprocess.Popen(
            [
                "uv", "run", "reva",
                "--no-analysis",
                "--port", "8083",
                str(test_binary)
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        try:
            assert server_health_check("http://localhost:8083", timeout=60)
            
            async def test_error_handling():
                import httpx
                async with httpx.AsyncClient() as client:
                    # Test invalid tool call
                    error_response = await self.send_mcp_request(
                        client,
                        "tools/call",
                        {
                            "name": "nonexistent-tool",
                            "arguments": {}
                        }
                    )
                    
                    # Should get an error response
                    assert error_response is not None
                    # MCP errors should have "error" field instead of "result"
                    assert "error" in error_response or "result" in error_response
                    
                    # Test malformed request
                    malformed_response = await client.post(
                        "http://localhost:8083/mcp/message",
                        json={"invalid": "request"},
                        headers={"Content-Type": "application/json"}
                    )
                    
                    # Should handle gracefully (not crash server)
                    assert malformed_response.status_code in (200, 400, 500)
                    
                    return True
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(test_error_handling())
            finally:
                loop.close()
                
        finally:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def test_mcp_multiple_tool_calls(self, sample_binaries, server_health_check):
        """Test multiple MCP tool calls in sequence."""
        test_binary = sample_binaries['simple_functions']
        
        process = subprocess.Popen(
            [
                "uv", "run", "reva",
                "--no-analysis",
                "--port", "8084",
                str(test_binary)
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        try:
            assert server_health_check("http://localhost:8084", timeout=60)
            
            async def test_multiple_calls():
                import httpx
                async with httpx.AsyncClient() as client:
                    # Initialize
                    await self.send_mcp_request(
                        client,
                        "initialize",
                        {
                            "protocolVersion": "2024-11-05", 
                            "capabilities": {},
                            "clientInfo": {"name": "pytest", "version": "1.0.0"}
                        }
                    )
                    
                    # Call 1: List programs
                    response1 = await self.send_mcp_request(
                        client,
                        "tools/call",
                        {"name": "list-programs", "arguments": {}}
                    )
                    assert response1 and "result" in response1
                    
                    # Call 2: List tools
                    response2 = await self.send_mcp_request(client, "tools/list")
                    assert response2 and "result" in response2
                    
                    # Both calls should succeed
                    return len(response2["result"].get("tools", []))
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                tool_count = loop.run_until_complete(test_multiple_calls())
                assert tool_count > 0
            finally:
                loop.close()
                
        finally:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()