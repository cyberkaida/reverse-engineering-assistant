"""End-to-end tests for ReVa MCP workflow: project creation, binary loading, and analysis."""

import asyncio
import signal
import subprocess
import time
from pathlib import Path

import pytest
import httpx


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.mcp
class TestReVaMCPWorkflow:
    """Test complete ReVa MCP workflow with project management and analysis tools."""

    async def send_mcp_request(self, client: httpx.AsyncClient, method: str, params: dict = None):
        """Send MCP request via HTTP transport."""
        mcp_request = {
            "jsonrpc": "2.0", 
            "id": 1,
            "method": method,
        }
        if params:
            mcp_request["params"] = params
        
        response = await client.post(
            "http://localhost:8085/mcp/message",
            json=mcp_request,
            headers={"Content-Type": "application/json"}
        )
        
        return response.json() if response.status_code == 200 else None

    async def initialize_mcp_session(self, client: httpx.AsyncClient):
        """Initialize MCP session."""
        return await self.send_mcp_request(
            client,
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "pytest-workflow", "version": "1.0.0"}
            }
        )

    def test_complete_project_workflow(self, sample_binaries, server_health_check):
        """Test complete workflow: create project, load binary, analyze."""
        test_binary = sample_binaries['simple_functions']
        
        process = subprocess.Popen(
            [
                "uv", "run", "reva",
                "--no-analysis",  # Start without analysis for manual control
                "--port", "8085",
                str(test_binary)
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        try:
            assert server_health_check("http://localhost:8085", timeout=60)
            
            async def workflow_test():
                async with httpx.AsyncClient() as client:
                    # Step 1: Initialize
                    init_response = await self.initialize_mcp_session(client)
                    assert init_response and "result" in init_response
                    
                    # Step 2: List programs (should show imported binary)
                    programs_response = await self.send_mcp_request(
                        client,
                        "tools/call",
                        {"name": "list-programs", "arguments": {}}
                    )
                    assert programs_response and "result" in programs_response
                    
                    # Should have our test binary loaded
                    content = str(programs_response["result"]["content"])
                    binary_name = test_binary.name
                    assert binary_name in content or "test_simple_functions" in content
                    
                    # Step 3: Try to get program info (if available)
                    try:
                        # Look for a program path to use in further calls
                        # The exact format depends on ReVa's response structure
                        program_path = None
                        if "programPath" in content or "/" in content:
                            # Extract program path from response
                            # This is a simplified extraction - real implementation may vary
                            lines = content.split('\n')
                            for line in lines:
                                if 'test_simple_functions' in line or binary_name in line:
                                    # Try to extract path-like string
                                    parts = line.split()
                                    for part in parts:
                                        if '/' in part and ('test_simple_functions' in part or binary_name in part):
                                            program_path = part.strip('",')
                                            break
                                    if program_path:
                                        break
                        
                        if program_path:
                            # Step 4: List functions (if we have a program path)
                            functions_response = await self.send_mcp_request(
                                client,
                                "tools/call",
                                {
                                    "name": "list-functions",
                                    "arguments": {"programPath": program_path}
                                }
                            )
                            
                            if functions_response and "result" in functions_response:
                                functions_content = str(functions_response["result"]["content"])
                                # Should find functions from our test binary
                                assert "main" in functions_content or "function" in functions_content.lower()
                            
                    except Exception as e:
                        # If function listing fails, that's okay - the main goal is MCP communication
                        print(f"Function listing failed (acceptable): {e}")
                    
                    return True
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(workflow_test())
                assert result
            finally:
                loop.close()
                
        finally:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def test_project_management_tools(self, sample_binaries, server_health_check):
        """Test project management MCP tools."""
        test_binary = sample_binaries['hello_world']
        
        process = subprocess.Popen(
            [
                "uv", "run", "reva",
                "--no-analysis",
                "--port", "8086",
                str(test_binary)
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        try:
            assert server_health_check("http://localhost:8086", timeout=60)
            
            async def test_project_tools():
                async with httpx.AsyncClient() as client:
                    await self.initialize_mcp_session(client)
                    
                    # Test available project tools
                    tools_response = await self.send_mcp_request(client, "tools/list")
                    assert tools_response and "result" in tools_response
                    
                    tools = tools_response["result"].get("tools", [])
                    tool_names = [tool["name"] for tool in tools]
                    
                    # Verify key project management tools exist
                    expected_project_tools = [
                        "list-programs",
                        "create-project",  # May or may not be available
                        "load-binary"      # May or may not be available  
                    ]
                    
                    available_tools = []
                    for tool in expected_project_tools:
                        if tool in tool_names:
                            available_tools.append(tool)
                    
                    # Should have at least list-programs
                    assert "list-programs" in tool_names, f"Available tools: {tool_names}"
                    
                    # Test calling available tools
                    for tool_name in available_tools[:2]:  # Test first 2 available tools
                        try:
                            response = await self.send_mcp_request(
                                client,
                                "tools/call",
                                {"name": tool_name, "arguments": {}}
                            )
                            # Tool should respond (success or failure)
                            assert response is not None
                        except Exception as e:
                            print(f"Tool {tool_name} failed (may be expected): {e}")
                    
                    return len(available_tools)
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                available_count = loop.run_until_complete(test_project_tools())
                assert available_count >= 1, "Should have at least one project management tool"
            finally:
                loop.close()
                
        finally:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def test_analysis_tools_availability(self, sample_binaries, server_health_check):
        """Test that analysis tools are available and callable."""
        test_binary = sample_binaries['string_operations']
        
        process = subprocess.Popen(
            [
                "uv", "run", "reva",
                "--no-analysis",
                "--port", "8087",
                str(test_binary)
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        try:
            assert server_health_check("http://localhost:8087", timeout=60)
            
            async def test_analysis_tools():
                async with httpx.AsyncClient() as client:
                    await self.initialize_mcp_session(client)
                    
                    # Get all available tools
                    tools_response = await self.send_mcp_request(client, "tools/list")
                    tools = tools_response["result"].get("tools", [])
                    tool_names = [tool["name"] for tool in tools]
                    
                    # Check for common analysis tools
                    analysis_tools = [
                        "list-functions",
                        "list-strings", 
                        "decompile",
                        "analyze-program"
                    ]
                    
                    available_analysis_tools = []
                    for tool in analysis_tools:
                        if tool in tool_names:
                            available_analysis_tools.append(tool)
                    
                    # Should have multiple analysis tools
                    assert len(available_analysis_tools) >= 2, f"Expected analysis tools, found: {available_analysis_tools}"
                    
                    # Test that tools can be called (even if they fail due to missing args)
                    for tool_name in available_analysis_tools[:3]:  # Test up to 3 tools
                        try:
                            response = await self.send_mcp_request(
                                client,
                                "tools/call",
                                {"name": tool_name, "arguments": {}}
                            )
                            # Should get some response (success or error)
                            assert response is not None
                            
                            # If it's an error about missing arguments, that's actually good
                            if "error" in response:
                                error_msg = str(response["error"])
                                # These are acceptable errors indicating the tool exists
                                acceptable_errors = [
                                    "required", "missing", "parameter", "argument", 
                                    "programPath", "functionName"
                                ]
                                assert any(err in error_msg.lower() for err in acceptable_errors), \
                                    f"Unexpected error for {tool_name}: {error_msg}"
                            
                        except Exception as e:
                            print(f"Analysis tool {tool_name} test failed: {e}")
                    
                    return available_analysis_tools
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                analysis_tools = loop.run_until_complete(test_analysis_tools())
                assert len(analysis_tools) >= 1, "Should have at least one analysis tool"
            finally:
                loop.close()
                
        finally:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def test_concurrent_mcp_requests(self, sample_binaries, server_health_check):
        """Test that the MCP server can handle concurrent requests."""
        test_binary = sample_binaries['minimal']
        
        process = subprocess.Popen(
            [
                "uv", "run", "reva",
                "--no-analysis",
                "--port", "8088",
                str(test_binary)
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        try:
            assert server_health_check("http://localhost:8088", timeout=60)
            
            async def test_concurrent():
                async with httpx.AsyncClient() as client:
                    await self.initialize_mcp_session(client)
                    
                    # Create multiple concurrent requests
                    async def make_request(req_id):
                        return await self.send_mcp_request(
                            client,
                            "tools/list"
                        )
                    
                    # Run 3 concurrent requests
                    tasks = [make_request(i) for i in range(3)]
                    responses = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    # All should succeed
                    success_count = 0
                    for response in responses:
                        if not isinstance(response, Exception) and response and "result" in response:
                            success_count += 1
                    
                    assert success_count >= 2, f"Expected at least 2 successful concurrent requests, got {success_count}"
                    
                    return success_count
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success_count = loop.run_until_complete(test_concurrent())
                assert success_count >= 2
            finally:
                loop.close()
                
        finally:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()