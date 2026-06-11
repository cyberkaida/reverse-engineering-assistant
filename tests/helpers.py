"""
Test helper utilities for ReVa headless integration tests.

Provides common functionality used across multiple test modules:
- MCP request handling
- Test program creation
- Response validation
"""

from typing import Dict, Any, Optional
import asyncio


def make_mcp_request(
    port: int,
    tool_name: str,
    arguments: Optional[Dict[str, Any]] = None,
    timeout: int = 10
) -> Optional[Dict[str, Any]]:
    """
    Make an MCP tool call request to the server using the MCP Python SDK.

    Args:
        port: Server port number
        tool_name: Name of the MCP tool to call
        arguments: Dictionary of tool arguments (optional)
        timeout: Request timeout in seconds (default: 10)

    Returns:
        Tool call result dictionary, or None if request fails

    Example:
        >>> response = make_mcp_request(8080, "list-project-files")
        >>> assert response is not None
    """
    try:
        # Use asyncio to run the async MCP client
        return asyncio.run(_make_mcp_request_async(port, tool_name, arguments, timeout))
    except Exception as e:
        print(f"MCP request failed: {e}")
        import traceback
        traceback.print_exc()
        return None


async def _make_mcp_request_async(
    port: int,
    tool_name: str,
    arguments: Optional[Dict[str, Any]],
    timeout: int
) -> Optional[Dict[str, Any]]:
    """
    Async implementation of MCP request using StreamableHTTP transport.
    """
    from mcp.client.streamable_http import streamablehttp_client
    from mcp import ClientSession
    import httpx

    url = f"http://localhost:{port}/mcp/message"

    def _no_keepalive_factory(headers=None, timeout=None, auth=None):
        """Disable keepalive to avoid stale TCP connections after SSE responses."""
        return httpx.AsyncClient(
            headers=headers,
            timeout=timeout,
            auth=auth,
            limits=httpx.Limits(max_keepalive_connections=0),
        )

    try:
        # Use the streamable HTTP client from MCP SDK
        async with streamablehttp_client(
            url,
            timeout=float(timeout),
            httpx_client_factory=_no_keepalive_factory,
        ) as (read_stream, write_stream, get_session_id):
            async with ClientSession(read_stream, write_stream) as session:
                # Initialize the session
                init_result = await session.initialize()
                print(f"DEBUG: Initialized session, server info: {init_result}")

                # Call the tool
                print(f"DEBUG: Calling tool '{tool_name}' with arguments {arguments}")
                result = await session.call_tool(
                    name=tool_name,
                    arguments=arguments or {}
                )
                print(f"DEBUG: Tool call result: {result}")

                # Return the tool call result
                return {
                    "content": result.content,
                    "isError": result.isError if hasattr(result, 'isError') else False
                }

    except Exception as e:
        print(f"Async MCP request failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def list_mcp_tools(
    port: int,
    timeout: int = 10
) -> Optional[list]:
    """
    List the tools registered on the server using the MCP Python SDK.

    Speaks the same streamable-HTTP protocol as make_mcp_request but issues
    a tools/list request instead of a tool call.

    Args:
        port: Server port number
        timeout: Request timeout in seconds (default: 10)

    Returns:
        List of mcp.types.Tool objects, or None if the request fails

    Example:
        >>> tools = list_mcp_tools(8080)
        >>> assert any(t.name == "list-project-files" for t in tools)
    """
    try:
        return asyncio.run(_list_mcp_tools_async(port, timeout))
    except Exception as e:
        print(f"MCP tools/list request failed: {e}")
        import traceback
        traceback.print_exc()
        return None


async def _list_mcp_tools_async(port: int, timeout: int) -> Optional[list]:
    """
    Async implementation of tools/list using StreamableHTTP transport.
    """
    from mcp.client.streamable_http import streamablehttp_client
    from mcp import ClientSession
    import httpx

    url = f"http://localhost:{port}/mcp/message"

    def _no_keepalive_factory(headers=None, timeout=None, auth=None):
        """Disable keepalive to avoid stale TCP connections after SSE responses."""
        return httpx.AsyncClient(
            headers=headers,
            timeout=timeout,
            auth=auth,
            limits=httpx.Limits(max_keepalive_connections=0),
        )

    try:
        async with streamablehttp_client(
            url,
            timeout=float(timeout),
            httpx_client_factory=_no_keepalive_factory,
        ) as (read_stream, write_stream, get_session_id):
            async with ClientSession(read_stream, write_stream) as session:
                init_result = await session.initialize()
                print(f"DEBUG: Initialized session, server info: {init_result}")

                result = await session.list_tools()
                return list(result.tools)

    except Exception as e:
        print(f"Async MCP tools/list request failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def create_test_program():
    """
    Create a simple test program in Ghidra for testing using ProgramBuilder.

    Creates a program with:
    - Architecture: x86 32-bit (LE)
    - Memory: .text section at 0x00401000 (4KB, filled with NOPs)
    - Strings: "Hello ReVa Test" at 0x00401100, "Test String 123" at 0x00401200
    - Symbol: "test_function" label at 0x00401000

    Returns:
        ProgramBuilder instance (caller must call dispose() or release program)

    Note:
        Uses Ghidra's ProgramBuilder for proper test program construction.
        The ProgramBuilder acts as the program consumer.
        Caller must either:
        - Call builder.dispose() to release the program, OR
        - Call program.release(builder) with the builder as consumer
    """
    try:
        from ghidra.program.database import ProgramBuilder
        from ghidra.util.task import TaskMonitor
        from ghidra.program.model.symbol import SourceType

        # Create program using ProgramBuilder (Ghidra's standard test helper)
        # ProgramBuilder uses itself as the consumer
        builder = ProgramBuilder("TestHeadlessProgram", ProgramBuilder._X86)
        program = builder.getProgram()

        # Add memory and data
        tx_id = program.startTransaction("Create Test Data")
        try:
            memory = program.getMemory()
            addr_space = program.getAddressFactory().getDefaultAddressSpace()
            text_start = addr_space.getAddress(0x00401000)

            # Add 4KB memory block filled with NOPs (0x90)
            # Convert Python int to Java byte using JPype
            from jpype import JByte
            nop_byte = JByte(0x90 - 256)  # Convert to signed byte (-112)
            memory.createInitializedBlock(
                ".text",
                text_start,
                0x1000,
                nop_byte,
                TaskMonitor.DUMMY,
                False
            )

            # Add test strings
            string_data1 = b"Hello ReVa Test\x00"
            memory.setBytes(addr_space.getAddress(0x00401100), string_data1)

            string_data2 = b"Test String 123\x00"
            memory.setBytes(addr_space.getAddress(0x00401200), string_data2)

            # Create a label
            symbol_table = program.getSymbolTable()
            symbol_table.createLabel(
                text_start,
                "test_function",
                SourceType.USER_DEFINED
            )

            program.endTransaction(tx_id, True)

            # Return the builder (it owns the program as consumer)
            return builder

        except Exception as e:
            program.endTransaction(tx_id, False)
            raise e

    except Exception as e:
        print(f"Failed to create test program: {e}")
        import traceback
        traceback.print_exc()
        return None


def get_response_result(response: Optional[Dict[str, Any]]) -> Any:
    """
    Extract the result from an MCP response.

    Args:
        response: Response from make_mcp_request() containing 'content' and 'isError' fields

    Returns:
        The content from the response

    Raises:
        AssertionError: If response is None or has an error

    Example:
        >>> response = make_mcp_request(8080, "list-project-files")
        >>> result = get_response_result(response)
    """
    assert response is not None, "Server did not respond"

    if response.get("isError", False):
        raise AssertionError(f"MCP call returned error: {response.get('content')}")

    assert "content" in response, "Response missing content field"
    return response["content"]
