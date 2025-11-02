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
        >>> response = make_mcp_request(8080, "list-open-programs")
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

    url = f"http://localhost:{port}/mcp/message"

    try:
        # Use the streamable HTTP client from MCP SDK
        async with streamablehttp_client(url, timeout=float(timeout)) as (read_stream, write_stream, get_session_id):
            async with ClientSession(read_stream, write_stream) as session:
                # Initialize the session
                init_result = await session.initialize()
                print(f"DEBUG: Initialized session, server info: {init_result}")

                # List available tools for debugging
                tools_result = await session.list_tools()
                print(f"DEBUG: Available tools: {tools_result}")

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


def create_test_program():
    """
    Create a simple test program in Ghidra for testing.

    Creates a program with:
    - Architecture: x86 32-bit (LE)
    - Memory: .text section at 0x00401000 (4KB, filled with NOPs)
    - Strings: "Hello ReVa Test" at 0x00401100, "Test String 123" at 0x00401200
    - Symbol: "test_function" label at 0x00401000

    Returns:
        ProgramDB instance, or None if creation fails

    Note:
        Caller is responsible for releasing the program with program.release(None)
    """
    try:
        from ghidra.program.database import ProgramDB
        from ghidra.program.model.lang import LanguageID
        from ghidra.util.task import TaskMonitor
        from ghidra.program.model.symbol import SourceType

        # Get language service
        from ghidra.program.util import DefaultLanguageService
        language_service = DefaultLanguageService.getLanguageService()

        # Create x86 32-bit program
        language = language_service.getLanguage(LanguageID("x86:LE:32:default"))
        compiler_spec = language.getDefaultCompilerSpec()

        # Create program
        program = ProgramDB("TestHeadlessProgram", language, compiler_spec, None)

        # Add memory and data
        memory = program.getMemory()
        tx_id = program.startTransaction("Create Test Data")
        try:
            # Create .text section at 0x00401000
            addr_space = program.getAddressFactory().getDefaultAddressSpace()
            text_start = addr_space.getAddress(0x00401000)

            # Add 4KB memory block filled with NOPs (0x90)
            memory.createInitializedBlock(
                ".text",
                text_start,
                0x1000,
                bytes([0x90])[0],  # NOP instruction
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
            return program

        except Exception as e:
            program.endTransaction(tx_id, False)
            raise e

    except Exception as e:
        print(f"Failed to create test program: {e}")
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
        >>> response = make_mcp_request(8080, "list-open-programs")
        >>> result = get_response_result(response)
    """
    assert response is not None, "Server did not respond"

    if response.get("isError", False):
        raise AssertionError(f"MCP call returned error: {response.get('content')}")

    assert "content" in response, "Response missing content field"
    return response["content"]
