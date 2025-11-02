"""
Test helper utilities for ReVa headless integration tests.

Provides common functionality used across multiple test modules:
- MCP request handling
- Test program creation
- Response validation
"""

import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional


def make_mcp_request(
    port: int,
    tool_name: str,
    arguments: Optional[Dict[str, Any]] = None,
    timeout: int = 10
) -> Optional[Dict[str, Any]]:
    """
    Make an MCP tool call request to the server.

    Args:
        port: Server port number
        tool_name: Name of the MCP tool to call
        arguments: Dictionary of tool arguments (optional)
        timeout: Request timeout in seconds (default: 10)

    Returns:
        Parsed JSON response dictionary, or None if request fails

    Example:
        >>> response = make_mcp_request(8080, "list-programs")
        >>> assert response["jsonrpc"] == "2.0"
    """
    url = f"http://localhost:{port}/mcp/message"

    # MCP JSON-RPC 2.0 request format
    request_data = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments or {}
        }
    }

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(request_data).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )

        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode('utf-8'))

    except urllib.error.URLError as e:
        print(f"MCP request failed (connection): {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"MCP request failed (invalid JSON): {e}")
        return None
    except Exception as e:
        print(f"MCP request failed (unexpected): {e}")
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
        response: Response from make_mcp_request()

    Returns:
        The result value from the response

    Raises:
        AssertionError: If response is None, has an error, or missing result

    Example:
        >>> response = make_mcp_request(8080, "list-programs")
        >>> result = get_response_result(response)
    """
    assert response is not None, "Server did not respond"

    if "error" in response:
        error_msg = response.get("error", {}).get("message", "Unknown error")
        raise AssertionError(f"MCP call returned error: {error_msg}")

    assert "result" in response, "Response missing result field"
    return response["result"]
