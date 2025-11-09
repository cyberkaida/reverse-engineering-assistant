"""
Test helper utilities for ReVa headless integration tests.

Provides common functionality used across multiple test modules:
- MCP request handling
- Test program creation
- Response validation
"""

from typing import Dict, Any, Optional
import asyncio
from pathlib import Path


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
        >>> response = make_mcp_request(8080, "list-open-programs")
        >>> result = get_response_result(response)
    """
    assert response is not None, "Server did not respond"

    if response.get("isError", False):
        raise AssertionError(f"MCP call returned error: {response.get('content')}")

    assert "content" in response, "Response missing content field"
    return response["content"]


# ============================================================================
# CLI Helper Functions
# ============================================================================

def create_minimal_binary(path: Path, arch: str = "x86") -> Path:
    """
    Create a minimal valid binary for testing.

    Creates a tiny but valid executable that Ghidra can recognize and import.
    The binary is as small as possible while still being valid.

    Args:
        path: Path where binary should be created
        arch: Architecture (currently only "x86" supported)

    Returns:
        Path to the created binary

    Example:
        >>> binary = create_minimal_binary(Path("test.exe"))
        >>> assert binary.exists()
        >>> assert binary.stat().st_size > 0
    """
    import sys
    import platform

    # Create minimal ELF (Linux/Unix) - 45 bytes
    # This is a minimal ELF that exits immediately
    elf_bytes = bytes([
        # ELF Header
        0x7f, 0x45, 0x4c, 0x46,  # Magic: 0x7f, 'E', 'L', 'F'
        0x01,                     # Class: 32-bit
        0x01,                     # Data: Little endian
        0x01,                     # Version: Current
        0x00,                     # OS/ABI: System V
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Padding
        0x02, 0x00,               # Type: Executable
        0x03, 0x00,               # Machine: x86
        0x01, 0x00, 0x00, 0x00,   # Version: 1
        0x00, 0x00, 0x00, 0x00,   # Entry point: 0 (will fail but Ghidra can analyze)
        0x34, 0x00, 0x00, 0x00,   # Program header offset: 52
        0x00, 0x00, 0x00, 0x00,   # Section header offset: 0
        0x00, 0x00, 0x00, 0x00,   # Flags: 0
        0x34, 0x00,               # ELF header size: 52
        0x20, 0x00,               # Program header size: 32
        0x00, 0x00,               # Program header count: 0
        0x00, 0x00,               # Section header size: 0
        0x00, 0x00,               # Section header count: 0
        0x00, 0x00,               # Section name string table index: 0
    ])

    path.write_bytes(elf_bytes)
    path.chmod(0o755)  # Make executable

    return path


def send_mcp_message(
    process,
    method: str,
    params: Optional[Dict[str, Any]] = None,
    msg_id: int = 1
) -> None:
    """
    Send a JSON-RPC message to subprocess stdin.

    Args:
        process: subprocess.Popen instance
        method: MCP method name (e.g., "initialize", "tools/list")
        params: Method parameters (optional)
        msg_id: Message ID for JSON-RPC

    Example:
        >>> send_mcp_message(proc, "initialize", {}, 1)
        >>> send_mcp_message(proc, "tools/list", None, 2)
    """
    import json

    message = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "method": method
    }

    if params is not None:
        message["params"] = params

    json_str = json.dumps(message)
    process.stdin.write(json_str + "\n")
    process.stdin.flush()


def read_mcp_response(process, timeout: float = 10.0) -> Dict[str, Any]:
    """
    Read a JSON-RPC response from subprocess stdout.

    Args:
        process: subprocess.Popen instance
        timeout: Maximum time to wait for response in seconds

    Returns:
        Parsed JSON-RPC response dictionary

    Raises:
        TimeoutError: If response not received within timeout
        RuntimeError: If process died
        json.JSONDecodeError: If response is not valid JSON

    Example:
        >>> response = read_mcp_response(proc, timeout=5.0)
        >>> assert response["jsonrpc"] == "2.0"
    """
    import json
    import select
    import time

    start_time = time.time()

    while True:
        # Check if process died
        if process.poll() is not None:
            _, stderr = process.communicate()
            raise RuntimeError(f"Process died: {stderr}")

        # Check timeout
        elapsed = time.time() - start_time
        if elapsed > timeout:
            raise TimeoutError(f"No response received within {timeout} seconds")

        # Try to read with remaining timeout
        remaining = timeout - elapsed

        # Use select on Unix, just readline with short timeout on Windows
        import sys
        if sys.platform != "win32":
            ready, _, _ = select.select([process.stdout], [], [], min(remaining, 0.1))
            if ready:
                line = process.stdout.readline()
                if line:
                    return json.loads(line.strip())
        else:
            # Windows doesn't support select on pipes, just try reading
            # This might block but we have timeout logic
            line = process.stdout.readline()
            if line:
                return json.loads(line.strip())

        time.sleep(0.05)  # Small sleep to avoid busy waiting


def wait_for_server_ready(process, timeout: float = 60.0) -> bool:
    """
    Wait for server to print "Bridge ready" message to stderr.

    Monitors stderr for the startup completion message.

    Args:
        process: subprocess.Popen instance
        timeout: Maximum time to wait in seconds

    Returns:
        True if server became ready, False otherwise

    Example:
        >>> assert wait_for_server_ready(proc, timeout=30)
    """
    import time
    import select
    import sys

    start_time = time.time()
    stderr_buffer = ""

    while True:
        # Check if process died
        if process.poll() is not None:
            return False

        # Check timeout
        elapsed = time.time() - start_time
        if elapsed > timeout:
            return False

        remaining = timeout - elapsed

        # Read from stderr
        if sys.platform != "win32":
            ready, _, _ = select.select([process.stderr], [], [], min(remaining, 0.1))
            if ready:
                char = process.stderr.read(1)
                if char:
                    stderr_buffer += char
                    # Check for ready message
                    if "Bridge ready" in stderr_buffer or "bridge ready" in stderr_buffer.lower():
                        return True
        else:
            # Windows: use non-blocking approach
            # This is less efficient but works on Windows
            time.sleep(0.1)
            # Check if there's stderr to read (this is imperfect on Windows)

        time.sleep(0.05)
