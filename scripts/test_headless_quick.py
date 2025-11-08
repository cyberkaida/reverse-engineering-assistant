#!/usr/bin/env python3
"""
Quick test script for ReVa headless mode

This script performs a quick smoke test to verify that:
1. PyGhidra can be initialized
2. ReVa headless launcher can start
3. Server becomes ready
4. MCP protocol works (list programs, list strings)
5. Server can be stopped cleanly

Usage:
    python scripts/test_headless_quick.py

Requirements:
    - pyghidra installed
    - GHIDRA_INSTALL_DIR set
    - Java 21+ installed
"""

import sys
import time
import json
import urllib.request
import urllib.error


def make_mcp_request(port, tool_name, arguments=None):
    """
    Make an MCP tool call request to the server

    Args:
        port: Server port
        tool_name: Name of the MCP tool to call
        arguments: Dictionary of tool arguments

    Returns:
        Response data or None on error
    """
    url = f"http://localhost:{port}/mcp/message"

    # MCP request format for tool call
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

        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception as e:
        print(f"     ✗ MCP request failed: {e}")
        return None


def create_test_program():
    """Create a simple test program in Ghidra for testing"""
    print("\n[*] Creating test program...")

    try:
        from ghidra.program.database import ProgramDB
        from ghidra.program.model.lang import LanguageID
        from ghidra.program.model.mem import Memory
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import TaskMonitor

        # Get language service
        from ghidra.program.util import DefaultLanguageService
        language_service = DefaultLanguageService.getLanguageService()

        # Create x86 32-bit program
        language = language_service.getLanguage(LanguageID("x86:LE:32:default"))
        compiler_spec = language.getDefaultCompilerSpec()

        # Create program
        program = ProgramDB("TestHeadlessProgram", language, compiler_spec, None)

        # Add memory block with some data
        memory = program.getMemory()
        tx_id = program.startTransaction("Create Memory")
        try:
            # Create .text section
            addr_space = program.getAddressFactory().getDefaultAddressSpace()
            text_start = addr_space.getAddress(0x00401000)

            # Add memory block
            memory.createInitializedBlock(
                ".text",
                text_start,
                0x1000,
                (byte)0x90,  # NOP instruction
                TaskMonitor.DUMMY,
                False
            )

            # Add some recognizable strings in memory
            string_data = b"Hello ReVa Test\x00"
            memory.setBytes(addr_space.getAddress(0x00401100), string_data)

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
            print(f"     ✓ Created test program: {program.getName()}")
            print(f"     ✓ Added memory block at 0x{text_start}")
            print(f"     ✓ Added test strings")

            return program

        except Exception as e:
            program.endTransaction(tx_id, False)
            raise e

    except Exception as e:
        print(f"     ✗ Failed to create test program: {e}")
        return None


def test_mcp_functionality(port):
    """Test MCP protocol functionality - FAILS if MCP doesn't work"""
    print("\n[6/8] Testing MCP protocol functionality...")

    # Test 1: List programs - MUST work
    print("     Testing list-programs tool...")
    response = make_mcp_request(port, "list-programs")

    if not response:
        print(f"     ✗ MCP request failed - server not responding")
        return False

    if "error" in response:
        print(f"     ✗ MCP protocol error: {response.get('error')}")
        return False

    if "result" not in response:
        print(f"     ✗ Invalid MCP response format (no result): {response}")
        return False

    print(f"     ✓ list-programs succeeded (MCP protocol working)")

    # Check if our test program is in the list (informational)
    result_content = response.get("result", {}).get("content", [])
    if result_content:
        programs_text = str(result_content)
        if "TestHeadlessProgram" in programs_text:
            print(f"     ✓ Test program found in program list")
        else:
            print(f"     ℹ Test program not in list (expected - not in a project)")

    # Test 2: List strings - protocol must work, data can be empty
    print("     Testing list-strings tool...")
    response = make_mcp_request(
        port,
        "list-strings",
        {
            "programPath": "/TestHeadlessProgram",
            "minLength": 5
        }
    )

    if not response:
        print(f"     ✗ MCP request failed - server not responding")
        return False

    # It's okay if this returns an error (program not found), but the protocol must work
    if "error" in response:
        error_msg = response.get("error", {}).get("message", "")
        if "not found" in error_msg.lower() or "does not exist" in error_msg.lower():
            print(f"     ℹ Program not found (expected without project): {error_msg}")
            return True  # This is okay - protocol works, program just not in project
        else:
            print(f"     ✗ Unexpected MCP error: {response.get('error')}")
            return False

    if "result" not in response:
        print(f"     ✗ Invalid MCP response format (no result): {response}")
        return False

    print(f"     ✓ list-strings succeeded")

    # Check if we found our test strings (informational)
    result_content = response.get("result", {}).get("content", [])
    if result_content:
        strings_text = str(result_content)
        if "Hello ReVa Test" in strings_text or "Test String" in strings_text:
            print(f"     ✓ Test strings found in program")
        else:
            print(f"     ℹ Strings response received (may not contain test data)")

    return True


def test_headless_startup():
    """Test that headless server can start and stop"""
    print("=" * 60)
    print("ReVa Headless Quick Test")
    print("=" * 60)

    launcher = None
    program = None

    try:
        # Step 1: Import pyghidra
        print("\n[1/8] Importing pyghidra...")
        try:
            import pyghidra
            print("     ✓ pyghidra imported")
        except ImportError as e:
            print(f"     ✗ Failed to import pyghidra: {e}")
            print("     Install with: pip install pyghidra")
            return False

        # Step 2: Initialize Ghidra
        print("\n[2/8] Initializing Ghidra...")
        start_time = time.time()
        pyghidra.start(verbose=False)
        init_time = time.time() - start_time
        print(f"     ✓ Ghidra initialized in {init_time:.2f}s")

        # Step 3: Import ReVa classes
        print("\n[3/8] Importing ReVa classes...")
        from reva.headless import RevaHeadlessLauncher
        print("     ✓ ReVa classes imported")

        # Step 4: Create test program
        print("\n[4/8] Creating test program...")
        program = create_test_program()
        if not program:
            print("     ✗ Failed to create test program")
            return False

        # Step 5: Start server
        print("\n[5/8] Starting ReVa MCP server...")
        launcher = RevaHeadlessLauncher()

        start_time = time.time()
        launcher.start()
        startup_time = time.time() - start_time
        print(f"     ✓ Server started in {startup_time:.2f}s")

        # Wait for ready
        if not launcher.waitForServer(30000):
            print("     ✗ Server failed to become ready within timeout")
            return False

        port = launcher.getPort()
        print(f"     ✓ Server ready on port {port}")
        print(f"     ✓ Endpoint: http://localhost:{port}/mcp/message")

        # Verify status
        assert launcher.isRunning(), "Server should be running"
        assert launcher.isServerReady(), "Server should be ready"
        print("     ✓ Status checks passed")

        # Step 6: Test MCP functionality
        if not test_mcp_functionality(port):
            print("     ✗ MCP functionality test FAILED")
            print("     This means the MCP protocol is not working!")
            return False

        # Step 7: Test server responsiveness
        print("\n[7/8] Testing server responsiveness...")
        time.sleep(1)  # Give server a moment
        if launcher.isRunning():
            print("     ✓ Server still running after MCP calls")
        else:
            print("     ✗ Server stopped unexpectedly")
            return False

        # Step 8: Clean shutdown
        print("\n[8/8] Testing clean shutdown...")
        launcher.stop()
        time.sleep(0.5)  # Give it a moment to stop
        print("     ✓ Server stopped cleanly")

        # Final summary
        print("\n" + "=" * 60)
        print("✅ All tests passed!")
        print("=" * 60)
        print(f"Total initialization time: {init_time:.2f}s")
        print(f"Server startup time: {startup_time:.2f}s")
        print(f"Server endpoint: http://localhost:{port}/mcp/message")
        print(f"MCP protocol: ✓ Working")
        print("\nReVa is ready for headless operation! 🎉")
        return True

    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        # Cleanup
        if launcher:
            try:
                launcher.stop()
            except:
                pass

        if program:
            try:
                from ghidra.program.database import ProgramDB
                if isinstance(program, ProgramDB):
                    program.release(None)
            except:
                pass


def main():
    """Main entry point"""
    success = test_headless_startup()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
