#!/usr/bin/env python3
"""
Integration test for the ReVa PyGhidra CLI tool.
This script tests the full workflow with a real binary.
"""

import os
import sys
import time
import subprocess
import signal
import requests
from pathlib import Path

def test_reva_cli():
    """Test the ReVa CLI with /bin/ls binary."""
    
    # Path to test binary
    test_binary = "/bin/ls"
    if not Path(test_binary).exists():
        print(f"❌ Test binary {test_binary} not found")
        return False
    
    print(f"✓ Using test binary: {test_binary}")
    
    # Start the ReVa CLI in a subprocess
    print("Starting ReVa CLI...")
    process = subprocess.Popen(
        ["uv", "run", "reva", "--no-analysis", "--port", "8080", test_binary],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    print(f"✓ Started ReVa process (PID: {process.pid})")
    
    # Give it time to start
    print("Waiting for initialization...")
    start_time = time.time()
    timeout = 60  # 60 seconds timeout
    
    server_ready = False
    while time.time() - start_time < timeout:
        # Check if process is still running
        if process.poll() is not None:
            print("❌ Process terminated unexpectedly")
            # Print output
            output, _ = process.communicate()
            print("Process output:")
            print(output)
            return False
        
        # Try to connect to MCP server
        try:
            response = requests.get("http://localhost:8080/", timeout=2)
            if response.status_code == 200 or response.status_code == 404:
                server_ready = True
                print("✓ MCP server is responding")
                break
        except requests.exceptions.RequestException:
            pass
        
        time.sleep(2)
    
    if not server_ready:
        print("❌ MCP server did not start within timeout")
        process.terminate()
        output, _ = process.communicate()
        print("Process output:")
        print(output)
        return False
    
    # Test is successful - server is running
    print("✓ Integration test successful!")
    print("Shutting down...")
    
    # Send interrupt signal to gracefully shutdown
    process.send_signal(signal.SIGINT)
    
    # Wait for graceful shutdown
    try:
        process.wait(timeout=10)
        print("✓ Process shut down gracefully")
    except subprocess.TimeoutExpired:
        print("⚠️ Process didn't shut down gracefully, forcing...")
        process.kill()
        process.wait()
    
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("ReVa PyGhidra CLI Integration Test")
    print("=" * 60)
    
    success = test_reva_cli()
    
    print("=" * 60)
    if success:
        print("✅ All tests passed!")
        sys.exit(0)
    else:
        print("❌ Tests failed")
        sys.exit(1)