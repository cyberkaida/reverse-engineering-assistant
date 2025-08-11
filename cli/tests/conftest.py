"""Test fixtures and utilities for ReVa CLI tests."""

import os
import shutil
import subprocess
import tempfile
import pytest
from pathlib import Path
from typing import Dict, List, Optional


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test artifacts."""
    temp_dir = tempfile.mkdtemp(prefix="reva_test_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


class TestBinaryCompiler:
    """Utility class for compiling test binaries on-the-fly."""
    
    def __init__(self, temp_dir: Path):
        self.temp_dir = temp_dir
        self.compiler = self._find_c_compiler()
    
    def _find_c_compiler(self) -> str:
        """Find an available C compiler."""
        compilers = ['gcc', 'clang', 'cc']
        for compiler in compilers:
            if shutil.which(compiler):
                return compiler
        pytest.skip("No C compiler found (tried: gcc, clang, cc)")
    
    def compile_c_code(self, code: str, binary_name: str = "test_binary") -> Path:
        """
        Compile C code to a binary.
        
        Args:
            code: C source code as string
            binary_name: Name for the output binary
            
        Returns:
            Path to the compiled binary
        """
        source_file = self.temp_dir / f"{binary_name}.c"
        binary_file = self.temp_dir / binary_name
        
        # Write source code
        source_file.write_text(code)
        
        # Compile
        cmd = [self.compiler, str(source_file), "-o", str(binary_file)]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
        except subprocess.CalledProcessError as e:
            pytest.fail(f"Failed to compile test binary: {e.stderr}")
        
        if not binary_file.exists():
            pytest.fail(f"Binary was not created at {binary_file}")
        
        return binary_file


@pytest.fixture
def binary_compiler(temp_dir):
    """Fixture providing a TestBinaryCompiler instance."""
    return TestBinaryCompiler(temp_dir)


# Common test programs
TEST_PROGRAMS = {
    'hello_world': '''
#include <stdio.h>

int main() {
    printf("Hello, World!\\n");
    return 0;
}
''',
    
    'simple_functions': '''
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int multiply(int x, int y) {
    return x * y;
}

void print_message(const char* msg) {
    printf("%s\\n", msg);
}

int main() {
    int result = add(5, 3);
    int product = multiply(result, 2);
    print_message("Math operations completed");
    return product;
}
''',
    
    'string_operations': '''
#include <stdio.h>
#include <string.h>

const char* messages[] = {
    "Error: Invalid input",
    "Warning: Low memory",
    "Info: Process completed",
    "Debug: Function called"
};

int main() {
    for (int i = 0; i < 4; i++) {
        printf("%s\\n", messages[i]);
    }
    return 0;
}
''',
    
    'minimal': '''
int main() { 
    return 42; 
}
'''
}


@pytest.fixture
def sample_binaries(binary_compiler):
    """Fixture providing compiled sample binaries."""
    binaries = {}
    for name, code in TEST_PROGRAMS.items():
        binaries[name] = binary_compiler.compile_c_code(code, f"test_{name}")
    return binaries


def wait_for_server_ready(url: str, timeout: int = 30) -> bool:
    """
    Wait for a server to become ready.
    
    Args:
        url: Server URL to check
        timeout: Timeout in seconds
        
    Returns:
        True if server becomes ready, False if timeout
    """
    import time
    import requests
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(url, timeout=2)
            # Accept both 200 (OK) and 404 (Not Found) as signs the server is running
            if response.status_code in (200, 404):
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(1)
    return False


@pytest.fixture
def server_health_check():
    """Fixture providing server health check utility."""
    return wait_for_server_ready