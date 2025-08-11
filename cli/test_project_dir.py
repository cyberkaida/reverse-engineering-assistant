#!/usr/bin/env python3
"""Test project directory behavior for the ReVa CLI tool."""

import os
import tempfile
from pathlib import Path
import subprocess
import time

def test_project_directory_options():
    """Test different project directory configurations."""
    
    print("Testing ReVa project directory options...")
    
    # Test 1: Default (temp directory)
    print("\n1. Testing default temp directory...")
    result = subprocess.run(
        ["uv", "run", "python", "-c", """
from reverse_engineering_assistant.cli import PyGhidraReVaRunner
runner = PyGhidraReVaRunner()
print(f"Project dir: {runner.project_dir}")
print(f"Project name: {runner.project_name}")
print(f"Cleanup enabled: {runner.cleanup_project}")
assert str(runner.project_dir).startswith('/tmp/reva_projects_') or str(runner.project_dir).startswith('/var/folders/')
assert runner.cleanup_project == True
print("✓ Default temp directory test passed")
"""],
        capture_output=True,
        text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print(f"❌ Error: {result.stderr}")
        return False
    
    # Test 2: Environment variable
    print("\n2. Testing REVA_PROJECT_TEMP_DIR environment variable...")
    test_dir = Path(tempfile.gettempdir()) / "test_reva_env"
    env = os.environ.copy()
    env["REVA_PROJECT_TEMP_DIR"] = str(test_dir)
    
    result = subprocess.run(
        ["uv", "run", "python", "-c", f"""
from reverse_engineering_assistant.cli import PyGhidraReVaRunner
runner = PyGhidraReVaRunner()
print(f"Project dir: {{runner.project_dir}}")
print(f"Cleanup enabled: {{runner.cleanup_project}}")
assert str(runner.project_dir) == "{test_dir}"
assert runner.cleanup_project == True
print("✓ Environment variable test passed")
"""],
        capture_output=True,
        text=True,
        env=env
    )
    print(result.stdout)
    if result.returncode != 0:
        print(f"❌ Error: {result.stderr}")
        return False
    
    # Clean up test directory
    if test_dir.exists():
        import shutil
        shutil.rmtree(test_dir)
    
    # Test 3: Explicit project directory
    print("\n3. Testing explicit project directory...")
    explicit_dir = Path(tempfile.gettempdir()) / "test_reva_explicit"
    
    result = subprocess.run(
        ["uv", "run", "python", "-c", f"""
from reverse_engineering_assistant.cli import PyGhidraReVaRunner
runner = PyGhidraReVaRunner(project_dir="{explicit_dir}")
print(f"Project dir: {{runner.project_dir}}")
print(f"Cleanup enabled: {{runner.cleanup_project}}")
assert str(runner.project_dir) == "{explicit_dir}"
assert runner.cleanup_project == False  # Should not cleanup explicit directories
print("✓ Explicit project directory test passed")
"""],
        capture_output=True,
        text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print(f"❌ Error: {result.stderr}")
        return False
    
    # Clean up explicit directory
    if explicit_dir.exists():
        import shutil
        shutil.rmtree(explicit_dir)
    
    # Test 4: Custom project name
    print("\n4. Testing custom project name...")
    result = subprocess.run(
        ["uv", "run", "python", "-c", """
from reverse_engineering_assistant.cli import PyGhidraReVaRunner
runner = PyGhidraReVaRunner(project_name="my_custom_project")
print(f"Project name: {runner.project_name}")
assert runner.project_name == "my_custom_project"
print("✓ Custom project name test passed")
"""],
        capture_output=True,
        text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print(f"❌ Error: {result.stderr}")
        return False
    
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("ReVa Project Directory Configuration Test")
    print("=" * 60)
    
    success = test_project_directory_options()
    
    print("\n" + "=" * 60)
    if success:
        print("✅ All project directory tests passed!")
    else:
        print("❌ Some tests failed")
    
    exit(0 if success else 1)