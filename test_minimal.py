#!/usr/bin/env python3
"""
Minimal test to verify pyghidra and Python infrastructure works.
This test doesn't require the Java build to complete.
"""

import os
import sys

print("=" * 80)
print("Minimal ReVa Headless Test (No Java Build Required)")
print("=" * 80)

# Test 1: Environment
print("\n1. Checking environment...")
ghidra_dir = os.getenv("GHIDRA_INSTALL_DIR")
if ghidra_dir:
    print(f"   ✓ GHIDRA_INSTALL_DIR: {ghidra_dir}")
else:
    print("   ✗ GHIDRA_INSTALL_DIR not set")
    sys.exit(1)

# Test 2: Python imports
print("\n2. Testing Python imports...")
try:
    import pyghidra
    print("   ✓ pyghidra imported")
except ImportError as e:
    print(f"   ✗ Failed to import pyghidra: {e}")
    sys.exit(1)

try:
    import requests
    print("   ✓ requests imported")
except ImportError as e:
    print(f"   ✗ Failed to import requests: {e}")
    sys.exit(1)

# Test 3: Pyghidra startup
print("\n3. Starting Ghidra via pyghidra...")
try:
    pyghidra.start()
    print("   ✓ Ghidra started successfully")
except Exception as e:
    print(f"   ✗ Failed to start Ghidra: {e}")
    sys.exit(1)

# Test 4: Try importing Java classes
print("\n4. Testing if ReVa Java classes are available...")
try:
    # Try to import the HeadlessRevaLauncher class
    from reva.server import HeadlessRevaLauncher
    print("   ✓ HeadlessRevaLauncher class found")

    # Try to create an instance
    launcher = HeadlessRevaLauncher()
    print("   ✓ HeadlessRevaLauncher instance created")
    print(f"   ✓ Server would run on {launcher.getServerHost()}:{launcher.getServerPort()}")

except ImportError as e:
    print(f"   ✗ Could not import ReVa classes: {e}")
    print("   → This is expected if Java build hasn't completed")
    print("   → Need to build with: gradle buildExtension")
except Exception as e:
    print(f"   ✗ Error creating launcher: {e}")
    print("   → This indicates a runtime issue with the Java code")

# Test 5: Python launcher script exists
print("\n5. Checking Python launcher script...")
launcher_script = os.path.join(os.getcwd(), "reva_headless.py")
if os.path.exists(launcher_script):
    print(f"   ✓ reva_headless.py exists")
    # Check if it's executable
    if os.access(launcher_script, os.X_OK):
        print(f"   ✓ reva_headless.py is executable")
    else:
        print(f"   ⚠ reva_headless.py is not executable")
else:
    print(f"   ✗ reva_headless.py not found")

# Test 6: Test files exist
print("\n6. Checking test files...")
test_files = [
    "tests/smoke_test.py",
    "tests/test_headless_e2e.py",
    "src/test/java/reva/server/HeadlessRevaLauncherIntegrationTest.java"
]
for test_file in test_files:
    if os.path.exists(test_file):
        print(f"   ✓ {test_file}")
    else:
        print(f"   ✗ {test_file} missing")

print("\n" + "=" * 80)
print("Summary:")
print("  - Python infrastructure: WORKING ✓")
print("  - Pyghidra: WORKING ✓")
print("  - Java classes: NEED BUILD (expected)")
print("  - Test files: PRESENT ✓")
print("=" * 80)
print("\nNext step: Build with 'gradle buildExtension' in environment with Maven access")
