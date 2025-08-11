#!/usr/bin/env python3
"""
Synchronize version across ReVa extension and Python package.
Usage: python scripts/sync-version.py <version>
"""

import sys
import re
from pathlib import Path

def update_pyproject_version(version: str):
    """Update version in cli/pyproject.toml"""
    pyproject_path = Path("cli/pyproject.toml")
    if not pyproject_path.exists():
        print(f"Error: {pyproject_path} not found")
        return False
    
    content = pyproject_path.read_text()
    
    # Update version line
    new_content = re.sub(
        r'^version = "[^"]*"',
        f'version = "{version}"',
        content,
        flags=re.MULTILINE
    )
    
    if new_content == content:
        print(f"Warning: No version change in {pyproject_path}")
        return False
    
    pyproject_path.write_text(new_content)
    print(f"✓ Updated {pyproject_path} to version {version}")
    return True

def main():
    if len(sys.argv) != 2:
        print("Usage: python scripts/sync-version.py <version>")
        print("Example: python scripts/sync-version.py 4.3.1")
        sys.exit(1)
    
    version = sys.argv[1]
    
    # Validate version format (basic semantic versioning)
    if not re.match(r'^\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?$', version):
        print(f"Error: Invalid version format: {version}")
        print("Expected format: X.Y.Z or X.Y.Z-suffix")
        sys.exit(1)
    
    print(f"Syncing version to {version}...")
    
    success = update_pyproject_version(version)
    
    if success:
        print("\n✅ Version sync complete!")
        print("\nNext steps:")
        print("1. Review the changes: git diff")
        print("2. Commit the changes: git commit -am 'Update version to {}'".format(version))
        print("3. Create a tag: git tag v{}".format(version))
        print("4. Push the tag: git push origin v{}".format(version))
    else:
        print("\n❌ Version sync failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()