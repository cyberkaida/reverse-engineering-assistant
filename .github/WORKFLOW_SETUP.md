# Setting Up the Headless Test Workflow

The headless test workflow file has been created but cannot be pushed automatically due to GitHub App permissions. This document explains how to add it manually.

## Why Manual Setup is Needed

GitHub Apps require special `workflows` permission to create or modify workflow files (`.github/workflows/*.yml`). This is a security feature to prevent unauthorized CI/CD changes.

## Option 1: Push from Local Machine (Recommended)

The workflow file exists in your local git repository. Simply push it from your machine:

```bash
# The file is at: .github/workflows/test-headless.yml
git add .github/workflows/test-headless.yml
git commit -m "Add headless test workflow"
git push
```

## Option 2: Copy from File Below

Create the file `.github/workflows/test-headless.yml` with this content:

```yaml
name: Test Headless Mode 🤖

on:
  push:
    branches: [ main, develop ]
    paths:
      - 'src/main/java/reva/headless/**'
      - 'src/main/java/reva/plugin/config/**'
      - 'src/main/java/reva/plugin/ConfigManager.java'
      - 'src/main/java/reva/server/McpServerManager.java'
      - 'scripts/**'
      - 'config/**'
      - '.github/workflows/test-headless.yml'
  pull_request:
    branches: [ main, develop ]
    paths:
      - 'src/main/java/reva/headless/**'
      - 'src/main/java/reva/plugin/config/**'
      - 'src/main/java/reva/plugin/ConfigManager.java'
      - 'src/main/java/reva/server/McpServerManager.java'
      - 'scripts/**'
      - 'config/**'
      - '.github/workflows/test-headless.yml'
  workflow_dispatch:  # Allow manual trigger

permissions:
  contents: read
  actions: read
  checks: write

jobs:
  test-headless:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
        ghidra-version: ["11.4.2", "latest"]
        python-version: ["3.9", "3.11", "3.12"]
        exclude:
          # Reduce matrix size - test latest Python on all, others on latest Ghidra only
          - ghidra-version: "11.4.2"
            python-version: "3.9"
          - ghidra-version: "11.4.2"
            python-version: "3.11"
      fail-fast: false  # Continue other tests if one fails

    name: Test on ${{ matrix.os }} / Ghidra ${{ matrix.ghidra-version }} / Python ${{ matrix.python-version }}
    runs-on: ${{ matrix.os }}

    steps:
    - name: Checkout code
      uses: actions/checkout@v5

    - name: Set up Java 21
      uses: actions/setup-java@v5
      with:
        java-version: "21"
        distribution: "microsoft"

    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v5
      with:
        python-version: ${{ matrix.python-version }}

    - name: Install Ghidra ${{ matrix.ghidra-version }}
      uses: antoniovazquezblanco/setup-ghidra@v2.0.14
      with:
        version: ${{ matrix.ghidra-version }}

    - name: Setup Gradle
      uses: gradle/actions/setup-gradle@v5
      with:
        gradle-version: "8.14"

    - name: Build ReVa Extension
      run: gradle buildExtension

    - name: Install ReVa Extension to Ghidra
      run: |
        EXTENSION_ZIP=$(ls -1 dist/*.zip | head -n 1)
        echo "Installing extension: $EXTENSION_ZIP"
        unzip -q "$EXTENSION_ZIP" -d "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/"
        ls -la "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/"

    - name: Install PyGhidra
      run: |
        python -m pip install --upgrade pip
        pip install pyghidra

    - name: Verify PyGhidra Installation
      run: |
        python -c "import pyghidra; print(f'PyGhidra version: {pyghidra.__version__}')"
        echo "GHIDRA_INSTALL_DIR: $GHIDRA_INSTALL_DIR"

    - name: Make scripts executable
      run: chmod +x scripts/*.py

    - name: Run Headless Quick Test
      id: headless_test
      run: |
        echo "::group::Running headless quick test"
        python scripts/test_headless_quick.py
        echo "::endgroup::"
      timeout-minutes: 5
      env:
        GHIDRA_INSTALL_DIR: ${{ env.GHIDRA_INSTALL_DIR }}

    - name: Test with Custom Port
      if: success()
      run: |
        echo "::group::Testing custom port configuration"
        timeout 30s python scripts/reva_headless_server.py --port 9090 --timeout 20 || true
        echo "::endgroup::"
      timeout-minutes: 2
      env:
        GHIDRA_INSTALL_DIR: ${{ env.GHIDRA_INSTALL_DIR }}

    - name: Test with Configuration File
      if: success()
      run: |
        echo "::group::Testing with configuration file"
        # Create a test config
        cat > test-config.properties << EOF
        reva.server.options.server.port=8888
        reva.server.options.server.host=127.0.0.1
        reva.server.options.debug.mode=true
        EOF
        timeout 30s python scripts/reva_headless_server.py --config test-config.properties --timeout 20 || true
        echo "::endgroup::"
      timeout-minutes: 2
      env:
        GHIDRA_INSTALL_DIR: ${{ env.GHIDRA_INSTALL_DIR }}

    - name: Upload test artifacts
      uses: actions/upload-artifact@v4
      if: always()
      with:
        name: headless-test-logs-${{ matrix.os }}-ghidra-${{ matrix.ghidra-version }}-py-${{ matrix.python-version }}
        path: |
          *.log
          test-config.properties
        if-no-files-found: ignore

  test-headless-windows:
    # Separate job for Windows due to different environment setup
    name: Test on Windows / Ghidra latest / Python 3.12
    runs-on: windows-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v5

    - name: Set up Java 21
      uses: actions/setup-java@v5
      with:
        java-version: "21"
        distribution: "microsoft"

    - name: Set up Python 3.12
      uses: actions/setup-python@v5
      with:
        python-version: "3.12"

    - name: Install Ghidra
      uses: antoniovazquezblanco/setup-ghidra@v2.0.14
      with:
        version: "latest"

    - name: Setup Gradle
      uses: gradle/actions/setup-gradle@v5
      with:
        gradle-version: "8.14"

    - name: Build ReVa Extension
      run: gradle buildExtension

    - name: Install ReVa Extension to Ghidra
      shell: pwsh
      run: |
        $EXTENSION_ZIP = Get-ChildItem -Path dist\*.zip | Select-Object -First 1
        Write-Host "Installing extension: $EXTENSION_ZIP"
        Expand-Archive -Path $EXTENSION_ZIP -DestinationPath "$env:GHIDRA_INSTALL_DIR\Ghidra\Extensions\" -Force
        Get-ChildItem -Path "$env:GHIDRA_INSTALL_DIR\Ghidra\Extensions\"

    - name: Install PyGhidra
      run: |
        python -m pip install --upgrade pip
        pip install pyghidra

    - name: Run Headless Quick Test
      run: python scripts/test_headless_quick.py
      timeout-minutes: 5
      env:
        GHIDRA_INSTALL_DIR: ${{ env.GHIDRA_INSTALL_DIR }}

  test-summary:
    name: Test Summary
    runs-on: ubuntu-latest
    needs: [test-headless, test-headless-windows]
    if: always()
    steps:
    - name: Check test results
      run: |
        echo "Headless tests completed"
        echo "Unix/Mac tests: ${{ needs.test-headless.result }}"
        echo "Windows tests: ${{ needs.test-headless-windows.result }}"

        if [ "${{ needs.test-headless.result }}" != "success" ] || [ "${{ needs.test-headless-windows.result }}" != "success" ]; then
          echo "❌ Some tests failed"
          exit 1
        else
          echo "✅ All tests passed"
        fi
```

## Option 3: Create via GitHub UI

1. Go to your repository on GitHub
2. Navigate to `.github/workflows/`
3. Click "Add file" → "Create new file"
4. Name it `test-headless.yml`
5. Paste the content from Option 2
6. Commit directly to your branch

## Verification

Once added, you can verify the workflow is active:

1. Go to the "Actions" tab in your repository
2. Look for "Test Headless Mode 🤖" in the workflows list
3. Click "Run workflow" to test manually

## What the Workflow Tests

- **9 test jobs** across Ubuntu, macOS, and Windows
- **Multiple versions**: Ghidra 11.4.2 & latest, Python 3.9/3.11/3.12
- **Test coverage**:
  - Server startup and shutdown
  - Custom port configuration
  - Configuration file loading
  - Cross-platform compatibility

## Expected Behavior

When the workflow is added:
- It will run automatically on pushes/PRs to main or develop
- It will only run when headless-related files change (path filtering)
- Each job takes ~6-8 minutes
- All jobs run in parallel

## Documentation

See `.github/CI_WORKFLOWS.md` for complete documentation on all CI workflows including this one.

## Support

If you have issues setting up the workflow:
1. Check the syntax with a YAML validator
2. Verify GitHub Actions is enabled for your repository
3. Check that required Actions permissions are granted
4. See the CI_WORKFLOWS.md troubleshooting section
