# GitHub Actions Workflow Setup

## Overview

A GitHub Actions workflow file for automated testing has been created at:
```
.github/workflows/headless-tests.yml
```

However, due to GitHub App permissions, this file **cannot be pushed automatically** and must be added manually by a repository maintainer.

## Why Manual Setup Required

GitHub Apps (like the one used by Claude Code) don't have the `workflows` permission by default for security reasons. Workflows can execute arbitrary code, so GitHub requires explicit permission or manual addition by maintainers.

## Setup Instructions

### Option 1: Direct Commit (Maintainers Only)

If you have write access to the repository:

```bash
# Add the workflow file
git add .github/workflows/headless-tests.yml

# Commit directly to main
git commit -m "ci: Add headless mode testing workflow"

# Push to main
git push origin main
```

### Option 2: Via Pull Request from Personal Fork

1. **Fork the repository** to your personal account

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/reverse-engineering-assistant.git
   cd reverse-engineering-assistant
   ```

3. **Create a branch**:
   ```bash
   git checkout -b add-headless-workflow
   ```

4. **Copy the workflow file** from the Claude branch:
   ```bash
   git fetch origin claude/headless-mcp-server-setup-011CUTYFrR9EmoLNEwoEYXPw
   git checkout claude/headless-mcp-server-setup-011CUTYFrR9EmoLNEwoEYXPw -- .github/workflows/headless-tests.yml
   ```

5. **Commit and push**:
   ```bash
   git add .github/workflows/headless-tests.yml
   git commit -m "ci: Add headless mode testing workflow"
   git push origin add-headless-workflow
   ```

6. **Create PR** on GitHub from your fork to the main repository

### Option 3: Manual Copy

1. Navigate to `.github/workflows/headless-tests.yml` in the repository
2. Copy the entire contents
3. Create the file manually in your local repository
4. Commit and push using your personal credentials (not via GitHub App)

## Workflow File Location

The workflow file can be found in this PR at:
```
.github/workflows/headless-tests.yml
```

Or view it here:
https://github.com/cyberkaida/reverse-engineering-assistant/blob/claude/headless-mcp-server-setup-011CUTYFrR9EmoLNEwoEYXPw/.github/workflows/headless-tests.yml

## Workflow Configuration

Once added, the workflow will:

### Triggers
- Run on push to `main`, `develop`, or `claude/**` branches
- Run on pull requests to `main` or `develop`
- Can be manually triggered via GitHub Actions UI

### Jobs

1. **smoke-test** (5 minute timeout)
   - Quick validation of core functionality
   - Fastest feedback for CI

2. **java-integration-tests** (20 minute timeout)
   - Tests Java components
   - Runs `gradle test --tests "*Headless*"`

3. **python-e2e-tests** (30 minute timeout)
   - Full end-to-end testing
   - Tests complete MCP protocol stack

4. **test-summary**
   - Aggregates results from all jobs
   - Provides overall pass/fail status

### Features

- ✅ Parallel job execution for faster CI
- ✅ Gradle caching for faster builds
- ✅ Test artifact uploads for debugging
- ✅ Ghidra setup via antoniovazquezblanco/setup-ghidra@v2.0.5
- ✅ Python 3.10 with test dependencies
- ✅ Comprehensive timeout settings

## Verifying Setup

After adding the workflow:

1. **Check Workflow Exists**:
   - Go to repository → Actions tab
   - Look for "Headless Mode Tests" workflow

2. **Trigger Manual Run**:
   - Click on "Headless Mode Tests"
   - Click "Run workflow"
   - Select branch and run

3. **Check First Run**:
   - Should see three jobs running in parallel
   - All jobs should complete successfully
   - Test artifacts should be uploaded

## Expected Test Results

When working correctly:

```
smoke-test: ✅ PASSED (~2-3 minutes)
java-integration-tests: ✅ PASSED (~5-8 minutes)
python-e2e-tests: ✅ PASSED (~10-15 minutes)
test-summary: ✅ ALL TESTS PASSED
```

## Troubleshooting

### Workflow Not Appearing

**Problem**: Workflow doesn't show in Actions tab

**Solution**:
- Verify file is in `.github/workflows/` directory
- Check YAML syntax with: `yamllint .github/workflows/headless-tests.yml`
- Ensure file is committed to a branch with workflow triggers

### Tests Failing in CI

**Problem**: Tests pass locally but fail in CI

**Solution**:
1. Check GitHub Actions logs for specific error
2. Verify Ghidra version (workflow uses 11.4)
3. Check for timing issues (may need to increase timeouts)
4. Ensure all dependencies are in requirements files

### Permission Errors

**Problem**: Cannot push workflow file

**Solution**:
- Use one of the manual setup options above
- Contact repository maintainer for help

## Alternative: Running Tests Manually

If workflow setup is delayed, tests can be run manually:

### Locally

```bash
# Smoke test
python3 tests/smoke_test.py

# Java tests
gradle test --tests "*Headless*"

# Python tests
pytest tests/test_headless_e2e.py -v
```

### In Docker

```bash
docker run --rm \
  -v $(pwd):/workspace \
  -e GHIDRA_INSTALL_DIR=/opt/ghidra \
  ghidra-dev:latest \
  bash -c "cd /workspace && gradle buildExtension && python3 tests/smoke_test.py"
```

## Future Enhancements

Potential workflow improvements:
- [ ] Add test coverage reporting
- [ ] Add performance benchmarks
- [ ] Add nightly builds with full test suite
- [ ] Add multi-OS testing (Ubuntu, macOS)
- [ ] Add Ghidra version matrix testing
- [ ] Add cache cleanup for disk space management

## Support

For workflow setup issues:
1. Review this document
2. Check workflow file syntax
3. Consult GitHub Actions documentation
4. Open an issue on GitHub

## References

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Workflow Syntax](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions)
- [antoniovazquezblanco/setup-ghidra](https://github.com/antoniovazquezblanco/setup-ghidra)
