# GitHub Actions CI Workflows

This document describes the CI/CD workflows for the ReVa project.

## Workflows Overview

### 1. `test-ghidra.yml` - Main Extension Tests

**Triggers**: Push/PR to main or develop branches

**What it does**:
- Tests ReVa as a Ghidra extension (GUI mode)
- Runs unit tests and integration tests
- Tests on multiple Ghidra versions (12.0, latest)
- Includes lint checks and CodeQL security analysis

**Jobs**:
- `test` - Runs gradle unit and integration tests
- `lint` - Code compilation checks
- `codeql` - Security vulnerability scanning

**Duration**: ~10-15 minutes per matrix job

### 2. `test-headless.yml` - Headless Mode Tests

**Triggers**:
- Push/PR to main or develop (when headless files change)
- Manual workflow dispatch

**What it does**:
- Tests ReVa in headless Ghidra mode via pyghidra
- Runs Python-based headless server tests
- Tests on multiple OS (Ubuntu, macOS, Windows)
- Tests on multiple Ghidra versions (12.0, latest)
- Tests on multiple Python versions (3.9, 3.11, 3.12)

**Jobs**:
- `test-headless` - Unix/Mac matrix testing
- `test-headless-windows` - Windows-specific testing
- `test-summary` - Aggregates results

**Duration**: ~5-8 minutes per matrix job

**Test Coverage**:
1. Quick smoke test (start/stop/verify)
2. Custom port configuration
3. Configuration file loading
4. Cross-platform compatibility

### 3. `publish-ghidra.yml` - Release Publishing

**Triggers**: Manual or release tags

**What it does**:
- Builds and publishes release artifacts
- Creates GitHub releases
- Uploads extension zip files

**Duration**: ~5 minutes

### 4. `claude.yml` - Claude Code Integration

**Triggers**: Varies (project-specific)

**What it does**:
- Claude Code specific automation
- May include code review, documentation, etc.

## Test Matrix Strategy

### Main Extension Tests (`test-ghidra.yml`)

```
Matrix:
  OS: ubuntu-latest
  Ghidra: [12.0, latest]

Total: 2 jobs
```

### Headless Mode Tests (`test-headless.yml`)

```
Unix/Mac Matrix:
  OS: [ubuntu-latest, macos-latest]
  Ghidra: [12.0, latest]
  Python: [3.9, 3.11, 3.12]
  Excludes: (12.0 + older Python versions)

  Total: 8 jobs (2 OS × 2 Ghidra × 2 Python combinations)

Windows:
  OS: windows-latest
  Ghidra: latest
  Python: 3.12

  Total: 1 job

Grand Total: 9 jobs
```

## Workflow Optimization

### Path Filtering

The headless workflow only runs when relevant files change:
- `src/main/java/reva/headless/**`
- `src/main/java/reva/plugin/config/**`
- `scripts/**`
- `config/**`
- Configuration files

This reduces unnecessary CI runs when unrelated files change.

### Matrix Exclusions

The headless workflow excludes some combinations to reduce CI time:
- Only tests older Python versions (3.9, 3.11) on latest Ghidra
- Tests Python 3.12 on all Ghidra versions
- Balances coverage vs. execution time

### Fail-Fast: Disabled

Both test workflows use `fail-fast: false` to ensure all matrix jobs complete even if some fail. This provides complete test coverage visibility.

## Running Workflows

### Automatic Triggers

Both workflows automatically run on:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches

### Manual Triggers

The headless workflow can be manually triggered:

1. Go to Actions tab in GitHub
2. Select "Test Headless Mode 🤖"
3. Click "Run workflow"
4. Select branch
5. Click "Run workflow"

This is useful for:
- Testing on feature branches
- Debugging CI issues
- Validating fixes

## Debugging Failed Tests

### View Test Results

1. Click on failed workflow run
2. Click on failed job
3. Expand failing step to see logs

### Download Artifacts

Failed runs upload artifacts:
- Test results (XML/HTML)
- Log files
- Configuration files

Download via workflow run page → Artifacts section

### Common Issues

**Issue: PyGhidra import fails**
```
ImportError: No module named 'pyghidra'
```
**Solution**: Check pip install step completed successfully

**Issue: Ghidra not found**
```
GHIDRA_INSTALL_DIR not set
```
**Solution**: Check setup-ghidra action completed successfully

**Issue: Timeout**
```
Error: The operation was canceled.
```
**Solution**: Increase timeout or check for hanging processes

**Issue: Port already in use**
```
BindException: Address already in use
```
**Solution**: Tests should use different ports or proper cleanup

## Performance Benchmarks

### Expected Durations

| Workflow | Jobs | Avg Time/Job | Total Time (parallel) |
|----------|------|--------------|----------------------|
| test-ghidra.yml | 2 + lint + codeql | 12 min | ~15 min |
| test-headless.yml | 9 | 6 min | ~8 min |
| publish-ghidra.yml | 1 | 5 min | ~5 min |

### Parallelization

Both test workflows run matrix jobs in parallel, significantly reducing total CI time compared to sequential execution.

## CI/CD Best Practices

### For Contributors

1. **Run tests locally first** when possible
   ```bash
   # Main tests
   gradle test
   gradle integrationTest

   # Headless tests
   python scripts/test_headless_quick.py
   ```

2. **Use draft PRs** for work in progress to avoid unnecessary CI runs

3. **Path filtering** means not all changes trigger all workflows

4. **Check CI status** before requesting review

### For Maintainers

1. **Review test results** before merging PRs

2. **Monitor CI performance** and adjust matrix if needed

3. **Update workflows** when:
   - New Ghidra version released
   - Python version EOL
   - Dependencies updated

4. **Keep documentation updated** when changing workflows

## Troubleshooting CI

### Workflow doesn't trigger

**Check**:
- Branch name matches trigger pattern
- File paths match path filter
- Workflow file is valid YAML

### Tests pass locally but fail in CI

**Common causes**:
- Environment differences (OS, versions)
- Missing dependencies in CI
- Timeout too short
- Race conditions

**Debug**:
1. Check workflow environment matches local
2. Add debug logging to tests
3. Increase timeouts
4. Use workflow dispatch to test manually

### Long CI times

**Optimization options**:
1. Reduce matrix size
2. Add path filters
3. Use caching for dependencies
4. Increase parallelization

## Monitoring

### Workflow Status Badge

Add to README:
```markdown
![Test Headless Mode](https://github.com/your-org/reverse-engineering-assistant/actions/workflows/test-headless.yml/badge.svg)
```

### Notifications

GitHub sends notifications on:
- Workflow failures (to committer)
- Status changes (if watching repo)

Configure in GitHub settings → Notifications

## Future Enhancements

Potential workflow improvements:

1. **Performance Tests**
   - Benchmark startup times
   - Memory usage profiling
   - API response times

2. **E2E Tests**
   - Full MCP client integration
   - Real binary analysis
   - Multi-tool workflows

3. **Docker Tests**
   - Build Docker image
   - Test container deployment
   - Docker Compose orchestration

4. **Coverage Reports**
   - JaCoCo for Java
   - Coverage.py for Python
   - Combined coverage metrics

5. **Automated Releases**
   - Version bumping
   - Changelog generation
   - Asset uploads

## References

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [setup-ghidra Action](https://github.com/antoniovazquezblanco/setup-ghidra)
- [Gradle Actions](https://github.com/gradle/actions)
- [PyGhidra Documentation](https://github.com/dod-cyber-crime-center/pyghidra)
