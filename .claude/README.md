# Claude Code Web Environment Setup

This directory contains configuration and scripts for Claude Code Web environment.

## Files

- **settings.json** - Claude Code configuration including hooks and permissions
- **setup-environment.sh** - SessionStart hook script that configures the web environment

## SessionStart Hook

The `setup-environment.sh` script automatically runs when a Claude Code Web session starts and:

1. **Only runs in web environments** - Skips execution on local installations
2. **Installs required dependencies**:
   - OpenJDK 21 (Java Development Kit)
   - Gradle 8.14 (Build tool)
   - Ghidra latest release (Reverse engineering framework)
3. **Sets up environment variables**:
   - `GHIDRA_INSTALL_DIR=/opt/ghidra`
   - `PATH` includes `/opt/gradle/bin`
4. **Persists configuration** - Saves environment variables to `CLAUDE_ENV_FILE` for subsequent bash commands
5. **Caches setup** - Uses `/tmp/.reva-env-setup-complete` marker to skip reinstallation on session resume

## Installation Locations

- **Gradle**: `/opt/gradle`
- **Ghidra**: `/opt/ghidra`

## Environment Detection

The script uses `CLAUDE_CODE_REMOTE` environment variable to detect web environments and only runs there, ensuring it doesn't interfere with local development setups.

## Building

After environment setup completes, you can build the project with:

```bash
gradle buildExtension
```

The environment is configured to match the CI/CD pipeline defined in `.github/workflows/test-ghidra.yml`.
