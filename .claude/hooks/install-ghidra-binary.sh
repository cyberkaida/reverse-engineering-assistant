#!/usr/bin/env bash
set -ex

# Log to both stderr and log file
LOG_FILE="/tmp/reva-install-ghidra.log"
exec > >(tee -a "${LOG_FILE}") 2>&1

# Only run in remote (web) environments
if [ -n "${GHIDRA_INSTALL_DIR}" ]; then
    echo "GHIDRA_INSTALL_DIR is not set, use @reva-setup-installer to install the Ghidra binary distribution"
fi

# Persist environment variables for all subsequent bash commands
if [ -n "$CLAUDE_ENV_FILE" ]; then
    echo "Make sure to add an export command for GHIDRA_INSTALL_DIR to ${CLAUDE_ENV_FILE}"
fi
