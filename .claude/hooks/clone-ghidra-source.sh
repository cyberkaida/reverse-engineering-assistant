#!/usr/bin/env bash
set -ex

# Log to both stderr and log file
LOG_FILE="/tmp/reva-clone-ghidra.log"
exec > >(tee -a "${LOG_FILE}") 2>&1

# Only run in remote (web) environments
if [ "${CLAUDE_CODE_REMOTE}" != "true" ]; then
    echo "[Clone Ghidra Hook] Local environment detected. Skipping."
    exit 0
fi

echo "[Clone Ghidra Hook] Cloning Ghidra source..."

GHIDRA_GIT=$(readlink -f "${CLAUDE_PROJECT_DIR}/../ghidra")

if [ ! -d "${GHIDRA_GIT}" ]; then
    git clone --depth 1 "https://github.com/NationalSecurityAgency/ghidra.git" "${GHIDRA_GIT}"
    echo "Cloned Ghidra to ${GHIDRA_GIT}"
    gradle -I gradle/support/fetchDependencies.gradle
else
    echo "Ghidra source already exists at ${GHIDRA_GIT}"
fi

echo "[Clone Ghidra Hook] Complete!"
