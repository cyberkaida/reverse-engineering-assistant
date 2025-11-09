#!/usr/bin/env bash
set -ex

# Log to both stderr and log file
LOG_FILE="/tmp/reva-clone-ghidra.log"
exec > >(tee -a "${LOG_FILE}") 2>&1

GHIDRA_GIT=$(readlink -f "${CLAUDE_PROJECT_DIR}/../ghidra")

if [ ! -d "${GHIDRA_GIT}" ]; then
    echo "The ghidra code is not at ${GHIDRA_GIT} use the @reva-setup-installer to fix this"
else
    echo "Ghidra source already exists at ${GHIDRA_GIT}"
fi
