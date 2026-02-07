#!/usr/bin/env bash
set -euo pipefail

# ReVa environment setup hook for Claude Code
# - Local: lightweight checks only
# - Remote (claude.ai/code): full automated Ghidra setup

GHIDRA_SOURCE_DIR="${CLAUDE_PROJECT_DIR}/../ghidra"
GHIDRA_INSTALL_BASE="${HOME}/.local/opt"
LOG_FILE="/tmp/reva-setup.log"

log() {
    echo "[ReVa Setup] $*" | tee -a "${LOG_FILE}"
}

# ─── Local mode ───────────────────────────────────────────────
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
    # Lightweight checks for local development
    if [ -d "${GHIDRA_SOURCE_DIR}" ]; then
        log "Ghidra source: ${GHIDRA_SOURCE_DIR}"
    else
        log "Ghidra source not found at ${GHIDRA_SOURCE_DIR}"
    fi

    if [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then
        log "Ghidra binary: ${GHIDRA_INSTALL_DIR}"
    else
        log "GHIDRA_INSTALL_DIR is not set"
    fi

    if command -v java &>/dev/null; then
        log "Java: $(java -version 2>&1 | head -1)"
    else
        log "Java not found"
    fi

    if command -v gradle &>/dev/null; then
        log "Gradle: $(gradle --version 2>&1 | grep '^Gradle' || echo 'unknown')"
    else
        log "Gradle not found"
    fi

    exit 0
fi

# ─── Remote mode (claude.ai/code) ─────────────────────────────
log "Remote environment detected, setting up Ghidra..."

# Clone Ghidra source (background)
clone_ghidra_source() {
    if [ -d "${GHIDRA_SOURCE_DIR}/.git" ]; then
        log "Ghidra source already exists at ${GHIDRA_SOURCE_DIR}"
        return 0
    fi
    log "Cloning Ghidra source (shallow)..."
    git clone --depth=1 --single-branch https://github.com/NationalSecurityAgency/ghidra.git "${GHIDRA_SOURCE_DIR}" 2>&1 | tail -1
    log "Ghidra source cloned to ${GHIDRA_SOURCE_DIR}"
}

# Download and extract Ghidra binary (background)
install_ghidra_binary() {
    # Check if already installed
    existing=$(find "${GHIDRA_INSTALL_BASE}" -maxdepth 1 -name "ghidra_*" -type d 2>/dev/null | head -1)
    if [ -n "${existing}" ]; then
        log "Ghidra binary already installed at ${existing}"
        echo "${existing}"
        return 0
    fi

    log "Querying GitHub for latest Ghidra release..."
    # Get the latest release asset URL for the zip (not the source archives)
    download_url=$(curl -fsSL "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest" \
        | grep -o '"browser_download_url": *"[^"]*"' \
        | grep -v 'src\|SHA-256\|source' \
        | head -1 \
        | sed 's/"browser_download_url": *"//;s/"//')

    if [ -z "${download_url}" ]; then
        log "ERROR: Could not determine Ghidra download URL"
        return 1
    fi

    filename=$(basename "${download_url}")
    log "Downloading ${filename}..."

    mkdir -p "${GHIDRA_INSTALL_BASE}"
    curl -fsSL -o "/tmp/${filename}" "${download_url}"

    log "Extracting ${filename}..."
    unzip -q -o "/tmp/${filename}" -d "${GHIDRA_INSTALL_BASE}"
    rm -f "/tmp/${filename}"

    installed=$(find "${GHIDRA_INSTALL_BASE}" -maxdepth 1 -name "ghidra_*" -type d | head -1)
    log "Ghidra binary installed at ${installed}"
    echo "${installed}"
}

# Run both downloads in parallel
CLONE_LOG="/tmp/reva-clone.log"
BINARY_LOG="/tmp/reva-binary.log"

clone_ghidra_source > "${CLONE_LOG}" 2>&1 &
CLONE_PID=$!

install_ghidra_binary > "${BINARY_LOG}" 2>&1 &
BINARY_PID=$!

# Wait for both to complete
CLONE_OK=true
BINARY_OK=true

if ! wait ${CLONE_PID}; then
    CLONE_OK=false
    log "ERROR: Ghidra source clone failed:"
    cat "${CLONE_LOG}" >> "${LOG_FILE}"
fi
cat "${CLONE_LOG}" | while read -r line; do log "(source) ${line}"; done

if ! wait ${BINARY_PID}; then
    BINARY_OK=false
    log "ERROR: Ghidra binary install failed:"
    cat "${BINARY_LOG}" >> "${LOG_FILE}"
fi
cat "${BINARY_LOG}" | while read -r line; do log "(binary) ${line}"; done

# Extract the install dir from the binary log (last line is the path)
GHIDRA_DIR=$(tail -1 "${BINARY_LOG}")

if [ "${BINARY_OK}" = true ] && [ -d "${GHIDRA_DIR}" ]; then
    export GHIDRA_INSTALL_DIR="${GHIDRA_DIR}"
    log "GHIDRA_INSTALL_DIR=${GHIDRA_INSTALL_DIR}"

    # Persist for all subsequent Claude Code bash commands
    if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
        echo "GHIDRA_INSTALL_DIR=${GHIDRA_INSTALL_DIR}" >> "${CLAUDE_ENV_FILE}"
        log "Persisted GHIDRA_INSTALL_DIR to ${CLAUDE_ENV_FILE}"
    fi
else
    log "WARNING: Ghidra binary not available, build will fail"
fi

# Warm gradle dependency cache
if [ "${BINARY_OK}" = true ] && command -v gradle &>/dev/null; then
    log "Warming gradle dependency cache..."
    cd "${CLAUDE_PROJECT_DIR}"
    gradle dependencies --quiet 2>&1 | tail -3
    log "Gradle dependencies cached"
fi

if [ "${CLONE_OK}" = false ] || [ "${BINARY_OK}" = false ]; then
    log "Setup completed with errors (check ${LOG_FILE})"
    exit 1
fi

log "Setup complete"
