#!/usr/bin/env bash
set -ex

# Log to both stderr and log file
LOG_FILE="/tmp/reva-install-ghidra.log"
exec > >(tee -a "${LOG_FILE}") 2>&1

# Only run in remote (web) environments
if [ "${CLAUDE_CODE_REMOTE}" != "true" ]; then
    echo "[Install Ghidra Hook] Local environment detected. Skipping."
    exit 0
fi

echo "[Install Ghidra Hook] Installing Ghidra binary..."

# Install Ghidra latest
if [ ! -d "/opt/ghidra" ]; then
    echo "Downloading Ghidra (latest)..."

    # Get latest Ghidra release info using jq
    RELEASE_JSON=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest)
    GHIDRA_VERSION=$(echo "$RELEASE_JSON" | jq -r '.tag_name' | sed -E 's/Ghidra_([^_]+)_build/\1/')

    # Get the actual download URL from the assets
    GHIDRA_URL=$(echo "$RELEASE_JSON" | jq -r '.assets[] | select(.name | endswith(".zip") and contains("PUBLIC")) | .browser_download_url' | head -n 1)

    echo "Downloading Ghidra ${GHIDRA_VERSION} from ${GHIDRA_URL}..."

    # Download Ghidra
    if ! curl -fsSL "$GHIDRA_URL" -o /tmp/ghidra.zip 2>/dev/null; then
        echo "Download of ${GHIDRA_URL} failed"
        exit 2
    fi

    # Extract and move to /opt/ghidra
    unzip -q /tmp/ghidra.zip -d /opt/
    # Find the extracted directory (it will be something like ghidra_11.4_PUBLIC)
    GHIDRA_DIR=$(find /opt -maxdepth 1 -type d -name "ghidra_*_PUBLIC" | head -n 1)
    mv "$GHIDRA_DIR" /opt/ghidra
    rm /tmp/ghidra.zip

    echo "Ghidra installed to /opt/ghidra"
else
    echo "Ghidra binary already exists at /opt/ghidra"
fi

export GHIDRA_INSTALL_DIR="/opt/ghidra"

# Persist environment variables for all subsequent bash commands
if [ -n "$CLAUDE_ENV_FILE" ]; then
    echo 'export GHIDRA_INSTALL_DIR="/opt/ghidra"' >> "$CLAUDE_ENV_FILE"
fi

# Verify installation
echo "Verifying Ghidra installation..."
echo "GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR"
ls -la "$GHIDRA_INSTALL_DIR" | head -n 5

echo "[Install Ghidra Hook] Complete!"
