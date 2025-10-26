#!/usr/bin/env bash
set -e

# Log to both stderr and log file
LOG_FILE="/tmp/reva-claude-startup-hook.log"
exec > >(tee -a "${LOG_FILE}") 2>&1

# Only run in remote (web) environments
if [ "${CLAUDE_CODE_REMOTE}" != "true" ]; then
    echo "[SessionStart Hook] Local environment detected. Skipping remote setup."
    exit 0
fi

echo "[SessionStart Hook] Remote environment detected. Starting setup..."

echo "=== Setting up Claude Code Web Environment for ReVa ==="

GHIDRA_GIT="${CLAUDE_PROJECT_DIR}/../ghidra"

if [ ! -d "${GHIDRA_GIT}" ]; then
    git clone "https://github.com/NationalSecurityAgency/ghidra.git" "${GHIDRA_GIT}"
    echo "Cloned Ghidra to ${GHIDRA_GIT}"
    pushd "${GHIDRA_GIT}" > /dev/null
        echo "Fetching Ghidra Dependencies"
        gradle -I gradle/support/fetchDependencies.gradle
        gradle buildGhidra
        pushd "/opt" > /dev/null
            unzip "${GHIDRA_GIT}/build/dist/*.zip"
            mv ghidra_*_DEV /opt/ghidra
            echo "Built development Ghidra. Installed in /opt/ghidra"
        popd
    popd > /dev/null
fi

# Install Ghidra latest
if [ ! -d "/opt/ghidra" ]; then
    echo "Installing Ghidra (latest)..."

    # Get latest Ghidra release info using jq
    RELEASE_JSON=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest)
    GHIDRA_VERSION=$(echo "$RELEASE_JSON" | jq -r '.tag_name' | sed -E 's/Ghidra_([^_]+)_build/\1/')

    # Get the actual download URL from the assets
    GHIDRA_URL=$(echo "$RELEASE_JSON" | jq -r '.assets[] | select(.name | endswith(".zip") and contains("PUBLIC")) | .browser_download_url' | head -n 1)

    echo "Downloading Ghidra ${GHIDRA_VERSION} from ${GHIDRA_URL}..."

    # Download Ghidra
    if ! wget -q "$GHIDRA_URL" -O /tmp/ghidra.zip 2>/dev/null; then
        echo "Download of ${GHIDRA_URL} failed"
        exit 2
    fi

    # Extract and move to /opt/ghidra
    unzip -q /tmp/ghidra.zip -d /opt/
    # Find the extracted directory (it will be something like ghidra_11.4_PUBLIC)
    GHIDRA_DIR=$(find /opt -maxdepth 1 -type d -name "ghidra_*_PUBLIC" | head -n 1)
    mv "$GHIDRA_DIR" /opt/ghidra
    rm /tmp/ghidra.zip
fi

export GHIDRA_INSTALL_DIR="/opt/ghidra"

# Verify installations
echo "Verifying installations..."
java -version
gradle --version
echo "GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR"
ls -la "$GHIDRA_INSTALL_DIR" | head -n 5

# Persist environment variables for all subsequent bash commands
if [ -n "$CLAUDE_ENV_FILE" ]; then
    echo 'export GHIDRA_INSTALL_DIR="/opt/ghidra"' >> "$CLAUDE_ENV_FILE"
    echo 'export PATH="/opt/gradle/bin:$PATH"' >> "$CLAUDE_ENV_FILE"
fi

# Pre-fetch Gradle dependencies
pushd ${CLAUDE_PROJECT_DIR} > /dev/null
    echo "Pre-fetching Gradle dependencies..."
    gradle copyDependencies
popd > /dev/null

echo "=== Environment setup complete! ==="
echo ""
echo "Environment variables set:"
echo "  GHIDRA_INSTALL_DIR=/opt/ghidra"
echo "  ghidra cloned to ../ghidra"
echo ""
echo "Ready to build with: gradle buildExtension"
