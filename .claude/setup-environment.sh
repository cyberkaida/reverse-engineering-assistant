#!/bin/bash
set -e

# Only run in remote (web) environments
if [ "$CLAUDE_CODE_REMOTE" != "true" ]; then
    exit 0
fi

echo "=== Setting up Claude Code Web Environment for ReVa ==="

# Check if already set up
if [ -f "/tmp/.reva-env-setup-complete" ]; then
    echo "Environment already configured. Skipping setup."
    # Persist environment variables
    if [ -n "$CLAUDE_ENV_FILE" ]; then
        echo 'export GHIDRA_INSTALL_DIR="/opt/ghidra"' >> "$CLAUDE_ENV_FILE"
        echo 'export PATH="/opt/gradle/bin:$PATH"' >> "$CLAUDE_ENV_FILE"
    fi
    exit 0
fi

echo "Installing required packages..."
apt-get update -qq
apt-get install -y -qq wget unzip openjdk-21-jdk curl jq > /dev/null 2>&1

# Install Gradle 8.14
if [ ! -d "/opt/gradle" ]; then
    echo "Installing Gradle 8.14..."
    wget -q https://services.gradle.org/distributions/gradle-8.14-bin.zip -O /tmp/gradle.zip
    unzip -q /tmp/gradle.zip -d /opt/
    mv /opt/gradle-8.14 /opt/gradle
    rm /tmp/gradle.zip
fi
export PATH="/opt/gradle/bin:$PATH"

# Install Ghidra latest
if [ ! -d "/opt/ghidra" ]; then
    echo "Installing Ghidra (latest)..."

    # Get latest Ghidra release info using jq
    RELEASE_JSON=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest)
    GHIDRA_VERSION=$(echo "$RELEASE_JSON" | jq -r '.tag_name' | sed -E 's/Ghidra_([^_]+)_build/\1/')

    # Get the actual download URL from the assets
    GHIDRA_URL=$(echo "$RELEASE_JSON" | jq -r '.assets[] | select(.name | endswith(".zip") and contains("PUBLIC")) | .browser_download_url' | head -n 1)

    if [ -z "$GHIDRA_VERSION" ] || [ -z "$GHIDRA_URL" ]; then
        echo "Failed to detect latest Ghidra version, using 11.4 as fallback"
        GHIDRA_VERSION="11.4"
        GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4_build/ghidra_11.4_PUBLIC_20241105.zip"
    fi

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

# Mark setup as complete
touch /tmp/.reva-env-setup-complete

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
echo "  PATH includes /opt/gradle/bin"
echo ""
echo "Ready to build with: gradle buildExtension"
