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
apt-get install -y -qq wget unzip openjdk-21-jdk curl > /dev/null 2>&1

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

    # Get latest Ghidra release info
    GHIDRA_VERSION=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest | grep '"tag_name":' | sed -E 's/.*"Ghidra_([^"]+)_build".*/\1/')

    if [ -z "$GHIDRA_VERSION" ]; then
        echo "Failed to detect latest Ghidra version, using 11.4 as fallback"
        GHIDRA_VERSION="11.4"
    fi

    echo "Downloading Ghidra ${GHIDRA_VERSION}..."
    GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_$(date +%Y%m%d).zip"

    # Try to download, if fails use a known good version
    if ! wget -q "$GHIDRA_URL" -O /tmp/ghidra.zip 2>/dev/null; then
        echo "Download failed, trying Ghidra 11.4..."
        wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4_build/ghidra_11.4_PUBLIC_20241105.zip" -O /tmp/ghidra.zip
        GHIDRA_VERSION="11.4"
    fi

    unzip -q /tmp/ghidra.zip -d /opt/
    mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra
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

echo "=== Environment setup complete! ==="
echo ""
echo "Environment variables set:"
echo "  GHIDRA_INSTALL_DIR=/opt/ghidra"
echo "  PATH includes /opt/gradle/bin"
echo ""
echo "Ready to build with: gradle buildExtension"
