#!/bin/bash
# Note: SessionStart hooks should handle errors gracefully and not block

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

# Check if packages are already installed
echo "Checking for required packages..."
MISSING_PACKAGES=()
command -v wget >/dev/null 2>&1 || MISSING_PACKAGES+=(wget)
command -v unzip >/dev/null 2>&1 || MISSING_PACKAGES+=(unzip)
command -v java >/dev/null 2>&1 || MISSING_PACKAGES+=(openjdk-21-jdk)
command -v curl >/dev/null 2>&1 || MISSING_PACKAGES+=(curl)
command -v jq >/dev/null 2>&1 || MISSING_PACKAGES+=(jq)

if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
    echo "Installing missing packages: ${MISSING_PACKAGES[*]}..."
    # Try to update package lists, but don't fail if it has issues
    apt-get update -qq 2>/dev/null || echo "Warning: apt-get update had issues, continuing anyway..."
    apt-get install -y -qq "${MISSING_PACKAGES[@]}" 2>&1 | grep -v "^Get:" || echo "Warning: Some package installations may have failed"
else
    echo "All required packages already installed."
fi

# Install Gradle 8.14
if [ ! -d "/opt/gradle" ]; then
    echo "Installing Gradle 8.14..."
    if wget -q https://services.gradle.org/distributions/gradle-8.14-bin.zip -O /tmp/gradle.zip 2>/dev/null; then
        unzip -q /tmp/gradle.zip -d /opt/ 2>/dev/null && \
        mv /opt/gradle-8.14 /opt/gradle 2>/dev/null && \
        rm /tmp/gradle.zip
        echo "Gradle installed successfully."
    else
        echo "Warning: Failed to download/install Gradle"
    fi
else
    echo "Gradle already installed."
fi

# Add gradle to PATH if it exists
if [ -d "/opt/gradle/bin" ]; then
    export PATH="/opt/gradle/bin:$PATH"
fi

# Install Ghidra latest
if [ ! -d "/opt/ghidra" ]; then
    echo "Installing Ghidra (latest)..."

    # Get latest Ghidra release info using jq
    RELEASE_JSON=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest 2>/dev/null)

    if [ -n "$RELEASE_JSON" ]; then
        GHIDRA_VERSION=$(echo "$RELEASE_JSON" | jq -r '.tag_name' 2>/dev/null | sed -E 's/Ghidra_([^_]+)_build/\1/')
        # Get the actual download URL from the assets
        GHIDRA_URL=$(echo "$RELEASE_JSON" | jq -r '.assets[] | select(.name | endswith(".zip") and contains("PUBLIC")) | .browser_download_url' 2>/dev/null | head -n 1)
    fi

    if [ -z "$GHIDRA_VERSION" ] || [ -z "$GHIDRA_URL" ]; then
        echo "Failed to detect latest Ghidra version, using 11.4 as fallback"
        GHIDRA_VERSION="11.4"
        GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4_build/ghidra_11.4_PUBLIC_20241105.zip"
    fi

    echo "Downloading Ghidra ${GHIDRA_VERSION} from ${GHIDRA_URL}..."

    # Download Ghidra
    if wget -q "$GHIDRA_URL" -O /tmp/ghidra.zip 2>/dev/null; then
        # Extract and move to /opt/ghidra
        if unzip -q /tmp/ghidra.zip -d /opt/ 2>/dev/null; then
            # Find the extracted directory (it will be something like ghidra_11.4_PUBLIC)
            GHIDRA_DIR=$(find /opt -maxdepth 1 -type d -name "ghidra_*_PUBLIC" 2>/dev/null | head -n 1)
            if [ -n "$GHIDRA_DIR" ]; then
                mv "$GHIDRA_DIR" /opt/ghidra 2>/dev/null
                echo "Ghidra installed successfully."
            else
                echo "Warning: Failed to find extracted Ghidra directory"
            fi
        else
            echo "Warning: Failed to extract Ghidra archive"
        fi
        rm -f /tmp/ghidra.zip
    else
        echo "Warning: Failed to download Ghidra"
    fi
else
    echo "Ghidra already installed."
fi

# Set GHIDRA_INSTALL_DIR if Ghidra exists
if [ -d "/opt/ghidra" ]; then
    export GHIDRA_INSTALL_DIR="/opt/ghidra"
fi

# Verify installations
echo ""
echo "=== Verifying installations ==="
if command -v java >/dev/null 2>&1; then
    echo "✓ Java: $(java -version 2>&1 | head -n 1)"
else
    echo "✗ Java: Not found"
fi

if command -v gradle >/dev/null 2>&1; then
    echo "✓ Gradle: $(gradle --version 2>/dev/null | head -n 1)"
else
    echo "✗ Gradle: Not found"
fi

if [ -d "/opt/ghidra" ]; then
    echo "✓ Ghidra: Installed at $GHIDRA_INSTALL_DIR"
else
    echo "✗ Ghidra: Not installed"
fi

# Mark setup as complete
touch /tmp/.reva-env-setup-complete

# Persist environment variables for all subsequent bash commands
if [ -n "$CLAUDE_ENV_FILE" ]; then
    if [ -d "/opt/ghidra" ]; then
        echo 'export GHIDRA_INSTALL_DIR="/opt/ghidra"' >> "$CLAUDE_ENV_FILE"
    fi
    if [ -d "/opt/gradle/bin" ]; then
        echo 'export PATH="/opt/gradle/bin:$PATH"' >> "$CLAUDE_ENV_FILE"
    fi
fi

echo ""
echo "=== Environment setup complete! ==="
if [ -d "/opt/ghidra" ]; then
    echo "  GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR"
fi
if command -v gradle >/dev/null 2>&1; then
    echo "  Gradle available in PATH"
    echo ""
    echo "Ready to build with: gradle buildExtension"
fi
