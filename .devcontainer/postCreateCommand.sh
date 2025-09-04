#!/bin/bash

# Post-create command script for ReVa devcontainer
set -e

echo "🚀 Setting up ReVa development environment..."

# Ensure we're in the correct directory
cd /workspaces/reverse-engineering-assistant

# Verify installations
echo "📋 Verifying installations..."
echo "Java version:"
java -version
echo "Gradle version:"
gradle --version
echo "Python version:"
python3 --version

# Clone and build Ghidra from source if not already done
if [ ! -d "/opt/ghidra-src/.git" ]; then
    echo "📦 Cloning Ghidra source code..."
    git clone https://github.com/NationalSecurityAgency/ghidra.git /opt/ghidra-src
fi

if [ ! -f "/opt/ghidra/ghidraRun" ]; then
    echo "🔨 Building Ghidra from source (this may take a while)..."
    cd /opt/ghidra-src
    gradle --no-daemon -I gradle/support/fetchDependencies.gradle init
    gradle --no-daemon buildGhidra
    
    echo "📦 Extracting Ghidra build..."
    unzip -q build/dist/ghidra_*_DEV_*.zip -d /opt
    mv /opt/ghidra_*_DEV* /opt/ghidra
    chmod +x /opt/ghidra/ghidraRun
    
    cd /workspaces/reverse-engineering-assistant
    echo "✅ Ghidra build complete!"
else
    echo "✅ Ghidra is already built and available"
fi

# Check if GHIDRA_INSTALL_DIR is properly set
if [ -z "$GHIDRA_INSTALL_DIR" ]; then
    echo "❌ GHIDRA_INSTALL_DIR is not set!"
    exit 1
fi

if [ ! -d "$GHIDRA_INSTALL_DIR" ]; then
    echo "❌ Ghidra directory does not exist at $GHIDRA_INSTALL_DIR"
    exit 1
fi

echo "✅ GHIDRA_INSTALL_DIR is properly set to: $GHIDRA_INSTALL_DIR"
echo "📂 Ghidra source is available at: /opt/ghidra-src"

# Activate Python virtual environment
echo "🐍 Activating Python virtual environment..."
source /opt/venv/bin/activate

# Install any additional Python dependencies if requirements files exist
if [ -f "cli/requirements.txt" ]; then
    echo "📦 Installing Python dependencies from cli/requirements.txt..."
    pip install -r cli/requirements.txt
fi

if [ -f "requirements.txt" ]; then
    echo "📦 Installing Python dependencies from requirements.txt..."
    pip install -r requirements.txt
fi

# Verify MCP SDK is installed
echo "🔧 Verifying MCP SDK installation..."
python3 -c "import mcp; print('✅ MCP SDK is installed')" || echo "❌ MCP SDK installation failed"

# Build the project
echo "🔨 Building ReVa extension..."
if gradle clean build; then
    echo "✅ Build successful!"
else
    echo "❌ Build failed!"
    exit 1
fi

# Run tests to verify everything is working
echo "🧪 Running unit tests..."
if gradle test --info; then
    echo "✅ Unit tests passed!"
else
    echo "⚠️ Unit tests failed - this might be expected in some environments"
fi

# Create Extensions directory if it doesn't exist
mkdir -p "$GHIDRA_INSTALL_DIR/Ghidra/Extensions"

echo "🎉 Setup complete! You can now:"
echo "  • Build the extension with: gradle"
echo "  • Install the extension with: gradle install"
echo "  • Run tests with: gradle test"
echo "  • Run integration tests with: gradle integrationTest --info"
echo "  • Start developing ReVa!"