#!/usr/bin/env bash
set -ex

# Log to both stderr and log file
LOG_FILE="/tmp/reva-setup-gradle.log"
exec > >(tee -a "${LOG_FILE}") 2>&1

# Only run in remote (web) environments
if [ "${CLAUDE_CODE_REMOTE}" != "true" ]; then
    echo "[Setup Gradle Hook] Local environment detected. Skipping."
    exit 0
fi

echo "[Setup Gradle Hook] Pre-fetching Gradle dependencies..."

# Verify Java and Gradle
java -version
gradle --version

# Pre-fetch Gradle dependencies
pushd "${CLAUDE_PROJECT_DIR}" > /dev/null
    echo "Fetching dependencies..."
    gradle copyDependencies
popd > /dev/null

echo "[Setup Gradle Hook] Complete!"
