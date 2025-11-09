#!/usr/bin/env bash
set -ex

# Log to both stderr and log file
LOG_FILE="/tmp/reva-setup-gradle.log"
exec > >(tee -a "${LOG_FILE}") 2>&1

# Verify Java and Gradle
java -version
gradle --version