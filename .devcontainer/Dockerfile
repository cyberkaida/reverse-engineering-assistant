FROM mcr.microsoft.com/devcontainers/base:ubuntu

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV GRADLE_VERSION=9.0
ENV PATH=$PATH:/opt/ghidra:/opt/gradle/bin

# Install basic dependencies including build tools for Ghidra
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    git \
    build-essential \
    python3 \
    python3-pip \
    python3-venv \
    openjdk-21-jdk \
    bison \
    flex \
    && rm -rf /var/lib/apt/lists/*

# Install Gradle
RUN wget -q https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip -O /tmp/gradle.zip && \
    unzip -q /tmp/gradle.zip -d /opt && \
    mv /opt/gradle-${GRADLE_VERSION} /opt/gradle && \
    rm /tmp/gradle.zip

# Create ghidra directories
RUN mkdir -p /opt/ghidra /opt/ghidra-src

# Create a Python virtual environment and install MCP SDK
RUN python3 -m venv /opt/venv && \
    . /opt/venv/bin/activate && \
    pip install --upgrade pip setuptools wheel && \
    pip install mcp pytest requests

# Set up vscode user permissions
RUN chown -R vscode:vscode /opt/ghidra /opt/ghidra-src /opt/gradle /opt/venv

# Switch to vscode user
USER vscode

# Add virtual environment to PATH for vscode user
ENV PATH="/opt/venv/bin:${PATH}"

# Verify installations
RUN java -version && gradle --version && python3 --version

WORKDIR /workspaces/reverse-engineering-assistant