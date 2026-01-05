# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ReVa (Reverse Engineering Assistant) is a Ghidra extension that provides a Model Context Protocol (MCP) server for AI-assisted reverse engineering. It supports both GUI and headless modes, with streamable HTTP transport for direct connections and stdio transport for Claude CLI integration.

## Build and Test Commands

### Java Extension (Ghidra Plugin)
```bash
# Set Ghidra installation directory first
export GHIDRA_INSTALL_DIR=/path/to/ghidra

# Build the extension
gradle

# Install directly to Ghidra's extension directory
gradle install

# Java unit tests (no Ghidra environment)
gradle test --info

# Integration tests (require GUI/headed environment, fork=1)
gradle integrationTest --info

# Run specific test class
gradle integrationTest --tests "*DecompilerToolProviderIntegrationTest" --info

# Run specific test method
gradle test --tests "*AddressUtilTest.testFormatAddress" --info
```

**Important**: Use `gradle` directly, NOT gradle wrapper (`./gradlew`)

### Python CLI and Tests
```bash
# Setup Python environment with uv
uv sync

# Run all Python tests
uv run pytest

# Run specific test file
uv run pytest tests/test_cli.py -v

# Run tests by marker
uv run pytest -m unit      # Fast unit tests with mocks
uv run pytest -m integration  # Integration tests with PyGhidra
uv run pytest -m e2e       # End-to-end subprocess tests

# Run CLI locally
uv run mcp-reva --verbose

# Install CLI for development
uv pip install -e .
```

### Running the Complete Test Suite

**Run all Java unit tests:**
```bash
gradle test
```

**Run all Java integration tests:**
```bash
gradle integrationTest
```

**Run all Python tests (unit, integration, and e2e):**
```bash
uv run pytest
```

**Run specific Python test categories:**
```bash
uv run pytest -m unit         # Unit tests only
uv run pytest -m integration  # Integration tests only
uv run pytest -m e2e          # End-to-end tests only
```

**Run complete test suite (Java + Python):**
```bash
gradle test && gradle integrationTest && uv run pytest
```

### Running ReVa

**GUI Mode (Ghidra Plugin):**
1. Start Ghidra and open a project
2. Server runs on http://localhost:8080/mcp/message (streamable transport)

**Headless Mode (Python Script):**
```bash
python scripts/reva_headless_server.py --wait
```

**Claude CLI Mode (Stdio Transport):**
```bash
# Add to Claude CLI
claude mcp add ReVa -- mcp-reva

# Run manually for testing
mcp-reva --verbose
```

## Project Structure

### Architecture Overview
ReVa has three operational modes sharing the same core:

**1. GUI Mode (Ghidra Plugin)**
```
RevaApplicationPlugin → McpServerManager → Jetty (HTTP) → MCP Tools/Resources
                     ↓
                ConfigManager (ToolOptions backend)
```

**2. Headless Mode (PyGhidra Script)**
```
RevaHeadlessLauncher → McpServerManager → Jetty (HTTP) → MCP Tools/Resources
                     ↓
                ConfigManager (File/InMemory backend)
```

**3. Claude CLI Mode (Stdio Transport)**
```
mcp-reva CLI → PyGhidra → ReVaLauncher → Jetty (HTTP)
            ↓                           ↓
    StdioBridge (async) ←────────→ MCP Tools/Resources
            ↓
    ProjectManager (temp project lifecycle)
```

### Core Java Components
- **Foundation Layer** (`util/`) - AddressUtil, ProgramLookupUtil, DataTypeParserUtil, etc.
- **Plugin Layer** (`plugin/`) - ConfigManager, RevaProgramManager, Ghidra lifecycle
- **Server Layer** (`server/`) - McpServerManager, Jetty server, streamable transport
- **Tool Layer** (`tools/`) - 17 specialized tool packages (decompiler, functions, strings, callgraph, dataflow, etc.)
- **Resource Layer** (`resources/`) - Read-only MCP resource providers
- **Headless Layer** (`headless/`) - RevaHeadlessLauncher for PyGhidra integration

### Python CLI Components
- **CLI Entry** (`src/reva_cli/__main__.py`) - mcp-reva command, blocking initialization
- **Launcher** (`launcher.py`) - ReVa server lifecycle (wraps Java RevaHeadlessLauncher)
- **Stdio Bridge** (`stdio_bridge.py`) - Async MCP stdio ↔ HTTP proxy
- **Project Manager** (`project_manager.py`) - Temporary project creation/cleanup

### Directory Structure
```
src/main/java/reva/          # Java extension code
  ├── util/                  # Foundational utilities (ALWAYS use these!)
  ├── plugin/                # ConfigManager, plugin lifecycle
  ├── server/                # McpServerManager, Jetty
  ├── tools/                 # 17 tool provider packages
  ├── resources/             # MCP resource providers
  ├── headless/              # RevaHeadlessLauncher
  └── ui/                    # Optional GUI components
src/test/                    # Java unit tests (no Ghidra)
src/test.slow/               # Java integration tests (GUI required, fork=1)
src/reva_cli/                # Python CLI for stdio transport
tests/                       # Python tests (pytest)
scripts/                     # Helper scripts (reva_headless_server.py)
```

### Package-Level Documentation
Each major package contains its own CLAUDE.md file with detailed implementation guidance:
- **Essential Infrastructure**: `util/`, `plugin/`, `server/` - Core systems documentation
- **Tool Providers**: Each of the 17 tool packages has comprehensive implementation guides
- **Supporting Systems**: `resources/`, `services/`, `ui/` - Specialized component documentation

### Tool Provider Categories
- **Core Analysis**: decompiler, functions, strings, symbols, xrefs, memory
- **Data & Types**: data, datatypes, structures
- **Advanced Analysis**: callgraph, dataflow, constants, vtable, imports
- **Annotations**: comments, bookmarks
- **Project Management**: project

## Development Guidelines

### Testing
- Integration tests validate actual Ghidra program state changes, not just MCP responses
- Use `Function.getParameters()` and `Function.getAllVariables()` to validate variable changes
- Use `DataType.isEquivalent()` to compare datatypes before/after changes
- Use JUnit 4 (avoid JUnit 5 annotations like `@ParameterizedTest`)
- **You are not finished until all tests pass!**

### Address Formatting
Always use `AddressUtil.formatAddress(address)` for consistent address formatting in JSON output:
```java
import reva.util.AddressUtil;
// Returns "0x" + address.toString()
String formatted = AddressUtil.formatAddress(address);
```

### Decompiler Tool Implementation
When adding new tools to DecompilerToolProvider:
1. Create `register[ToolName]Tool()` method following existing patterns
2. Call it from `registerTools()` method
3. Use `HighFunctionDBUtil.updateDBVariable()` for persisting variable changes
4. Follow the `rename-variables` pattern for consistency
5. Handle decompilation with proper error handling and transaction management

### Critical Utility Usage
**ALWAYS use ReVa utilities instead of direct Ghidra APIs** for consistency:
- `AddressUtil.formatAddress()` - **REQUIRED** for all address formatting in JSON output
- `ProgramLookupUtil.getValidatedProgram()` - **REQUIRED** for program resolution with helpful errors
- `AbstractToolProvider.getProgramFromArgs()` - **REQUIRED** for tool parameter extraction
- `DataTypeParserUtil.parseDataTypeObjectFromString()` - Parse datatype strings ("char*", "int[10]")
- `HighFunctionDBUtil.updateDBVariable()` - **REQUIRED** for persisting variable changes
- `SymbolUtil.isDefaultSymbolName()` - Filter Ghidra-generated names

### Key APIs
- `DecompInterface` - Get decompiled function and high-level representation (always dispose!)
- `LocalSymbolMap.getSymbols()` returns Iterator (use while loop, not for-each)
- `AbstractToolProvider` helper methods - getString, getInt, getOptionalInt, getOptionalBoolean

### Common Patterns
- Always use transactions when modifying program state
- Handle decompilation failures gracefully with try-catch and timeouts
- Validate parameters before processing using AbstractToolProvider helpers
- Return structured JSON with success flags and program metadata
- Wrap parameter extraction in try-catch blocks to convert IllegalArgumentException to error responses
- Use pagination for large datasets (functions, symbols, strings, etc.)

## MCP Server Configuration

### Transport Modes

**HTTP Streamable (GUI & Headless modes):**
- Default port: 8080
- Endpoint: http://localhost:8080/mcp/message
- Transport: HttpServletStreamableServerTransportProvider
- Used by: GUI plugin, headless scripts, direct HTTP clients

**Stdio (Claude CLI mode):**
- Uses stdin/stdout for MCP protocol
- StdioBridge proxies to local HTTP server (random port)
- Automatic project creation/cleanup
- Used by: `mcp-reva` command, Claude CLI

### Configuration Management
- **GUI Mode**: ConfigManager with ToolOptions backend (persists in Ghidra settings)
- **Headless Mode**: ConfigManager with File or InMemory backend
- **Claude CLI Mode**: Uses random port, minimal config (optimized for stdio)

## Claude Code Marketplace Skills

ReVa includes Claude Code marketplace plugins (`/ReVa/skills/`) for common reverse engineering workflows:
- **binary-triage**: Initial binary survey - memory layout, strings, imports, suspicious indicators
- **deep-analysis**: Focused investigation of specific functions/behaviors with iterative refinement
- **ctf-rev**: CTF reverse engineering challenges - crackmes, key validators, algorithm recovery
- **ctf-pwn**: CTF binary exploitation - buffer overflows, format strings, ROP chains
- **ctf-crypto**: CTF cryptography challenges - weak crypto, key extraction, algorithm identification

Install via: `claude plugin marketplace add cyberkaida/reverse-engineering-assistant`

## External Dependencies

### Java
- Ghidra: 12.0+ (source at `../ghidra`)
- Java: 21+
- MCP SDK: io.modelcontextprotocol.sdk v0.17.0 (BOM-managed)
- Jackson: 2.20.x (force-resolved for MCP SDK compatibility)
- Jetty: 11.0.26 (embedded servlet server)

### Python
- Python: 3.10+ (managed via uv)
- PyGhidra: 3.0.0+ (Ghidra initialization)
- MCP: Latest (stdio transport implementation)
- httpx + httpx-sse: MCP HTTP client (for StdioBridge)

## Program Identification
- **ALWAYS use `programPath` for program identifiers** in both tool inputs and outputs
- The value is the Ghidra project pathname (e.g., "/Hatchery.exe" or "/folder/program.exe")
- Never use alternative field names like `path`, `name`, or `executable` for program identification
- Tools that list programs return a `programPath` field that can be directly used as input to other tools
- All tools use `ProgramLookupUtil.getValidatedProgram()` for consistent program resolution and helpful error messages
- When a program cannot be found, the error message will include suggestions of available programs

## Recent Feature Additions

Notable tool capabilities added recently:
- **Function tagging**: `function-tags` tool for categorizing functions during analysis
- **Bulk decompilation**: Decompile all callers/referencers of a function in one call
- **Undefined function discovery**: Find and create functions from call/data references
- **Call graph analysis**: Trace call paths, find callers/callees
- **Data flow analysis**: Track data dependencies and value propagation
- **Constant search**: Find hardcoded values (magic numbers, crypto constants)
- **Vtable analysis**: Analyze virtual function tables for C++ binaries
- **Import/export analysis**: Detailed import/export enumeration
- **Verbose mode**: Many tools support `verbose` parameter for additional context
- **Signature-only decompilation**: Get function signatures without full decompilation

## Architecture Decision Records

### MCP Implementation
- **Transport (Java)**: HttpServletStreamableServerTransportProvider (NOT SSE) via Jetty
- **Transport (Python)**: Stdio ↔ HTTP proxy via async StdioBridge
- **Server**: Embedded Jetty servlet server, thread-safe with ConcurrentHashMap
- **Tool Pattern**: AbstractToolProvider base class with consistent error handling
- **Config Pattern**: Backend abstraction (ToolOptions/File/InMemory) for multi-mode support

### Python CLI Design
- **Blocking Init**: PyGhidra/server startup before asyncio.run() to avoid event loop blocking
- **Stdio Bridge**: Async MCP client/server proxying HTTP (enables Claude CLI integration)
- **Project Lifecycle**: Temporary projects auto-created/cleaned for stdio mode
- **Port Strategy**: Random ports for CLI mode to avoid conflicts

### Development Constraints
- **Java**: Target Java 21, minimum Ghidra 12.0+
- **Python**: 3.10+, uv for dependency management
- **Testing (Java)**: Integration tests require `java.awt.headless=false`, fork=1
- **Testing (Python)**: pytest with markers (unit/integration/e2e/cli)
- **Build**: Use `gradle` directly, NOT `./gradlew`
- **MCP SDK**: v0.17.0 with forced Jackson 2.20.x for compatibility

## Important Notes

### Critical
- **NEVER revert to SSE transport** - uses streamable HttpServlet transport
- **Memory**: Always dispose DecompInterface instances to prevent leaks
- **Testing**: Fork every Java integration test (forkEvery=1) to prevent conflicts
- **Python Init**: PyGhidra/server must initialize BEFORE asyncio.run() in CLI

### Common Issues
- **Jackson conflicts**: `rm lib/*.jar` and rebuild to fix MCP SDK compatibility
- **Test reports**: Use Read tool or Grep, NOT `open` command
- **CI logs**: Use Task agent to read (very long logs, context-intensive)
- **Stdio mode**: Requires clean stdin/stdout - no debug prints to stdout

### Testing Strategy
- **Java unit tests**: Fast, no Ghidra environment, test utilities/logic
- **Java integration tests**: Slow, require GUI (headless=false), fork=1, validate state changes
- **Python unit tests**: Fast, mock PyGhidra, test CLI logic
- **Python integration tests**: Require PyGhidra, test actual server
- **Python e2e tests**: Subprocess tests, test full CLI lifecycle