# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ReVa (Reverse Engineering Assistant) is a Ghidra extension that provides a Model Context Protocol (MCP) server for AI-assisted reverse engineering. It uses a streamable transport (SSE) and implements various tools for interacting with Ghidra's capabilities. The project supports both GUI and headless operation through PyGhidra integration.

The architecture follows a tool-driven approach where each capability (decompiler analysis, function manipulation, string analysis, etc.) is implemented as an MCP tool provider that can be independently called by AI assistants.

## Build and Test Commands

### Building
```bash
# Set Ghidra installation directory first
export GHIDRA_INSTALL_DIR=/path/to/ghidra
gradle
```

### Testing
- Unit tests: `gradle test --info`
- Integration tests (require GUI/headed environment): `gradle integrationTest --info`
- Single test class: `gradle test --tests "ClassName" --info`
- Single test method: `gradle test --tests "ClassName.methodName" --info`
- Debug tests: Increase logging or modify test code directly - cannot use curl to test MCP server

### Python CLI Testing
```bash
cd cli/
uv run pytest tests/ -v
uv run pytest tests/test_specific.py -v
```

**Important**: Do not use gradle wrapper (`./gradlew`), use `gradle` directly.

## Project Structure

### Key Directories
- `src/main/java/reva/` - Main source code
  - `server/` - MCP server implementation using streamable transport
  - `tools/` - Tool providers (decompiler, functions, strings, etc.)
  - `plugin/` - Ghidra plugin infrastructure
  - `resources/` - MCP resource providers
  - `util/` - Utility classes
- `cli/` - Python CLI for headless operation via PyGhidra
  - `src/reverse_engineering_assistant/` - Python package source
  - `tests/` - Python CLI tests

### Test Organization
- `src/test/` - Unit tests (no Ghidra environment required)
- `src/test.slow/` - Integration tests (require Ghidra environment)
- Uses shared test environment for performance - all integration tests run against same program instance

## Development Guidelines

### Testing
- Integration tests validate actual Ghidra program state changes, not just MCP responses
- Use `Function.getParameters()` and `Function.getAllVariables()` to validate variable changes
- Use `DataType.isEquivalent()` to compare datatypes before/after changes
- Use JUnit 4 (avoid JUnit 5 annotations like `@ParameterizedTest`)
- Integration tests must use `@Fork` annotation to prevent configuration conflicts
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

### Key APIs
- `DataTypeParserUtil.parseDataTypeObjectFromString()` - Parse datatype strings ("char*", "int[10]")
- `HighFunctionDBUtil.updateDBVariable(symbol, newName, newDataType, SourceType.USER_DEFINED)` - Persist changes
- `DecompInterface` - Get decompiled function and high-level representation
- `LocalSymbolMap.getSymbols()` returns Iterator (use while loop, not for-each)

### Common Patterns
- Always use transactions when modifying program state
- Handle decompilation failures gracefully with try-catch
- Validate parameters before processing
- Return structured JSON with success flags and updated decompilation
- Use AbstractToolProvider helper methods (getString, getInt, getOptionalInt, getOptionalBoolean)
- Wrap parameter extraction in try-catch blocks to convert IllegalArgumentException

## MCP Server Configuration

The server uses streamable transport (SSE) on port 8080 by default. Configuration is managed through:
- `ConfigManager` - Handles server configuration
- `McpServerManager` - Manages the MCP server lifecycle
- Transport: HttpServletStreamableServerTransportProvider (MCP v0.11.0)

The server supports multiple concurrent connections and can serve multiple tools simultaneously.

## Python CLI Integration

The Python CLI (`reva` command) provides headless operation through PyGhidra:
- Uses same Java MCP server but connects via PyGhidra bridge
- Requires PyGhidra installation and proper environment setup
- Supports all the same tools as GUI version
- Configuration through environment variables and command-line options

### Critical Development Workflow
When changing Java code, you must update the Python CLI:
1. Build Java extension: `gradle`
2. Copy to Ghidra: Copy `dist/ghidra_*_ReVa.zip` to `$GHIDRA_INSTALL_DIR/Extensions/Ghidra/`
3. Update Python CLI: `cd cli && uv sync`

## External Dependencies
- Ghidra source code location: `../ghidra`
- MCP SDK: io.modelcontextprotocol.sdk v0.11.0
- Jackson: 2.17.0 (forced version for compatibility)
- Jetty: 11.0.25 (embedded servlet support)
- Python CLI: PyGhidra integration for headless operation

## Important Notes
- Don't revert to the SSE transport (already using streamable)
- The extension requires Ghidra 11.3 or above
- Fork every integration test to prevent configuration conflicts
- Integration tests run with `java.awt.headless=false`
- Use semantic versioning for releases (v1.2.3 format)
- Python and Java versions must be kept in sync for proper operation