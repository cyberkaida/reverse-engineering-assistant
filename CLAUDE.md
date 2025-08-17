# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ReVa (Reverse Engineering Assistant) is a Ghidra extension that provides a Model Context Protocol (MCP) server for AI-assisted reverse engineering. It uses a streamable transport (SSE) and implements various tools for interacting with Ghidra's capabilities.

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
- Debug tests: Increase logging or modify test code directly - cannot use curl to test MCP server

**Important**: Do not use gradle wrapper (`./gradlew`), use `gradle` directly.

## Project Structure

### Key Directories
- `src/main/java/reva/` - Main source code
  - `server/` - MCP server implementation using streamable transport
  - `tools/` - Tool providers (decompiler, functions, strings, etc.)
  - `plugin/` - Ghidra plugin infrastructure
  - `resources/` - MCP resource providers
  - `util/` - Utility classes

### Test Organization
- `src/test/` - Unit tests (no Ghidra environment required)
- `src/test.slow/` - Integration tests (require Ghidra environment)

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

## External Dependencies
- Ghidra source code location: `../ghidra`
- MCP SDK: io.modelcontextprotocol.sdk v0.11.0
- Jackson: 2.17.0 (forced version for compatibility)
- Jetty: 11.0.25 (embedded servlet support)

## Program Identification
- **ALWAYS use `programPath` for program identifiers** in both tool inputs and outputs
- The value is the Ghidra project pathname (e.g., "/Hatchery.exe" or "/folder/program.exe")
- Never use alternative field names like `path`, `name`, or `executable` for program identification
- Tools that list programs return a `programPath` field that can be directly used as input to other tools
- All tools use `ProgramLookupUtil.getValidatedProgram()` for consistent program resolution and helpful error messages
- When a program cannot be found, the error message will include suggestions of available programs

## Important Notes
- Don't revert to the SSE transport (already using streamable)
- The extension requires Ghidra 11.3 or above
- Fork every integration test to prevent configuration conflicts
- Integration tests run with `java.awt.headless=false`