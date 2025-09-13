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
- Run specific tests: Use standard gradle test filtering with both test targets
- Single test class: `gradle integrationTest --tests "*DecompilerToolProviderIntegrationTest" --info`
- Single test method: `gradle test --tests "*AddressUtilTest.testFormatAddress" --info`
- Debug tests: Increase logging or modify test code directly - cannot use curl to test MCP server

**Important**: Do not use gradle wrapper (`./gradlew`), use `gradle` directly.

## Project Structure

### Architecture Overview
ReVa follows a layered architecture with clear separation of concerns:

- **Foundation Layer** (`util/`) - Core utilities and patterns used everywhere
- **Integration Layer** (`plugin/`) - Ghidra plugin infrastructure and configuration
- **Service Layer** (`services/`) - Service integration and coordination
- **Server Layer** (`server/`) - MCP server with Jetty and streamable transport
- **Resource Layer** (`resources/`) - MCP resource providers for read-only data
- **Tool Layer** (`tools/`) - MCP tool providers for interactive operations
- **UI Layer** (`ui/`) - Optional user interface components

### Key Directories
- `src/main/java/reva/` - Main source code
  - `util/` - **Foundational utilities** (AddressUtil, ProgramLookupUtil, DataTypeParserUtil, etc.)
  - `plugin/` - **Ghidra plugin infrastructure** (ConfigManager, RevaProgramManager, lifecycle)
  - `server/` - **MCP server implementation** (McpServerManager, Jetty, streamable transport)
  - `tools/` - **Tool providers** (decompiler, functions, strings, etc.) - 12 specialized packages
  - `resources/` - **MCP resource providers** (read-only data exposure)
  - `services/` - **Service layer integration** (abstraction between plugins and MCP)
  - `ui/` - **User interface components** (optional, minimal implementation)

### Test Organization
- `src/test/` - Unit tests (no Ghidra environment required)
- `src/test.slow/` - Integration tests (require Ghidra environment)

### Package-Level Documentation
Each major package contains its own CLAUDE.md file with detailed implementation guidance:
- **Essential Infrastructure**: `util/`, `plugin/`, `server/` - Core systems documentation
- **Tool Providers**: Each of the 12 tool packages has comprehensive implementation guides
- **Supporting Systems**: `resources/`, `services/`, `ui/` - Specialized component documentation

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

The server uses streamable transport (SSE) on port 8080 by default. Configuration is managed through:
- `ConfigManager` - Handles server configuration
- `McpServerManager` - Manages the MCP server lifecycle
- Transport: HttpServletStreamableServerTransportProvider (streamable transport)

## External Dependencies
- Ghidra source code location: `../ghidra`
- MCP SDK: io.modelcontextprotocol.sdk v0.11.1 (uses MCP BOM)
- Jackson: 2.17.0 (forced version for compatibility)
- Jetty: 11.0.25 (embedded servlet support)
- Target: Java 21, Ghidra 11.3+

## Program Identification
- **ALWAYS use `programPath` for program identifiers** in both tool inputs and outputs
- The value is the Ghidra project pathname (e.g., "/Hatchery.exe" or "/folder/program.exe")
- Never use alternative field names like `path`, `name`, or `executable` for program identification
- Tools that list programs return a `programPath` field that can be directly used as input to other tools
- All tools use `ProgramLookupUtil.getValidatedProgram()` for consistent program resolution and helpful error messages
- When a program cannot be found, the error message will include suggestions of available programs

## Architecture Decision Records

### MCP Implementation
- **Transport**: Uses streamable transport (HttpServletStreamableServerTransportProvider), not SSE
- **Server**: Embedded Jetty server with servlet-based MCP endpoints
- **Thread Safety**: ConcurrentHashMap for multi-tool coordination, volatile fields for state
- **Tool Pattern**: AbstractToolProvider base class with consistent parameter extraction and error handling

### Development Constraints
- **Java**: Target Java 21, minimum Ghidra 11.3+
- **Testing**: Integration tests require `java.awt.headless=false` (GUI environment)
- **Build**: Use `gradle` directly, not gradle wrapper
- **MCP SDK**: v0.11.1 with forced Jackson 2.17.0 for compatibility

## Important Notes
- Don't revert to SSE transport (already using streamable)
- Fork every integration test to prevent configuration conflicts
- **Memory Management**: Always dispose DecompInterface instances to prevent leaks
- **Read-Before-Modify**: Decompiler tools enforce function reading before modification
- **Error Messages**: Provide specific, actionable error messages with suggestions
- When reading the test report, use the read tool or grep, do not use `open`.