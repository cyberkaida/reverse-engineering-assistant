# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the tools package in ReVa.

## Package Overview

The `reva.tools` package implements MCP (Model Context Protocol) tool providers that expose Ghidra's reverse engineering capabilities to AI models. Each tool provider focuses on a specific domain (decompilation, functions, strings, etc.) and follows consistent patterns for parameter handling, error management, and JSON response formatting.

## Architecture Patterns

### Base Classes
- **ToolProvider** - Interface defining the contract for all tool providers
- **AbstractToolProvider** - Base implementation providing common functionality:
  - Parameter extraction and validation helper methods
  - JSON serialization utilities
  - Error handling and logging
  - MCP tool registration patterns
  - Program validation and address resolution

### Tool Provider Structure
Each tool provider package contains:
- `[Domain]ToolProvider.java` - Main provider class extending AbstractToolProvider
- Individual tool implementations registered in `registerTools()` method
- Domain-specific utility methods for Ghidra API interactions

## Development Guidelines

### Creating New Tool Providers

1. **Extend AbstractToolProvider**:
   ```java
   public class MyToolProvider extends AbstractToolProvider {
       public MyToolProvider(McpSyncServer server) {
           super(server);
       }
   }
   ```

2. **Implement registerTools() pattern**:
   ```java
   @Override
   public void registerTools() throws McpError {
       registerMyTool();
       registerAnotherTool();
   }
   
   private void registerMyTool() throws McpError {
       // Create tool schema and register handler
   }
   ```

3. **Follow naming conventions**:
   - Tool names: `domain-action` (e.g., `decompiler-analyze`, `functions-list`)
   - Method names: `register[ToolName]Tool()` 
   - Package structure: `reva.tools.[domain]/[Domain]ToolProvider.java`

### Parameter Handling

**ALWAYS use AbstractToolProvider helper methods** for parameter extraction:

```java
// Required parameters
String programPath = getString(request, "programPath");
int count = getInt(request, "maxCount");
boolean includeThunks = getBoolean(args, "includeThunks");

// Optional parameters with defaults
String filterPattern = getOptionalString(request, "pattern", ".*");
int startIndex = getOptionalInt(request, "startIndex", 0);
boolean verbose = getOptionalBoolean(request, "verbose", false);

// Maps and lists
Map<String, String> mappings = getStringMap(args, "mappings");
List<String> addresses = getOptionalStringList(args, "addresses", List.of());
```

**Wrap parameter extraction in try-catch** to convert IllegalArgumentException to user-friendly errors:
```java
try {
    String programPath = getString(request, "programPath");
    Program program = getValidatedProgram(programPath);
    // ... tool logic
} catch (IllegalArgumentException | ProgramValidationException e) {
    return createErrorResult(e.getMessage());
}
```

### Program and Address Resolution

**Use provided helper methods** for consistent behavior:

```java
// Program validation (throws ProgramValidationException with helpful error messages)
Program program = getProgramFromArgs(request);

// Address resolution (supports both addresses and symbol names)
Address address = getAddressFromArgs(args, program, "address");

// Function resolution (supports names, addresses, and symbols)
Function function = getFunctionFromArgs(args, program, "functionName");

// Pagination (standard pattern for listing tools)
PaginationParams pagination = getPaginationParams(request, 50); // 50 = default max
```

### Response Patterns

**Use consistent JSON response formats**:

```java
// Success with data
Map<String, Object> result = Map.of(
    "success", true,
    "data", actualData,
    "programPath", program.getDomainFile().getPathname()
);
return createJsonResult(result);

// Error response
return createErrorResult("Description of what went wrong");

// Multiple JSON responses
List<Object> results = List.of(result1, result2, result3);
return createMultiJsonResult(results);
```

### Address Formatting

**ALWAYS use AddressUtil.formatAddress()** for consistent address formatting:
```java
import reva.util.AddressUtil;

String formattedAddress = AddressUtil.formatAddress(address); // Returns "0x" + address.toString()
```

### Transaction Management

**Use transactions for all program modifications**:
```java
int transactionID = program.startTransaction("Tool operation description");
try {
    // Perform modifications
    program.endTransaction(transactionID, true);
} catch (Exception e) {
    program.endTransaction(transactionID, false);
    throw e;
}
```

### Decompiler Tool Patterns

When working with decompilation (especially in DecompilerToolProvider):

1. **Handle decompilation failures gracefully**:
   ```java
   DecompInterface decompiler = new DecompInterface();
   try {
       decompiler.openProgram(program);
       DecompileResults results = decompiler.decompileFunction(function, 30, null);
       if (!results.decompileCompleted()) {
           return createErrorResult("Decompilation failed: " + results.getErrorMessage());
       }
   } finally {
       decompiler.dispose();
   }
   ```

2. **Use HighFunctionDBUtil for persistent changes**:
   ```java
   HighFunctionDBUtil.updateDBVariable(symbol, newName, newDataType, SourceType.USER_DEFINED);
   ```

3. **Handle LocalSymbolMap correctly**:
   ```java
   // LocalSymbolMap.getSymbols() returns Iterator, not Iterable
   Iterator<LocalSymbolMap> symbolIter = localSymMap.getSymbols();
   while (symbolIter.hasNext()) {
       LocalSymbolMap symbol = symbolIter.next();
       // Process symbol
   }
   ```

## Error Handling

### Exception Hierarchy
- **IllegalArgumentException** - Invalid parameters (auto-converted to error response)
- **ProgramValidationException** - Program not found or invalid state (auto-converted to error response)
- **McpError** - MCP protocol errors (propagated to server)
- **RuntimeException** - Unexpected errors (logged and converted to generic error response)

### Error Response Guidelines
- Be specific about what went wrong
- Include helpful suggestions when possible (e.g., available programs when program not found)
- Never expose internal implementation details in error messages
- Use consistent error message formats across tools

## Testing Guidelines

### Integration Test Patterns
- Validate actual Ghidra program state changes, not just MCP responses
- Use `Function.getParameters()` and `Function.getAllVariables()` to verify variable changes
- Use `DataType.isEquivalent()` to compare datatypes before/after changes
- Fork every test to prevent configuration conflicts
- Tests run with `java.awt.headless=false`

### Unit Test Focus
- Parameter validation logic
- JSON response formatting
- Error handling paths
- Edge cases in helper methods

## Tool Categories

### Current Tool Providers
- **project/** - Program listing and project management
- **functions/** - Function analysis, listing, and management
- **decompiler/** - Decompilation and variable manipulation
- **strings/** - String analysis and search
- **symbols/** - Symbol table operations
- **xrefs/** - Cross-reference analysis
- **memory/** - Memory layout and analysis
- **data/** - Data type and structure analysis
- **datatypes/** - Data type management
- **structures/** - Structure definition and analysis
- **comments/** - Comment management
- **bookmarks/** - Bookmark operations

### Tool Naming Conventions
- Use kebab-case for tool names
- Format: `{domain}-{action}` (e.g., `functions-list`, `decompiler-analyze`)
- Keep names concise but descriptive
- Use consistent action verbs: `list`, `get`, `set`, `create`, `delete`, `analyze`

## Important Notes

- **Program identification**: Always use `programPath` parameter for program identification
- **Parameter validation**: Wrap all parameter extraction in try-catch blocks
- **Address formatting**: Use AddressUtil.formatAddress() consistently
- **Transactions**: Required for all program modifications
- **Error messages**: Be helpful and specific
- **JSON responses**: Follow consistent structure patterns
- **Decompiler lifecycle**: Always dispose of DecompInterface instances