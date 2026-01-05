# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the tools package in ReVa.

## Package Overview

The `reva.tools` package implements MCP (Model Context Protocol) tool providers that expose Ghidra's reverse engineering capabilities to AI models. The package contains 17 specialized tool providers organized into five categories: Core Analysis, Data & Types, Advanced Analysis, Annotations, and Project Management. Each tool provider focuses on a specific domain and follows consistent patterns for parameter handling, error management, and JSON response formatting.

## Architecture Patterns

### Base Classes
- **ToolProvider** - Interface defining the contract for all tool providers
- **AbstractToolProvider** - Base implementation providing common functionality:
  - Parameter extraction and validation helper methods with automatic type conversion
  - JSON serialization utilities
  - **Automatic exception wrapping** - registerTool() wraps handlers to catch IllegalArgumentException and ProgramValidationException
  - Error handling and logging
  - MCP tool registration patterns
  - Program validation and address resolution

### Tool Provider Structure
Each tool provider package contains:
- `[Domain]ToolProvider.java` - Main provider class extending AbstractToolProvider
- Individual tool implementations registered in `registerTools()` method
- Domain-specific utility methods for Ghidra API interactions
- Optional package-level CLAUDE.md with specialized guidance

### Tool Registration Pattern
**Follow this consistent pattern for all tools**:
```java
private void registerMyTool() {
    // 1. Define schema properties
    Map<String, Object> properties = new HashMap<>();
    properties.put("programPath", Map.of(
        "type", "string",
        "description", "Path to the program"
    ));
    properties.put("optionalParam", Map.of(
        "type", "integer",
        "description", "Optional parameter",
        "default", 100
    ));

    // 2. Define required parameters
    List<String> required = List.of("programPath");

    // 3. Create tool with schema
    McpSchema.Tool tool = McpSchema.Tool.builder()
        .name("domain-action")
        .title("Human Readable Title")
        .description("Detailed description for AI models")
        .inputSchema(createSchema(properties, required))
        .build();

    // 4. Register with handler (automatic exception wrapping)
    registerTool(tool, (exchange, request) -> {
        // Parameter extraction (throws caught automatically)
        Program program = getProgramFromArgs(request);
        int param = getOptionalInt(request, "optionalParam", 100);

        // Tool logic here
        Map<String, Object> result = Map.of(
            "success", true,
            "data", actualData,
            "programPath", program.getDomainFile().getPathname()
        );
        return createJsonResult(result);
    });
}

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

**ALWAYS use AbstractToolProvider helper methods** for parameter extraction. These methods handle automatic type conversion:

```java
// Required parameters (auto-converts types)
String programPath = getString(request, "programPath");  // Converts non-strings via toString()
int count = getInt(request, "maxCount");                 // Parses strings, converts Number types
boolean includeThunks = getBoolean(args, "includeThunks"); // Handles "true"/"false" strings

// Optional parameters with defaults
String filterPattern = getOptionalString(request, "pattern", ".*");
int startIndex = getOptionalInt(request, "startIndex", 0);  // Returns primitive int
boolean verbose = getOptionalBoolean(request, "verbose", false);

// Optional with nullable return (can distinguish "not provided" from "default")
Integer optionalLimit = getOptionalInteger(args, "limit", null);  // Returns Integer (can be null)

// Maps and lists
Map<String, String> mappings = getStringMap(args, "mappings");  // Required string map
Map<String, String> optionalMappings = getOptionalStringMap(args, "mappings", Map.of());  // Optional string map
Map<String, Object> options = getOptionalMap(args, "options", Map.of());  // Optional generic map
List<String> addresses = getOptionalStringList(args, "addresses", List.of());  // Optional string list
List<String> tags = getStringList(args, "tags");  // Required string list
```

**Exception handling is automatic** - registerTool() wraps handlers to catch exceptions:
```java
// NO try-catch needed for IllegalArgumentException or ProgramValidationException!
// The registerTool() method automatically catches and converts to error responses
String programPath = getString(request, "programPath");  // Throws if missing
Program program = getValidatedProgram(programPath);     // Throws if invalid
// ... tool logic

// Only catch for custom error handling or cleanup
```

### Program and Address Resolution

**Use provided helper methods** for consistent behavior:

```java
// Program validation (throws ProgramValidationException with helpful error messages)
Program program = getProgramFromArgs(request);

// Address resolution (supports both addresses and symbol names)
Address address = getAddressFromArgs(args, program, "address");
Address addressCustomKey = getAddressFromArgs(args, program, "addressOrSymbol");

// Symbol name to address resolution (resolves symbol names only)
Address symbolAddress = getAddressFromSymbolArgs(args, program, "symbolName");
Address symbolDefaultKey = getAddressFromSymbolArgs(args, program); // Uses "symbolName" as key

// Function resolution (supports names, addresses, and symbols)
Function function = getFunctionFromArgs(args, program, "functionName");
Function functionDefault = getFunctionFromArgs(args, program); // Uses "functionNameOrAddress" as key

// Pagination (standard pattern for listing tools)
PaginationParams pagination = getPaginationParams(request, 50); // 50 = default max
PaginationParams paginationDefault = getPaginationParams(request); // Default max = 100
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

### Critical Utility Usage

**ALWAYS use ReVa utilities instead of direct Ghidra APIs** for consistency:

**Address and Symbol Utilities**:
- `AddressUtil.formatAddress(address)` - **REQUIRED** for all address formatting in JSON output
- `AddressUtil.resolveAddressOrSymbol(program, addressOrSymbol)` - Resolve addresses or symbol names
- `AddressUtil.getContainingFunction(program, address)` - Get function containing an address

**Program and Data Type Utilities**:
- `ProgramLookupUtil.getValidatedProgram(programPath)` - **REQUIRED** for program resolution with helpful errors
- `DataTypeParserUtil.parseDataTypeObjectFromString(dtm, typeString)` - Parse datatype strings ("char*", "int[10]")

**Symbol and Variable Utilities**:
- `SymbolUtil.isDefaultSymbolName(name)` - Filter Ghidra-generated names (FUN_, DAT_, etc.)
- `HighFunctionDBUtil.updateDBVariable(symbol, name, type, source)` - **REQUIRED** for persisting variable changes

**Analysis and Comparison Utilities**:
- `SimilarityComparator` - Compare functions and strings by similarity scoring (LCS-based)
- `DecompilationContextUtil.buildContext(program, function)` - Build rich context for decompilation responses
- `DecompilationDiffUtil` - Compare decompilations before/after changes

**Support Utilities**:
- `DebugLogger` - Debug logging with conditional output
- `RevaInternalServiceRegistry.getService(ServiceClass.class)` - Access services like ConfigManager

### Common Patterns and Best Practices

**Thread Safety for Multi-Tool Coordination**:
```java
// Use concurrent collections for shared state
private final Map<String, Long> tracker = new ConcurrentHashMap<>();

// Use atomic types for counting
AtomicInteger count = new AtomicInteger(0);
count.incrementAndGet();

// Use volatile for state flags
private volatile boolean isProcessing = false;
```

**Service Access Pattern**:
```java
import reva.util.RevaInternalServiceRegistry;
import reva.plugin.ConfigManager;

ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
int timeout = configManager.getDecompilerTimeoutSeconds();
```

**Pagination Best Practices**:
- Always provide count tools before listing tools
- Use default max of 50-100 items per page
- Include pagination metadata in responses
- Use AtomicInteger for efficient iteration counting

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

### Automatic Exception Wrapping
**The registerTool() method automatically wraps handlers** with safe execution:
```java
// From AbstractToolProvider.registerTool():
java.util.function.BiFunction<..., McpSchema.CallToolResult> safeHandler =
    (exchange, request) -> {
        try {
            return handler.apply(exchange, request);
        } catch (IllegalArgumentException e) {
            return createErrorResult(e.getMessage());
        } catch (ProgramValidationException e) {
            return createErrorResult(e.getMessage());
        } catch (Exception e) {
            logError("Unexpected error in tool execution", e);
            return createErrorResult("Tool execution failed: " + e.getMessage());
        }
    };
```

### Exception Hierarchy
- **IllegalArgumentException** - Invalid parameters (**auto-caught and converted** to error response)
- **ProgramValidationException** - Program not found or invalid state (**auto-caught and converted** to error response)
- **McpError** - MCP protocol errors (propagated to server)
- **RuntimeException** - Unexpected errors (logged and converted to generic error response)

### When to Use Try-Catch in Tool Handlers
**Only use explicit try-catch for**:
- Custom error messages or recovery logic
- Transaction rollback on specific errors
- Resource cleanup (e.g., DecompInterface disposal with finally)
- Domain-specific exception types (DuplicateNameException, InvalidInputException, etc.)

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

## Practical Implementation Tips

### Parameter Schema Best Practices
**Provide helpful defaults and descriptions**:
```java
properties.put("maxCount", Map.of(
    "type", "integer",
    "description", "Maximum number of items to return (recommended: 100)",
    "default", 100
));
properties.put("includeComments", Map.of(
    "type", "boolean",
    "description", "Whether to include comments in the output",
    "default", false
));
```

### Response Metadata
**Always include programPath and pagination info**:
```java
Map<String, Object> result = Map.of(
    "success", true,
    "data", actualData,
    "programPath", program.getDomainFile().getPathname(),
    "pagination", Map.of(
        "startIndex", startIndex,
        "returned", actualData.size(),
        "requested", maxCount
    )
);
```

### Iterator vs Iterable Gotchas
**Be aware of Ghidra API iterator patterns**:
```java
// LocalSymbolMap returns Iterator, NOT Iterable - cannot use for-each
Iterator<HighSymbol> symbolIter = localSymMap.getSymbols();
while (symbolIter.hasNext()) {  // Use while loop
    HighSymbol symbol = symbolIter.next();
    // Process
}

// FunctionIterator IS Iterable - can use for-each or while
FunctionIterator functions = functionManager.getFunctions(true);
functions.forEach(function -> { /* Process */ });  // This works
```

### Efficient Pagination Pattern
**Use atomic counters for clean pagination logic**:
```java
AtomicInteger currentIndex = new AtomicInteger(0);
AtomicInteger collected = new AtomicInteger(0);

FunctionIterator functions = program.getFunctionManager().getFunctions(true);
while (functions.hasNext() && collected.get() < maxCount) {
    Function function = functions.next();

    // Skip until reaching start index
    if (currentIndex.getAndIncrement() < startIndex) {
        continue;
    }

    // Collect this item
    items.add(processFunction(function));
    collected.incrementAndGet();
}
```

### Timeout Configuration Pattern
**Use ConfigManager for configurable timeouts**:
```java
private TaskMonitor createTimeoutMonitor() {
    ConfigManager config = RevaInternalServiceRegistry.getService(ConfigManager.class);
    int timeoutSeconds = config.getDecompilerTimeoutSeconds();
    return TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
}

// Check for timeout
if (monitor.isCancelled()) {
    return createErrorResult("Operation timed out after " + timeoutSeconds + " seconds");
}
```

## Tool Categories

### Current Tool Providers (17 Total)

**Core Analysis** (6 providers):
- **decompiler/** - Decompilation and variable manipulation
- **functions/** - Function analysis, listing, and management
- **strings/** - String analysis and search
- **symbols/** - Symbol table operations
- **xrefs/** - Cross-reference analysis
- **memory/** - Memory layout and analysis

**Data & Types** (3 providers):
- **data/** - Data type and structure analysis
- **datatypes/** - Data type management
- **structures/** - Structure definition and analysis

**Advanced Analysis** (5 providers):
- **callgraph/** - Call graph analysis and navigation
- **dataflow/** - Data flow analysis and tracking
- **constants/** - Constant value analysis and identification
- **vtable/** - Virtual table detection and analysis
- **imports/** - Import table and external reference analysis

**Annotations** (2 providers):
- **comments/** - Comment management
- **bookmarks/** - Bookmark operations

**Project Management** (1 provider):
- **project/** - Program listing and project management

### Tool Naming Conventions
- Use kebab-case for tool names
- Format: `{domain}-{action}` (e.g., `functions-list`, `decompiler-analyze`)
- Keep names concise but descriptive
- Use consistent action verbs: `list`, `get`, `set`, `create`, `delete`, `analyze`

## Important Notes

- **Program identification**: Always use `programPath` parameter for program identification
- **Automatic exception handling**: registerTool() automatically catches IllegalArgumentException and ProgramValidationException
- **Type conversion**: Helper methods automatically convert types (Number to int, String to boolean, etc.)
- **Address formatting**: Use AddressUtil.formatAddress() consistently
- **Transactions**: Required for all program modifications
- **Thread safety**: Use ConcurrentHashMap and AtomicInteger for shared state
- **Service access**: Use RevaInternalServiceRegistry to get services like ConfigManager
- **Error messages**: Be helpful and specific
- **JSON responses**: Follow consistent structure patterns
- **Decompiler lifecycle**: Always dispose of DecompInterface instances
- **Timeout management**: Use createTimeoutMonitor() for long-running operations