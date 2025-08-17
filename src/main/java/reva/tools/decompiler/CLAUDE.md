# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the decompiler tools package.

## Package Overview

The `reva.tools.decompiler` package provides MCP tools for function decompilation and variable manipulation. It handles Ghidra's decompiler interface and implements read-before-modify tracking to ensure safe variable operations.

## Key Tools

- `decompiler-get` - Get decompiled function with context
- `decompiler-search` - Search across function decompilations  
- `decompiler-rename-variables` - Rename variables in functions
- `decompiler-change-variable-data-types` - Change variable data types
- `decompiler-set-comment` - Set decompilation comments

## Critical Implementation Patterns

### Decompiler Interface Management

**ALWAYS dispose of DecompInterface instances**:
```java
DecompInterface decompiler = new DecompInterface();
try {
    decompiler.openProgram(program);
    // Use decompiler
} finally {
    decompiler.dispose(); // CRITICAL - prevents memory leaks
}
```

### Timeout Management
Use configured timeouts for all decompilation operations:
```java
private TaskMonitor createTimeoutMonitor() {
    ConfigManager configManager = RevaInternalServiceRegistry.getInstance(ConfigManager.class);
    int timeoutMs = configManager.getDecompilerTimeoutMs();
    return TimeoutTaskMonitor.timeoutIn(timeoutMs, TimeUnit.MILLISECONDS);
}
```

### Decompilation Result Validation
**Always check if decompilation completed successfully**:
```java
DecompileResults results = decompiler.decompileFunction(function, timeout, monitor);
if (!results.decompileCompleted()) {
    return createErrorResult("Decompilation failed: " + results.getErrorMessage());
}
```

### Read-Before-Modify Pattern
The package implements tracking to enforce that functions must be read before modification:
```java
private final Map<String, Long> readDecompilationTracker = new ConcurrentHashMap<>();

// Track when function is read
private void trackFunctionRead(String programPath, Address functionAddress) {
    String key = programPath + ":" + AddressUtil.formatAddress(functionAddress);
    readDecompilationTracker.put(key, System.currentTimeMillis());
}

// Check if function was read before allowing modification
private boolean wasFunctionRead(String programPath, Address functionAddress) {
    String key = programPath + ":" + AddressUtil.formatAddress(functionAddress);
    return readDecompilationTracker.containsKey(key);
}
```

## Variable Manipulation Patterns

### Using HighFunctionDBUtil for Persistence
**ALWAYS use HighFunctionDBUtil.updateDBVariable() for persistent variable changes**:
```java
// Get the high-level representation
HighFunction highFunction = results.getHighFunction();
if (highFunction == null) {
    return createErrorResult("Could not get high-level function representation");
}

// Update variable in database
HighFunctionDBUtil.updateDBVariable(symbol, newName, newDataType, SourceType.USER_DEFINED);
```

### LocalSymbolMap Iterator Handling
**LocalSymbolMap.getSymbols() returns Iterator, not Iterable** - use while loop:
```java
LocalSymbolMap localSymMap = highFunction.getLocalSymbolMap();
Iterator<HighSymbol> symbolIter = localSymMap.getSymbols();
while (symbolIter.hasNext()) {
    HighSymbol symbol = symbolIter.next();
    // Process symbol
}
```

### Data Type Parsing
Use DataTypeParserUtil for consistent data type parsing:
```java
import reva.util.DataTypeParserUtil;

DataType newDataType = DataTypeParserUtil.parseDataTypeObjectFromString(
    program.getDataTypeManager(), dataTypeString);
if (newDataType == null) {
    throw new IllegalArgumentException("Invalid data type: " + dataTypeString);
}
```

## Transaction Management

**All variable modifications require transactions**:
```java
int transactionID = program.startTransaction("Rename variables");
try {
    // Perform variable modifications
    HighFunctionDBUtil.updateDBVariable(symbol, newName, newDataType, SourceType.USER_DEFINED);
    program.endTransaction(transactionID, true);
} catch (Exception e) {
    program.endTransaction(transactionID, false);
    throw e;
}
```

## Response Patterns

### Decompilation Context
Include rich context in decompilation responses:
```java
Map<String, Object> result = Map.of(
    "success", true,
    "function", Map.of(
        "name", function.getName(),
        "address", AddressUtil.formatAddress(function.getEntryPoint()),
        "signature", function.getSignature().getPrototypeString()
    ),
    "decompilation", decompiledFunction.getC(),
    "context", DecompilationContextUtil.buildContext(program, function),
    "programPath", program.getDomainFile().getPathname()
);
```

### Variable Mapping Validation
Validate variable mappings before processing:
```java
Map<String, String> mappings = getStringMap(args, "mappings");
if (mappings.isEmpty()) {
    return createErrorResult("No variable mappings provided");
}

// Validate each mapping
for (Map.Entry<String, String> entry : mappings.entrySet()) {
    String oldName = entry.getKey();
    String newName = entry.getValue();
    
    if (oldName.trim().isEmpty() || newName.trim().isEmpty()) {
        return createErrorResult("Variable names cannot be empty");
    }
    
    if (oldName.equals(newName)) {
        continue; // Skip no-change mappings
    }
}
```

## Error Handling Patterns

### Decompilation Failures
```java
try {
    DecompileResults results = decompiler.decompileFunction(function, timeout, monitor);
    if (!results.decompileCompleted()) {
        return createErrorResult("Decompilation failed: " + results.getErrorMessage());
    }
} catch (Exception e) {
    return createErrorResult("Decompilation error: " + e.getMessage());
}
```

### Variable Operation Failures
```java
try {
    HighFunctionDBUtil.updateDBVariable(symbol, newName, newDataType, SourceType.USER_DEFINED);
} catch (DuplicateNameException e) {
    return createErrorResult("Variable name already exists: " + newName);
} catch (InvalidInputException e) {
    return createErrorResult("Invalid variable name: " + newName);
}
```

## Testing Considerations

### Integration Tests
- Validate actual variable changes persist in the database
- Use `Function.getParameters()` and `Function.getAllVariables()` to verify changes
- Use `DataType.isEquivalent()` to compare data types before/after changes
- Test timeout behavior with long-running decompilations
- Verify read-before-modify tracking works correctly

### Test Data Requirements
- Functions with various parameter counts and types
- Functions with local variables of different data types
- Functions that fail to decompile (for error handling tests)
- Large functions that may timeout

## Important Notes

- **Memory Management**: Always dispose DecompInterface instances
- **Timeout Handling**: Use configured timeouts for all operations
- **Transaction Safety**: Wrap all modifications in transactions
- **Read Tracking**: Respect read-before-modify pattern
- **Iterator Handling**: LocalSymbolMap returns Iterator, not Iterable
- **Data Type Validation**: Use DataTypeParserUtil for parsing
- **Error Context**: Provide specific error messages for debugging