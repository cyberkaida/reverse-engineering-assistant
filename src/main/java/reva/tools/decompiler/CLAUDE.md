# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the decompiler tools package.

## Package Overview

The `reva.tools.decompiler` package provides MCP tools for function decompilation and variable manipulation. It handles Ghidra's decompiler interface and implements read-before-modify tracking to ensure safe variable operations.

## Registered Tools

### Core Decompilation Tools
- `get-decompilation` - Get decompiled function with line range support, optional assembly sync, comments, incoming references, and caller/callee lists
- `search-decompilation` - Search regex patterns across all function decompilations
- `rename-variables` - Rename variables in decompiled functions (with diff)
- `change-variable-datatypes` - Change variable data types (with diff)
- `set-decompilation-comment` - Set comment at specific decompilation line

### Bulk Decompilation Tools
- `get-callers-decompiled` - Bulk decompile all functions that call a target (with pagination and call site highlighting)
- `get-referencers-decompiled` - Bulk decompile all functions that reference an address/symbol (handles code and data refs)

## Critical Implementation Patterns

### Decompiler Interface Management

**Use helper methods for consistent decompiler lifecycle**:
```java
// Create and configure decompiler (returns null on failure)
DecompInterface decompiler = createConfiguredDecompiler(program, "tool-name");
if (decompiler == null) {
    return createErrorResult("Failed to initialize decompiler");
}

try {
    // Use decompiler
    DecompilationAttempt attempt = decompileFunctionSafely(decompiler, function, "tool-name");
    if (!attempt.success()) {
        return createErrorResult(attempt.errorMessage());
    }
    // Process results...
} finally {
    decompiler.dispose(); // CRITICAL - prevents memory leaks
}
```

### Timeout Management
Use configured timeouts via helper methods:
```java
// Create timeout monitor from config
private TaskMonitor createTimeoutMonitor() {
    ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
    int timeoutSeconds = configManager.getDecompilerTimeoutSeconds();
    return TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
}

// Check if timed out
private boolean isTimedOut(TaskMonitor monitor) {
    return monitor.isCancelled();
}
```

### Safe Decompilation Pattern
**Use DecompilationAttempt wrapper for consistent error handling**:
```java
// Returns success/failure with error message
private record DecompilationAttempt(
    DecompileResults results,
    String errorMessage,
    boolean success
) {
    static DecompilationAttempt success(DecompileResults results) {
        return new DecompilationAttempt(results, null, true);
    }

    static DecompilationAttempt failure(String message) {
        return new DecompilationAttempt(null, message, false);
    }
}

// Use in tool handlers
DecompilationAttempt attempt = decompileFunctionSafely(decompiler, function, "tool-name");
if (!attempt.success()) {
    return createErrorResult(attempt.errorMessage());
}
```

### Read-Before-Modify Pattern
**Enforces that functions must be read via get-decompilation before modification**:
```java
// Tracking map with 30-minute expiry
private final Map<String, Long> readDecompilationTracker = new ConcurrentHashMap<>();
private static final long READ_TRACKING_EXPIRY_MS = TimeUnit.MINUTES.toMillis(30);

// Track when function is read (done automatically in get-decompilation)
String functionKey = programPath + ":" + AddressUtil.formatAddress(function.getEntryPoint());
readDecompilationTracker.put(functionKey, System.currentTimeMillis());

// Check before allowing modification
private boolean hasReadDecompilation(String functionKey) {
    Long lastReadTime = readDecompilationTracker.get(functionKey);
    if (lastReadTime == null) {
        return false;
    }
    long expiryThreshold = System.currentTimeMillis() - READ_TRACKING_EXPIRY_MS;
    return lastReadTime > expiryThreshold;
}

// Validate in modify tools
if (!hasReadDecompilation(functionKey)) {
    return createErrorResult("You must read the decompilation for function '" +
        function.getName() + "' using get-decompilation tool before making changes.");
}
```

**Cleanup on program close**:
```java
@Override
public void programClosed(Program program) {
    super.programClosed(program);
    String programPath = program.getDomainFile().getPathname();
    // Remove entries for closed program using thread-safe removeIf
    readDecompilationTracker.entrySet().removeIf(
        entry -> entry.getKey().startsWith(programPath + ":")
    );
}
```

## Variable Manipulation Patterns

### Using HighFunctionDBUtil for Persistence
**ALWAYS use HighFunctionDBUtil.updateDBVariable() for persistent variable changes**:
```java
// Get the high-level representation
HighFunction highFunction = attempt.results().getHighFunction();
if (highFunction == null) {
    return createErrorResult("Could not get high-level function representation");
}

// Update variable in database (name and/or datatype)
HighFunctionDBUtil.updateDBVariable(symbol, newName, newDataType, SourceType.USER_DEFINED);
```

### Processing Variables with SymbolProcessor Pattern
**Use functional interface for consistent variable iteration**:
```java
@FunctionalInterface
private interface SymbolProcessor {
    boolean process(HighSymbol symbol) throws DuplicateNameException, InvalidInputException;
}

// Helper method processes both local and global variables
private int processAllVariables(
    HighFunction highFunction,
    SymbolProcessor processor,
    String toolName) {
    int processedCount = 0;

    // Process local variables
    Iterator<HighSymbol> localVars = highFunction.getLocalSymbolMap().getSymbols();
    while (localVars.hasNext()) {
        HighSymbol symbol = localVars.next();
        try {
            if (processor.process(symbol)) {
                processedCount++;
            }
        } catch (DuplicateNameException | InvalidInputException e) {
            logError(toolName + ": Failed to process " + symbol.getName(), e);
        }
    }

    // Process global variables
    Iterator<HighSymbol> globalVars = highFunction.getGlobalSymbolMap().getSymbols();
    while (globalVars.hasNext()) {
        // Same pattern as above...
    }

    return processedCount;
}

// Use in tool handler
int renamedCount = processAllVariables(highFunction, symbol -> {
    String newName = mappings.get(symbol.getName());
    if (newName != null) {
        HighFunctionDBUtil.updateDBVariable(symbol, newName, null, SourceType.USER_DEFINED);
        return true;
    }
    return false;
}, "rename-variables");
```

### LocalSymbolMap Iterator Handling
**LocalSymbolMap.getSymbols() returns Iterator, not Iterable** - must use while loop:
```java
// CORRECT - use while loop
Iterator<HighSymbol> symbolIter = highFunction.getLocalSymbolMap().getSymbols();
while (symbolIter.hasNext()) {
    HighSymbol symbol = symbolIter.next();
    // Process symbol
}

// WRONG - for-each doesn't work
for (HighSymbol symbol : highFunction.getLocalSymbolMap().getSymbols()) { // COMPILATION ERROR
    // ...
}
```

### Data Type Parsing
**Use DataTypeParserUtil for consistent data type parsing**:
```java
import reva.util.DataTypeParserUtil;

// Parse with optional archive name
DataType newDataType = DataTypeParserUtil.parseDataTypeObjectFromString(
    dataTypeString, archiveName);
if (newDataType == null) {
    errors.add("Could not find data type: " + dataTypeString);
    return false;
}
```

## Transaction Management

**All variable modifications require transactions**:
```java
int transactionId = program.startTransaction("Rename Variables");
try {
    // Perform variable modifications
    int renamedCount = processAllVariables(highFunction, processor, toolName);
    program.endTransaction(transactionId, true);
} catch (Exception e) {
    program.endTransaction(transactionId, false);
    logError(toolName + ": Error during variable operations", e);
    return createErrorResult("Failed to modify variables: " + e.getMessage());
}
```

## Tool Parameter Patterns

### get-decompilation Parameters
```java
// Core parameters
String functionNameOrAddress = getString(request, "functionNameOrAddress");
int offset = getOptionalInt(request, "offset", 1);  // Line to start from
Integer limit = getOptionalInteger(request.arguments(), "limit", 50);  // Lines to return

// Optional content flags
boolean includeDisassembly = getOptionalBoolean(request, "includeDisassembly", false);
boolean includeComments = getOptionalBoolean(request, "includeComments", false);
boolean includeIncomingReferences = getOptionalBoolean(request, "includeIncomingReferences", true);
boolean includeReferenceContext = getOptionalBoolean(request, "includeReferenceContext", true);

// Optional metadata flags
boolean includeCallers = getOptionalBoolean(request, "includeCallers", false);
boolean includeCallees = getOptionalBoolean(request, "includeCallees", false);
boolean signatureOnly = getOptionalBoolean(request, "signatureOnly", false);
```

**Key features**:
- Line range support (offset/limit) for context conservation
- Optional assembly sync via `includeDisassembly`
- Optional incoming references with code context
- Optional caller/callee lists (avoids separate tool calls)
- Signature-only mode to save tokens
- Handles undefined functions via `UndefinedFunction.findFunction()`

### Bulk Decompilation Parameters
```java
// get-callers-decompiled / get-referencers-decompiled
int maxCallers = getOptionalInt(request, "maxCallers", 10);  // Max 50
int startIndex = getOptionalInt(request, "startIndex", 0);   // For pagination
boolean includeCallContext = getOptionalBoolean(request, "includeCallContext", true);
boolean includeDataRefs = getOptionalBoolean(request, "includeDataRefs", true);  // referencers only
```

**Pagination pattern**:
- `startIndex` and `maxCallers/maxReferencers` for paging
- Returns `nextStartIndex` and `hasMore` in response
- Limits: max 50 per page, max 500 total collected

### Variable Modification Parameters
```java
// rename-variables
Map<String, String> mappings = getStringMap(request.arguments(), "variableMappings");
if (mappings == null || mappings.isEmpty()) {
    return createErrorResult("No variable mappings provided");
}

// change-variable-datatypes
Map<String, String> datatypeMappings = getStringMap(request.arguments(), "datatypeMappings");
String archiveName = getOptionalString(request, "archiveName", "");
```

## Response Patterns

### Decompilation Response with Diff
**Return changes after variable modifications**:
```java
Map<String, Object> resultData = new HashMap<>();
resultData.put("programName", program.getName());
resultData.put("functionName", function.getName());
resultData.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
resultData.put("variablesRenamed", true);
resultData.put("renamedCount", renamedCount);

// Get updated decompilation and create diff
resultData.putAll(getDecompilationDiff(program, function, beforeDecompilation, toolName));

return createJsonResult(resultData);
```

**getDecompilationDiff() helper method**:
```java
private Map<String, Object> getDecompilationDiff(
    Program program,
    Function function,
    String beforeDecompilation,
    String toolName) {
    Map<String, Object> result = new HashMap<>();

    DecompInterface newDecompiler = createConfiguredDecompiler(program, toolName + "-diff");
    try {
        DecompilationAttempt attempt = decompileFunctionSafely(newDecompiler, function, toolName);
        if (attempt.success()) {
            String afterDecompilation = attempt.results().getDecompiledFunction().getC();
            DecompilationDiffUtil.DiffResult diff =
                DecompilationDiffUtil.createDiff(beforeDecompilation, afterDecompilation);
            result.put("changes", DecompilationDiffUtil.toMap(diff));
        } else {
            result.put("decompilationError", attempt.errorMessage());
        }
    } finally {
        newDecompiler.dispose();
    }

    return result;
}
```

### Caller/Callee List Response
**Include call counts and function metadata**:
```java
// Count calls with timeout handling
CallCountResult countResult = countCallsWithTimeout(program, function, isCallers);
List<Map<String, Object>> callersList = buildCallListInfo(
    callers, countResult.callCounts(), MAX_CALLERS_IN_DECOMPILATION);

resultData.put("callers", callersList);
resultData.put("callerCount", callersList.size());
resultData.put("totalCallerCount", totalCallers);
if (totalCallers > MAX_CALLERS_IN_DECOMPILATION) {
    resultData.put("callersLimited", true);
}
if (countResult.timedOut()) {
    resultData.put("callerCallCountsIncomplete", true);
}
```

## Special Features and Helpers

### Call Reference Counting with Timeout
**Efficiently count calls with periodic timeout checks**:
```java
private record CallCountResult(
    Map<Address, Integer> callCounts,
    boolean timedOut
) {}

private CallCountResult countCallsWithTimeout(
    Program program,
    Function function,
    boolean countCallers) {
    TaskMonitor monitor = createTimeoutMonitor();
    Map<Address, Integer> callCounts = new HashMap<>();
    boolean timedOut = false;

    // Check timeout periodically (every 100 instructions, every 50 references)
    int instrCount = 0;
    int refCount = 0;

    for (Instruction instr : listing.getInstructions(functionBody, true)) {
        if (++instrCount % TIMEOUT_CHECK_INSTRUCTION_INTERVAL == 0 && monitor.isCancelled()) {
            timedOut = true;
            break;
        }

        // Count references...
        if (++refCount % TIMEOUT_CHECK_REFERENCE_INTERVAL == 0 && monitor.isCancelled()) {
            timedOut = true;
            break;
        }
    }

    return new CallCountResult(callCounts, timedOut);
}
```

### Synchronized Assembly and Comments
**Get decompilation synchronized with assembly listing**:
```java
private Map<String, Object> getSynchronizedContent(
    Program program,
    ClangTokenGroup markup,
    String fullDecompCode,
    int offset,
    Integer limit,
    boolean includeDisassembly,
    boolean includeComments,
    boolean includeIncomingReferences,
    boolean includeReferenceContext,
    Function function) {
    // Convert decompiler markup to lines
    List<ClangLine> clangLines = DecompilerUtils.toLines(markup);

    // Map decompilation lines to assembly addresses
    for (ClangLine line : clangLines) {
        List<ClangToken> tokens = line.getAllTokens();
        // Extract addresses from tokens
        // Get assembly at those addresses
    }

    // Include incoming references at function level
    if (includeIncomingReferences) {
        List<Map<String, Object>> incomingRefs =
            DecompilationContextUtil.getEnhancedIncomingReferences(
                program, function, includeReferenceContext, maxIncomingRefs);
    }
}
```

### Finding Call Line Numbers
**Map addresses to decompilation line numbers**:
```java
private List<Integer> findCallLineNumbers(
    DecompileResults results,
    List<Address> addresses) {
    List<Integer> lineNumbers = new ArrayList<>();

    ClangTokenGroup markup = results.getCCodeMarkup();
    Set<Address> addressSet = new HashSet<>(addresses);
    List<ClangLine> lines = DecompilerUtils.toLines(markup);

    for (ClangLine line : lines) {
        for (ClangToken token : line.getAllTokens()) {
            Address tokenAddr = token.getMinAddress();
            if (tokenAddr != null && addressSet.contains(tokenAddr)) {
                lineNumbers.add(line.getLineNumber());
                break; // Only add line once
            }
        }
    }

    return lineNumbers;
}
```

### Undefined Function Handling
**Support decompiling undefined functions**:
```java
// After resolving address, if no defined function found
if (function == null && resolvedAddress != null) {
    // Validate address is in executable memory
    MemoryBlock block = program.getMemory().getBlock(resolvedAddress);
    if (block == null || !block.isExecute()) {
        return createErrorResult("Address not in executable memory");
    }

    // Check for instruction
    Instruction instr = program.getListing().getInstructionAt(resolvedAddress);
    if (instr == null) {
        return createErrorResult("No instruction at address");
    }

    // Create temporary function
    TaskMonitor undefinedFuncMonitor = createTimeoutMonitor();
    function = UndefinedFunction.findFunction(program, resolvedAddress, undefinedFuncMonitor);
    if (function != null) {
        isUndefinedFunction = true;
        resultData.put("isUndefinedFunction", true);
        resultData.put("undefinedFunctionNote",
            "This is a temporary function created for decompilation preview. " +
            "Variable modifications are not supported.");
    }
}
```

## Error Handling Patterns

### Check for Undefined Functions Before Modification
```java
// In variable modification tools
try {
    function = getFunctionFromArgs(request.arguments(), program);
} catch (IllegalArgumentException e) {
    // Check if this might be an undefined function location
    if (AddressUtil.isUndefinedFunctionAddress(program, functionNameOrAddress)) {
        return createErrorResult("Cannot modify variables at " + functionNameOrAddress +
            ": this address has code but no defined function. " +
            "Use create-function to define it first, then retry.");
    }
    return createErrorResult("Function not found: " + e.getMessage());
}
```

### Timeout Handling in Search
```java
// In search-decompilation: continue to next function on timeout
TaskMonitor functionTimeoutMonitor = createTimeoutMonitor();
DecompileResults decompileResults = decompiler.decompileFunction(
    function, 0, functionTimeoutMonitor);

if (isTimedOut(functionTimeoutMonitor)) {
    Msg.warn(DecompilerToolProvider.class,
        toolName + ": Decompilation timed out for " + function.getName());
    continue; // Skip this function and continue with next
}
```

### Progress Notifications in Search
```java
private void sendSearchProgress(
    McpSyncServerExchange exchange,
    String progressToken,
    int processedFunctions,
    int totalFunctions,
    int resultsCount,
    int maxResults,
    boolean hasMoreFunctions) {

    // Send progress every 10 functions or when complete
    if (exchange == null || (processedFunctions % 10 != 0 && resultsCount < maxResults && hasMoreFunctions)) {
        return;
    }

    String message = String.format("Processed %d/%d functions - found %d matches",
        processedFunctions, totalFunctions, resultsCount);

    exchange.progressNotification(new McpSchema.ProgressNotification(
        progressToken, (double) processedFunctions, (double) totalFunctions, message));
}
```

## Testing Considerations

### Integration Tests
- Validate actual variable changes persist in the database
- Use `Function.getParameters()` and `Function.getAllVariables()` to verify changes
- Use `DataType.isEquivalent()` to compare data types before/after changes
- Test timeout behavior with long-running decompilations
- Verify read-before-modify tracking works correctly
- Test bulk decompilation pagination
- Test undefined function decompilation (no modifications allowed)

### Test Data Requirements
- Functions with various parameter counts and types
- Functions with local variables of different data types
- Functions that fail to decompile (for error handling tests)
- Large functions that may timeout
- Functions with many callers/callees
- Undefined addresses in executable memory

## Important Constants

```java
// Expiry time for read tracking entries
private static final long READ_TRACKING_EXPIRY_MS = TimeUnit.MINUTES.toMillis(30);

// Limits for inline caller/callee info in get-decompilation
private static final int MAX_CALLERS_IN_DECOMPILATION = 50;
private static final int MAX_CALLEES_IN_DECOMPILATION = 50;

// Timeout check intervals during reference counting
private static final int TIMEOUT_CHECK_INSTRUCTION_INTERVAL = 100;
private static final int TIMEOUT_CHECK_REFERENCE_INTERVAL = 50;

// Bulk decompilation limits
private static final int MAX_TOTAL_CALLERS = 500;  // Max to collect before pagination
private static final int MAX_TOTAL_REFERENCERS = 500;
```

## Important Notes

- **Memory Management**: Always dispose DecompInterface instances in finally blocks
- **Timeout Handling**: Use createTimeoutMonitor() with configured timeouts for all operations
- **Transaction Safety**: Wrap all modifications in transactions with proper rollback
- **Read Tracking**: Enforced read-before-modify pattern with 30-minute expiry and program close cleanup
- **Iterator Handling**: LocalSymbolMap.getSymbols() returns Iterator, not Iterable - use while loops
- **Data Type Validation**: Use DataTypeParserUtil.parseDataTypeObjectFromString() for parsing
- **Helper Methods**: Use createConfiguredDecompiler() and decompileFunctionSafely() for consistency
- **Undefined Functions**: Support decompilation but block modifications
- **Bulk Operations**: Include pagination with max 50 per page, max 500 total
- **Progress Notifications**: Send updates every 10 functions during search
- **Diff Generation**: Use DecompilationDiffUtil for before/after comparison
- **Call Counts**: Use countCallsWithTimeout() with periodic timeout checks
- **Address Formatting**: Always use AddressUtil.formatAddress() for consistency