# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the functions tools package.

## Package Overview

The `reva.tools.functions` package provides MCP tools for function analysis, listing, and management operations in Ghidra programs. It handles function enumeration, similarity analysis, and prototype manipulation.

## Key Tools

- `get-function-count` - Get total count of functions (use before listing for pagination)
- `get-functions` - List functions with pagination and filtering (supports `filterByTag`, `untagged`, `verbose`)
- `get-functions-by-similarity` - Find functions similar to a target function (compact by default, use `verbose: true` for full details)
- `set-function-prototype` - Modify function signatures and prototypes
- `function-tags` - Manage tags on functions (modes: get/set/add/remove/list)

## Core Patterns

### Function Enumeration with Filtering
**Use SymbolUtil for default name filtering**:
```java
import reva.util.SymbolUtil;

FunctionIterator functions = program.getFunctionManager().getFunctions(true);
functions.forEach(function -> {
    // Skip default Ghidra function names if filtering is enabled
    if (filterDefaultNames && SymbolUtil.isDefaultSymbolName(function.getName())) {
        return;
    }
    // Process function
});
```

### Pagination Pattern
**Always use get-function-count first, then paginate with recommended chunk size**:
```java
PaginationParams pagination = getPaginationParams(request, 100); // Default 100
int startIndex = pagination.startIndex();
int maxCount = pagination.maxCount();

// Collect functions with pagination
AtomicInteger currentIndex = new AtomicInteger(0);
AtomicInteger collected = new AtomicInteger(0);
```

### Function Data Structure
**Standard function information format**:
```java
Map<String, Object> functionData = Map.of(
    "name", function.getName(),
    "address", AddressUtil.formatAddress(function.getEntryPoint()),
    "signature", function.getSignature().getPrototypeString(),
    "parameterCount", function.getParameterCount(),
    "namespace", function.getParentNamespace().getName(),
    "isThunk", function.isThunk(),
    "hasVarArgs", function.hasVarArgs(),
    "callingConvention", function.getCallingConventionName()
);
```

## Function Tags

Function tags categorize functions (e.g., "AI", "rendering", "save/load"). Tags are included in all function info responses via the `tags` field (sorted alphabetically).

### Tag Operations
The `function-tags` tool uses a `mode` parameter:
- `get` - Return current tags on a function
- `set` - Replace all tags with provided list (empty list clears all)
- `add` - Add to existing tags
- `remove` - Remove specified tags
- `list` - List all tags in the program with usage counts (no function required)

**Note**: Empty or whitespace-only tag names are automatically filtered out.

### Querying by Tag
Use `get-functions` with `filterByTag` parameter to find all functions with a specific tag.
Use `get-functions` with `untagged: true` to find functions that have no tags (useful for tracking progress).
Note: `filterByTag` and `untagged` are mutually exclusive.

### Response Format
For get/set/add/remove modes, responses are lean (just identifiers + tags):
```json
{"success": true, "programPath": "/prog", "mode": "add", "function": "processAI", "address": "0x00401000", "tags": ["AI", "game-logic"]}
```

### Example Workflow
```json
// 1. Tag functions by category
{"programPath": "/prog", "mode": "add", "function": "processAI", "tags": ["AI", "game-logic"]}
// Returns: {"success": true, ..., "function": "processAI", "address": "0x...", "tags": ["AI", "game-logic"]}

// 2. List all tags in program
{"programPath": "/prog", "mode": "list"}
// Returns: {"success": true, "tags": [{"name": "AI", "count": 5}, ...], "totalTags": 2}

// 3. Find all AI functions via get-functions
{"programPath": "/prog", "filterByTag": "AI"}
// Returns paginated list of functions tagged "AI"

// 4. Find untagged functions (what still needs categorization)
{"programPath": "/prog", "untagged": true}
// Returns paginated list of functions with no tags
```

### Ghidra API
```java
// Tags are accessed via Function interface
function.addTag("AI");           // Creates tag if doesn't exist
function.removeTag("rendering");
Set<FunctionTag> tags = function.getTags();

// Program-wide tag management
FunctionTagManager tagManager = program.getFunctionManager().getFunctionTagManager();
List<? extends FunctionTag> allTags = tagManager.getAllFunctionTags();
int count = tagManager.getUseCount(tag);
```

## Function Prototype Management

### Signature Parsing
**Use FunctionSignatureParser for prototype changes**:
```java
import ghidra.app.util.parser.FunctionSignatureParser;

try {
    FunctionDefinitionDataType newSignature = FunctionSignatureParser.parse(
        program.getDataTypeManager(), signature);
    
    // Validate the signature
    if (newSignature == null) {
        return createErrorResult("Invalid function signature: " + signature);
    }
} catch (ParseException e) {
    return createErrorResult("Error parsing function signature: " + e.getMessage());
}
```

### Parameter Handling
**Convert between ParameterDefinition and Parameter**:
```java
// From parsed signature to function parameters
ParameterDefinition[] paramDefs = newSignature.getArguments();
List<Parameter> parameters = new ArrayList<>();

for (int i = 0; i < paramDefs.length; i++) {
    ParameterDefinition paramDef = paramDefs[i];
    Parameter param = new ParameterImpl(
        paramDef.getName(),
        paramDef.getDataType(),
        program
    );
    parameters.add(param);
}
```

### Transaction-Safe Prototype Updates
**Always wrap function modifications in transactions**:
```java
int transactionID = program.startTransaction("Set function prototype");
try {
    // Update return type
    function.setReturnType(newSignature.getReturnType(), SourceType.USER_DEFINED);
    
    // Update parameters
    function.replaceParameters(parameters, 
        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
        true, SourceType.USER_DEFINED);
    
    // Update calling convention if specified
    if (newSignature.getGenericCallingConvention() != null) {
        function.setCallingConvention(newSignature.getGenericCallingConvention().getName());
    }
    
    program.endTransaction(transactionID, true);
} catch (Exception e) {
    program.endTransaction(transactionID, false);
    throw e;
}
```

## Compact vs Verbose Mode

Both `get-functions` and `get-functions-by-similarity` support a `verbose` parameter (default: `false`).

### Compact Mode (Default)
Compact mode returns minimal data for efficient scanning:
```json
// get-functions compact output
{"name": "processAI", "address": "0x00401000", "sizeInBytes": 256, "tags": ["AI"], "callerCount": 5, "calleeCount": 3}

// get-functions-by-similarity compact output (includes similarity)
{"name": "processAI", "address": "0x00401000", "sizeInBytes": 256, "tags": ["AI"], "callerCount": 5, "calleeCount": 3, "similarity": 0.85}
```

**Note**: `callerCount`/`calleeCount` may be `-1` if computation timed out.

### Verbose Mode
Use `verbose: true` to get full function details (signature, parameters, returnType, isThunk, isExternal, etc.).

## Similarity Analysis

The `get-functions-by-similarity` tool uses LCS (Longest Common Substring) to rank functions by name similarity.

### Similarity Score
The `similarity` field (0.0-1.0) indicates how well the function name matches the search string.
Higher scores appear first in results.

### Function Comparison API
```java
import reva.util.SimilarityComparator;

// Calculate similarity between two strings (0.0 to 1.0)
double score = SimilarityComparator.calculateLcsSimilarity("search", "functionName");

// Sort functions by name similarity using comparator
SimilarityComparator<Map<String, Object>> comparator = new SimilarityComparator<>(
    searchString,
    funcInfo -> (String) funcInfo.get("name")
);
Collections.sort(functions, comparator);
```

## Function Filtering Patterns

### Default Name Filtering
**Always provide option to filter default Ghidra names**:
```java
boolean filterDefaultNames = getOptionalBoolean(request, "filterDefaultNames", true);

if (filterDefaultNames && SymbolUtil.isDefaultSymbolName(function.getName())) {
    // Skip this function
    continue;
}
```

### Thunk Function Handling
**Consider thunk functions separately**:
```java
boolean includeThunks = getOptionalBoolean(request, "includeThunks", false);

if (!includeThunks && function.isThunk()) {
    // Skip thunk functions
    continue;
}
```

## Error Handling Patterns

### Function Resolution Errors
```java
try {
    Function function = getFunctionFromArgs(args, program, "functionName");
} catch (IllegalArgumentException e) {
    return createErrorResult("Function not found: " + functionName);
}
```

### Prototype Update Errors
```java
try {
    function.setReturnType(returnType, SourceType.USER_DEFINED);
} catch (InvalidInputException e) {
    return createErrorResult("Invalid return type: " + e.getMessage());
} catch (DuplicateNameException e) {
    return createErrorResult("Parameter name conflict: " + e.getMessage());
}
```

## Response Patterns

### Function List Response
```java
Map<String, Object> result = Map.of(
    "functions", functionList,
    "pagination", Map.of(
        "startIndex", startIndex,
        "maxCount", maxCount,
        "returnedCount", functionList.size(),
        "totalCount", totalFunctionCount
    ),
    "programPath", program.getDomainFile().getPathname()
);
```

### Count Response
```java
Map<String, Object> countData = Map.of(
    "count", totalCount,
    "programPath", program.getDomainFile().getPathname(),
    "filtered", filterDefaultNames
);
```

## Testing Considerations

### Test Data Requirements
- Programs with various function types (regular, thunk, external)
- Functions with different calling conventions
- Functions with complex parameter lists
- Programs with both user-defined and default function names

### Integration Tests
- Verify function enumeration accuracy
- Test prototype updates persist correctly
- Validate similarity scoring consistency  
- Check pagination boundary conditions
- Ensure transaction rollback on errors

## Performance Considerations

### Large Program Handling
- Use pagination for programs with many functions
- Recommend chunks of 100 functions maximum
- Consider memory usage with similarity analysis
- Use AtomicInteger for efficient counting

### Function Iteration
```java
// Efficient function iteration pattern
FunctionIterator functions = program.getFunctionManager().getFunctions(true);
while (functions.hasNext() && collected.get() < maxCount) {
    Function function = functions.next();
    
    if (currentIndex.getAndIncrement() < startIndex) {
        continue; // Skip until start index
    }
    
    // Process function
    collected.incrementAndGet();
}
```

## Important Notes

- **Pagination**: Always provide pagination for function listing operations
- **Filtering**: Default to filtering out Ghidra-generated names
- **Transactions**: Required for all function modifications
- **Similarity**: Use SimilarityComparator for consistent scoring
- **Address Formatting**: Use AddressUtil.formatAddress() for addresses
- **Error Context**: Provide specific error messages for function resolution failures