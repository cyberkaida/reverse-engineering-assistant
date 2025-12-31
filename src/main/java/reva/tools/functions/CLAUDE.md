# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the functions tools package.

## Package Overview

The `reva.tools.functions` package provides MCP tools for function analysis, listing, and management operations in Ghidra programs. It handles function enumeration, similarity analysis, prototype manipulation, and function creation.

## Key Tools

- `get-function-count` - Get total count of functions (use before listing for pagination)
- `get-functions` - List functions with advanced filtering, sorting, and dependency analysis
- `get-functions-by-similarity` - Find functions similar to a target function (compact by default, use `verbose: true` for full details)
- `set-function-prototype` - Modify function signatures and prototypes with C-style signatures
- `get-undefined-function-candidates` - Find addresses that are referenced but not defined as functions
- `create-function` - Create a function at an address with auto-detected signature
- `function-tags` - Manage tags on functions (modes: get/set/add/remove/list)

## get-functions Parameters

The `get-functions` tool supports extensive filtering, sorting, and dependency analysis:

### Basic Filtering
| Parameter | Type | Description |
|-----------|------|-------------|
| `include` | string | `"all"`, `"named"` (default), or `"unnamed"` |
| `filterByTags` | string[] | Functions must have ANY of these tags (OR logic) |
| `excludeTags` | string[] | Functions must NOT have ANY of these tags |
| `untagged` | boolean | Only functions with no tags (mutually exclusive with filterByTags) |

### Count Range Filtering
| Parameter | Type | Description |
|-----------|------|-------------|
| `minCalleeCount` | integer | Minimum callees (functions this function calls) |
| `maxCalleeCount` | integer | Maximum callees |
| `minCallerCount` | integer | Minimum callers (functions that call this function) |
| `maxCallerCount` | integer | Maximum callers |

### Sorting
| Parameter | Type | Description |
|-----------|------|-------------|
| `sortBy` | string | `"address"`, `"name"`, `"calleeCount"`, `"callerCount"`, `"sizeInBytes"` |
| `sortOrder` | string | `"ascending"` (default) or `"descending"` |

### Dependency Filtering (Bottom-Up Porting Workflow)
| Parameter | Type | Description |
|-----------|------|-------------|
| `requireCalleesTagged` | string[] | All callees must have ALL of these tags (or be external/thunks) |
| `allowExternalCallees` | boolean | External/thunk callees exempt from tag requirement (default: true) |
| `allowUntaggedCallees` | boolean | Untagged callees exempt from tag requirement (default: false) |

### Output Options
| Parameter | Type | Description |
|-----------|------|-------------|
| `verbose` | boolean | Full function details (default: false) |
| `includeCallees` | boolean | Include callee details in response (default: false) |
| `startIndex` | integer | Pagination start (default: 0) |
| `maxCount` | integer | Max results per page (default: 100) |

### Example: Find Functions Ready to Port
```json
{
  "programPath": "/trafficgiant.exe",
  "requireCalleesTagged": ["ported"],
  "excludeTags": ["ported"],
  "maxCalleeCount": 5,
  "sortBy": "calleeCount",
  "sortOrder": "ascending",
  "includeCallees": true
}
```
Returns functions where:
- Function is NOT tagged "ported"
- ALL callees ARE tagged "ported" (or are external/thunks)
- Has ≤5 callees (simpler functions first)
- Includes callee details showing what each function depends on

## Function Include Filter

All three function listing tools (`get-function-count`, `get-functions`, `get-functions-by-similarity`) support the `include` parameter:

| Value | Description |
|-------|-------------|
| `"all"` | Include all functions |
| `"named"` | Only user-named functions (excludes FUN_*, DAT_*, etc.) - **DEFAULT** |
| `"unnamed"` | Only default Ghidra names (FUN_*, DAT_*, etc.) |

**Example usage:**
```json
// Count unnamed functions (what still needs analysis)
{"programPath": "/prog", "include": "unnamed"}

// List all functions including default names
{"programPath": "/prog", "include": "all"}

// Search for similar functions among unnamed ones
{"programPath": "/prog", "searchString": "init", "include": "unnamed"}
```

## Core Patterns

### Function Enumeration with Include Filter
**Use IncludeFilterUtil for include-based filtering**:
```java
import reva.util.IncludeFilterUtil;

// Validate include parameter (defaults to "named")
String include = IncludeFilterUtil.validate(getOptionalString(request, "include", null));

FunctionIterator functions = program.getFunctionManager().getFunctions(true);
functions.forEach(function -> {
    if (!IncludeFilterUtil.shouldInclude(function.getName(), include)) {
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
**Standard function information format** (from createFunctionInfo):
```java
Map<String, Object> functionData = Map.of(
    "name", function.getName(),
    "address", AddressUtil.formatAddress(function.getEntryPoint()),
    "endAddress", AddressUtil.formatAddress(body.getMaxAddress()),
    "sizeInBytes", body.getNumAddresses(),
    "signature", function.getSignature().toString(),
    "returnType", function.getReturnType().toString(),
    "isExternal", function.isExternal(),
    "isThunk", function.isThunk(),
    "isDefaultName", SymbolUtil.isDefaultSymbolName(function.getName()),
    "callerCount", callerCount,  // -1 if timed out
    "calleeCount", calleeCount,  // -1 if timed out
    "parameters", parametersList,  // List of {name, dataType} maps
    "tags", tagNames  // Sorted list of tag names
);
```

**Note**: `callerCount` and `calleeCount` may be `-1` if computation timed out (uses TaskMonitor).

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
Use `get-functions` with `filterByTags` parameter (array) to find all functions with any of the specified tags.
Use `get-functions` with `excludeTags` parameter to exclude functions with certain tags.
Use `get-functions` with `untagged: true` to find functions that have no tags (useful for tracking progress).
Note: `filterByTags` and `untagged` are mutually exclusive.

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

// 3. Find all AI or rendering functions via get-functions
{"programPath": "/prog", "filterByTags": ["AI", "rendering"]}
// Returns paginated list of functions tagged with either "AI" or "rendering"

// 4. Find untagged functions (what still needs categorization)
{"programPath": "/prog", "untagged": true}
// Returns paginated list of functions with no tags

// 5. Find functions tagged "AI" but not "ported"
{"programPath": "/prog", "filterByTags": ["AI"], "excludeTags": ["ported"]}
// Returns AI functions that haven't been ported yet
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

## Function Creation and Prototype Management

### Creating Functions
**Use CreateFunctionCmd for simple function creation**:
```java
import ghidra.app.cmd.function.CreateFunctionCmd;

// create-function tool uses this approach
CreateFunctionCmd cmd = new CreateFunctionCmd(address);
boolean success = cmd.applyTo(program);
if (!success) {
    String statusMsg = cmd.getStatusMsg();
    // Handle error
}

// Ghidra automatically determines function body, parameters, and return type
Function createdFunc = program.getFunctionManager().getFunctionAt(address);
```

### Undefined Function Candidates
**The get-undefined-function-candidates tool finds potential functions**:
- Scans all CALL and DATA references in the program
- Filters to addresses that:
  - Are NOT already defined as functions
  - Are in executable memory with valid instructions
  - Are not in PLT/GOT/import sections (excluded patterns)
  - Have at least `minReferenceCount` references (default: 1)
- Returns candidates sorted by reference count (descending)
- Includes flags: `hasCallReference`, `hasDataReference`
- Use with `create-function` to define discovered functions

**Memory protection**: Stops after `MAX_UNIQUE_CANDIDATES` (10,000) to prevent memory exhaustion.

The `set-function-prototype` tool supports two modes:

### Simple Rename
Use `newName` for quick renames without changing the signature:
```json
{"programPath": "/prog", "location": "0x00401000", "newName": "ProcessGameState"}
```

### Full Prototype Change
Use `signature` for complete prototype changes (return type, parameters, name):
```json
{"programPath": "/prog", "location": "0x00401000", "signature": "int ProcessGameState(GameContext* ctx)"}
```

**Note**: The `location` parameter accepts both addresses (e.g., `"0x00401000"`) and symbol names (e.g., `"FUN_00401000"`).

**Important Notes**:
- `newName` and `signature` are mutually exclusive
- `newName` only works with existing functions; use `signature` with `createIfNotExists` to create new functions
- Renaming to the same name is a no-op (succeeds without changes)
- Renaming fails if the name already exists in the same namespace
- Invalid function names will be rejected by Ghidra

### Signature Parsing
**Use FunctionSignatureParser for prototype changes**:
```java
import ghidra.app.util.parser.FunctionSignatureParser;

// set-function-prototype tool uses this approach
FunctionSignatureParser parser = new FunctionSignatureParser(
    program.getDataTypeManager(), null);

// Parse with normalization (handles whitespace issues)
String normalizedSignature = normalizeFunctionSignature(signature);
FunctionDefinitionDataType functionDef = parser.parse(
    originalSignature,  // Existing function signature (or null)
    normalizedSignature);

// Note: parser.parse() can throw ParseException
```

**Signature Normalization**: The `normalizeFunctionSignature` method fixes whitespace issues:
- `"char *func("` → `"char* func("` (space before * causes parsing failures)
- Uses regex: `(\\w+)\\s+\\*(\\w+)\\(` → `$1* $2(`

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

### Custom Storage for Auto-Parameters
**Handle auto-parameter modifications (e.g., 'this' in __thiscall)**:
```java
// Check if applying signature requires custom storage
boolean needsCustomStorage = needsCustomStorageForSignature(function, functionDef);
boolean wasUsingCustomStorage = function.hasCustomVariableStorage();

if (needsCustomStorage && !wasUsingCustomStorage) {
    // Enable custom storage to modify auto-parameters
    function.setCustomVariableStorage(true);
}

// Create parameters with preserved storage if using custom storage
List<Variable> parameters = new ArrayList<>();
ParameterDefinition[] paramDefs = functionDef.getArguments();
Parameter[] existingParams = function.getParameters();

for (int i = 0; i < paramDefs.length; i++) {
    if (function.hasCustomVariableStorage() && i < existingParams.length) {
        // Preserve existing parameter's storage
        parameters.add(new ParameterImpl(
            paramDef.getName(),
            paramDef.getDataType(),
            existingParams[i].getVariableStorage(),  // Keep storage
            program));
    } else {
        // Auto-assign storage
        parameters.add(new ParameterImpl(
            paramDef.getName(),
            paramDef.getDataType(),
            program));
    }
}
```

**Important**: `needsCustomStorageForSignature` checks if:
- Any auto-parameter's data type is being changed
- Auto-parameters are being removed
If true, custom storage must be enabled before modification.

### Transaction-Safe Prototype Updates
**Always wrap function modifications in transactions**:
```java
int txId = program.startTransaction("Set function prototype");
try {
    // Update function name if different
    if (!function.getName().equals(functionDef.getName())) {
        function.setName(functionDef.getName(), SourceType.USER_DEFINED);
    }

    // Update return type
    function.setReturnType(functionDef.getReturnType(), SourceType.USER_DEFINED);

    // Update parameters (use appropriate update type)
    Function.FunctionUpdateType updateType = function.hasCustomVariableStorage()
        ? Function.FunctionUpdateType.CUSTOM_STORAGE
        : Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS;

    function.replaceParameters(parameters, updateType, true, SourceType.USER_DEFINED);

    // Set varargs if needed
    if (functionDef.hasVarArgs() != function.hasVarArgs()) {
        function.setVarArgs(functionDef.hasVarArgs());
    }

    program.endTransaction(txId, true);
} catch (Exception e) {
    program.endTransaction(txId, false);
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

### Include Parameter Filtering
**Use the include parameter for name-based filtering**:
```java
String include = IncludeFilterUtil.validate(getOptionalString(request, "include", null));

// Filter using shouldIncludeFunctionInfo helper (for cached function info maps)
List<Map<String, Object>> filtered = allFunctions.stream()
    .filter(f -> shouldIncludeFunctionInfo(f, include))
    .toList();
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
    "include", include  // "all", "named", or "unnamed"
);
```

## Testing Considerations

### Test Data Requirements
- Programs with various function types (regular, thunk, external)
- Functions with different calling conventions
- Functions with complex parameter lists
- Programs with both user-defined and default function names
- Programs with undefined function candidates (addresses with references but no function)
- Programs with function tags (test get/set/add/remove operations)

### Integration Tests
- Verify function enumeration accuracy
- Test prototype updates persist correctly (including custom storage scenarios)
- Validate similarity scoring consistency (substring pre-filter + LCS)
- Check pagination boundary conditions
- Ensure transaction rollback on errors
- Test function creation from undefined candidates
- Verify tag operations and cache invalidation
- Test caller/callee count timeout handling (-1 values)
- Verify cache expiration and synchronization

## Caching Architecture

### Two-Level Cache System
FunctionToolProvider implements a sophisticated caching system to optimize performance:

**1. Function Info Cache** (`functionInfoCache`):
- **Purpose**: Shared cache for raw function data (used by both `get-functions` and `get-functions-by-similarity`)
- **Key**: `FunctionInfoCacheKey(programPath, filterDefaultNames)`
- **Value**: `CachedFunctionInfo(functions, timestamp, programModificationNumber)`
- **Expiration**: 10 minutes
- **Size Limit**: 10 entries (program/filter combinations)
- **Why**: Computing caller/callee counts is expensive (requires TaskMonitor)

**2. Similarity Search Cache** (`similarityCache`):
- **Purpose**: Cache sorted similarity search results (LCS computation is expensive)
- **Key**: `SimilarityCacheKey(programPath, searchString, filterDefaultNames)`
- **Value**: `CachedSearchResult(sortedFunctions, timestamp, totalCount, programModificationNumber)`
- **Expiration**: 10 minutes
- **Size Limit**: 50 entries, max 2000 results per search
- **Why**: LCS-based sorting is CPU-intensive for large function lists

### Cache Invalidation
```java
// Invalidate when function metadata changes (e.g., tags modified)
private void invalidateFunctionCaches(String programPath) {
    functionInfoCache.entrySet().removeIf(entry -> entry.getKey().programPath().equals(programPath));
    similarityCache.entrySet().removeIf(entry -> entry.getKey().programPath().equals(programPath));
}

// Called automatically on programClosed()
@Override
public void programClosed(Program program) {
    super.programClosed(program);
    String programPath = program.getDomainFile().getPathname();
    // Clear both caches for this program
}
```

### Cache Synchronization
**Critical**: Building caches uses synchronized blocks to prevent duplicate work:
```java
synchronized (functionInfoCache) {
    // Double-check pattern - another thread may have built cache
    cached = functionInfoCache.get(cacheKey);
    if (cached != null && !cached.isExpired() && cached.programModificationNumber() == currentModNumber) {
        return cached.functions();
    }
    // Build cache...
}
```

### Similarity Search Optimization
**Two-phase approach** for better performance:
1. **Pre-filter**: Separate substring matches from non-matches
2. **Sort substring matches** (small list, best candidates)
3. **Optionally sort non-matches** if substring matches < 1000

```java
String searchLower = searchString.toLowerCase();
List<Map<String, Object>> substringMatches = new ArrayList<>();
List<Map<String, Object>> nonMatches = new ArrayList<>();

for (Map<String, Object> functionInfo : allFunctions) {
    String nameLower = ((String) functionInfo.get("name")).toLowerCase();
    if (nameLower.contains(searchLower)) {
        substringMatches.add(functionInfo);
    } else {
        nonMatches.add(functionInfo);
    }
}

// Sort substring matches (best candidates)
Collections.sort(substringMatches, comparator);
// Only sort non-matches if needed
if (substringMatches.size() < 1000) {
    Collections.sort(nonMatches, comparator);
}
```

## Performance Considerations

### Large Program Handling
- Use pagination for programs with many functions
- Recommend chunks of 100 functions maximum
- Consider memory usage with similarity analysis
- Use AtomicInteger for efficient counting
- **Function info cache** eliminates redundant caller/callee computation
- **Similarity cache** eliminates redundant LCS sorting

### Timeout Protection
- **Function info cache**: 300-second timeout (checks every 100 functions)
- **Similarity search**: 120-second timeout
- **Caller/callee counts**: Use TaskMonitor, return -1 if cancelled
- **Slow operation logging**: Warns if operations take > 5 seconds

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

## Undefined Function Candidate Analysis

### What It Finds
The `get-undefined-function-candidates` tool identifies potential functions that Ghidra's auto-analysis missed:
- Scans ALL references in the program (CALL and DATA types)
- Focuses on addresses that are **referenced but not defined as functions**
- Filters to executable memory with valid instructions

### Filtering Strategy
**Exclusions** (to reduce false positives):
- Already defined functions
- External addresses
- Non-executable memory blocks
- PLT/GOT/import sections (patterns: `.plt`, `.got`, `.idata`, `.edata`, `extern`, `external`)
- Addresses without instructions (IAT thunks, data pointers)

**Cached optimization**: Memory block exclusion status is cached to avoid recalculating for every reference.

### Reference Type Tracking
Each candidate includes:
- `hasCallReference` - Direct function calls (`CALL` instruction targets)
- `hasDataReference` - Function pointer references (callbacks, vtables, exception handlers)
- `sampleReferences` - Up to 5 example callers with function names/addresses

### Workflow Pattern
```java
// 1. Find candidates
get-undefined-function-candidates → returns sorted list by reference count

// 2. Preview candidate (use decompiler tool)
get-decompilation → check if it looks like a function

// 3. Create function
create-function → Ghidra auto-detects signature
// OR
set-function-prototype → explicit signature control
```

### Memory Protection
- **MAX_UNIQUE_CANDIDATES**: 10,000 candidates (early termination if exceeded)
- Prevents memory exhaustion on large programs with many undefined references
- `earlyTermination` flag indicates incomplete results

## Important Notes

- **Pagination**: Always provide pagination for function listing operations
- **Include Parameter**: Use `include` parameter with values "all", "named", "unnamed" (default: "named")
- **Transactions**: Required for all function modifications
- **Similarity**: Use SimilarityComparator for consistent scoring
- **Address Formatting**: Use AddressUtil.formatAddress() for addresses
- **Error Context**: Provide specific error messages for function resolution failures
- **Cache Invalidation**: Call `invalidateFunctionCaches()` after modifying function metadata (e.g., tags)
- **Cache Strategy**: Function info is cached per-program (all functions), filtering applied at query time
- **Thread Safety**: Both caches use ConcurrentHashMap and synchronized blocks for safe concurrent access
- **Timeout Handling**: Caller/callee counts may be -1 if computation timed out (check before using)
