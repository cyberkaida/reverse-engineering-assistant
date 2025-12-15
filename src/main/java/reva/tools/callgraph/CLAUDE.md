# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the call graph tools package.

## Package Overview

The `reva.tools.callgraph` package provides MCP tools for analyzing function call relationships and hierarchies in Ghidra programs. It enables discovering caller/callee relationships, building hierarchical call trees, and finding common callers across multiple functions. Uses Ghidra's built-in `Function.getCallingFunctions()` and `Function.getCalledFunctions()` for accurate call relationship detection.

## Key Tools

- `get-call-graph` - Get bidirectional call graph around a function (callers + callees) up to specified depth
- `get-call-tree` - Get hierarchical call tree in one direction (callers upward or callees downward)
- `find-common-callers` - Find functions that call ALL specified target functions

## Core Concepts

### Graph vs Tree Views

**Graph View** (`get-call-graph`):
- Shows both directions simultaneously (callers AND callees)
- Uses permanent visited tracking to avoid duplicates
- Each function appears only once per direction
- Best for understanding a function's immediate context
- Limited to 250 nodes per direction (MAX_NODES_PER_DIRECTION)

**Tree View** (`get-call-tree`):
- Shows only one direction (callers OR callees)
- Uses temporary visited tracking (allows same function in different branches)
- Same function can appear multiple times in different paths
- Best for understanding hierarchical call sequences
- Limited to 500 total nodes (MAX_NODES_TREE)

### Depth and Node Limits

**Depth Clamping**:
```java
private static final int MAX_DEPTH_LIMIT = 10;

private int clampDepth(int depth) {
    if (depth < 1) return 1;
    if (depth > MAX_DEPTH_LIMIT) return MAX_DEPTH_LIMIT;
    return depth;
}
```

**Node Count Tracking**:
- Use `int[]` for pass-by-reference counting in recursive methods
- Separate counters for callers vs callees in graph view
- Single counter for tree view

## Call Graph Analysis

### Building Bidirectional Graphs

**Pattern for get-call-graph tool**:
```java
// Separate visited sets and counters for each direction
Set<String> callerVisited = new HashSet<>();
Set<String> calleeVisited = new HashSet<>();
int[] callerNodeCount = {0};
int[] calleeNodeCount = {0};

// Build caller graph (upward) with independent tracking
List<Map<String, Object>> callers = buildGraphList(centerFunction, depth,
    callerVisited, callerNodeCount, true, monitor);

// Build callee graph (downward) with independent tracking
List<Map<String, Object>> callees = buildGraphList(centerFunction, depth,
    calleeVisited, calleeNodeCount, false, monitor);
```

### Graph List Building

**Use permanent visited tracking to prevent duplicates**:
```java
private List<Map<String, Object>> buildGraphList(Function function,
        int depth, Set<String> visited, int[] nodeCount, boolean getCallers,
        TaskMonitor monitor) throws CancelledException {

    if (depth <= 0 || nodeCount[0] >= MAX_NODES_PER_DIRECTION) {
        return List.of();
    }

    Set<Function> related = getCallers
        ? function.getCallingFunctions(monitor)
        : function.getCalledFunctions(monitor);

    for (Function relatedFunc : related) {
        String funcKey = getFunctionKey(relatedFunc);
        boolean isCycle = visited.contains(funcKey);

        if (isCycle) {
            // Mark as cyclic, don't recurse
            info.put("cyclic", true);
        } else {
            visited.add(funcKey);  // Permanent - stays in set
            nodeCount[0]++;

            // Recurse to build nested structure
            if (depth > 1) {
                List<Map<String, Object>> nested = buildGraphList(
                    relatedFunc, depth - 1, visited, nodeCount, getCallers, monitor);
                if (!nested.isEmpty()) {
                    info.put(getCallers ? "callers" : "callees", nested);
                }
            }
        }
    }
}
```

## Call Tree Analysis

### Hierarchical Tree Building

**Use temporary visited tracking for path-based cycle detection**:
```java
private Map<String, Object> buildTree(Function function,
        int maxDepth, int currentDepth, Set<String> visited, int[] nodeCount,
        boolean getCallers, TaskMonitor monitor) throws CancelledException {

    String funcKey = getFunctionKey(function);

    // Cycle detection within current path
    if (visited.contains(funcKey)) {
        node.put("cyclic", true);
        return node;  // Don't recurse
    }

    // Mark as visited for this path
    visited.add(funcKey);
    nodeCount[0]++;

    Set<Function> related = getCallers
        ? function.getCallingFunctions(monitor)
        : function.getCalledFunctions(monitor);

    if (!related.isEmpty()) {
        List<Map<String, Object>> childNodes = new ArrayList<>();
        for (Function relatedFunc : related) {
            childNodes.add(buildTree(relatedFunc, maxDepth,
                currentDepth + 1, visited, nodeCount, getCallers, monitor));
        }
        node.put(getCallers ? "callers" : "callees", childNodes);
    }

    // Remove from visited to allow this function in other branches
    visited.remove(funcKey);  // CRITICAL: Temporary tracking
    return node;
}
```

### Direction Parameter Handling

**Validate and interpret direction parameter**:
```java
String direction = getOptionalString(request, "direction", "callees");

// Validate direction parameter
if (!"callers".equalsIgnoreCase(direction) && !"callees".equalsIgnoreCase(direction)) {
    return createErrorResult("Invalid direction: '" + direction +
        "'. Must be 'callers' or 'callees'.");
}

boolean traverseCallers = "callers".equalsIgnoreCase(direction);
```

## Common Caller Analysis

### Finding Intersection of Caller Sets

**Use set intersection to find common callers**:
```java
private McpSchema.CallToolResult findCommonCallers(Program program,
        List<Function> targetFunctions) {
    Set<Function> commonCallers = null;

    for (Function targetFunc : targetFunctions) {
        Set<Function> callersOfThis = targetFunc.getCallingFunctions(monitor);

        if (commonCallers == null) {
            commonCallers = new HashSet<>(callersOfThis);  // First set
        } else {
            commonCallers.retainAll(callersOfThis);  // Intersection
        }

        // Early exit if no common callers remain
        if (commonCallers.isEmpty()) {
            break;
        }
    }

    return createResult(commonCallers);
}
```

### Multi-Function Resolution

**Resolve multiple function addresses from parameter list**:
```java
List<String> addressStrings = getStringList(request.arguments(), "functionAddresses");

if (addressStrings.isEmpty()) {
    return createErrorResult("At least one function address is required");
}

List<Function> targetFunctions = new ArrayList<>();
for (String addrStr : addressStrings) {
    Address addr = AddressUtil.resolveAddressOrSymbol(program, addrStr);
    if (addr == null) {
        return createErrorResult("Could not resolve address: " + addrStr);
    }
    Function func = resolveFunction(program, addr);
    if (func == null) {
        return createErrorResult("No function at address: " + addrStr);
    }
    targetFunctions.add(func);
}
```

## Function Resolution Patterns

### Flexible Function Resolution

**Try multiple resolution strategies**:
```java
private Function resolveFunction(Program program, Address address) {
    // First try exact match at address
    Function function = program.getFunctionManager().getFunctionAt(address);
    if (function == null) {
        // Fall back to containing function
        function = program.getFunctionManager().getFunctionContaining(address);
    }
    return function;
}
```

### Function Key Generation

**Use formatted address as unique identifier**:
```java
private String getFunctionKey(Function function) {
    return AddressUtil.formatAddress(function.getEntryPoint());
}
```

## Timeout and Cancellation

### Creating Timeout Monitors

**Use TimeoutTaskMonitor for long-running operations**:
```java
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import java.util.concurrent.TimeUnit;

private static final int DEFAULT_TIMEOUT_SECONDS = 60;

private TaskMonitor createTimeoutMonitor() {
    return TimeoutTaskMonitor.timeoutIn(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
}
```

### Checking for Cancellation

**Propagate CancelledException from recursive methods**:
```java
try {
    monitor.checkCancelled();  // Check before potentially long operation

    Set<Function> related = function.getCallingFunctions(monitor);
    // Process related functions

} catch (CancelledException e) {
    return createErrorResult("Operation cancelled or timed out");
}
```

## Response Structure Patterns

### Call Graph Response

**Include metadata and counts for both directions**:
```java
Map<String, Object> result = new HashMap<>();
result.put("programPath", program.getDomainFile().getPathname());
result.put("centerFunction", Map.of(
    "name", centerFunction.getName(),
    "address", AddressUtil.formatAddress(centerFunction.getEntryPoint())
));
result.put("depth", depth);
result.put("callerCount", callerNodeCount[0]);
result.put("calleeCount", calleeNodeCount[0]);
result.put("callers", callers);
result.put("callees", callees);
```

### Call Tree Response

**Include direction and depth metadata**:
```java
Map<String, Object> result = new HashMap<>();
result.put("programPath", program.getDomainFile().getPathname());
result.put("direction", traverseCallers ? "callers" : "callees");
result.put("maxDepth", maxDepth);
result.put("totalNodes", nodeCount[0]);
result.put("tree", tree);
```

### Common Callers Response

**Include sorted caller list with counts**:
```java
// Sort by address for consistent ordering
callerList.sort((a, b) -> {
    String addrStrA = (String) a.get("address");
    String addrStrB = (String) b.get("address");
    if (addrStrA == null && addrStrB == null) return 0;
    if (addrStrA == null) return 1;  // Nulls sort to end
    if (addrStrB == null) return -1;
    return addrStrA.compareTo(addrStrB);  // String comparison of hex addresses
});

Map<String, Object> result = new HashMap<>();
result.put("programPath", program.getDomainFile().getPathname());
result.put("targetFunctions", targetFunctionList);
result.put("commonCallerCount", callerList.size());
result.put("commonCallers", callerList);
```

### Node Information Structure

**Standard function node format**:
```java
Map<String, Object> info = new HashMap<>();
info.put("name", function.getName());
info.put("address", AddressUtil.formatAddress(function.getEntryPoint()));

// Optional fields based on context
info.put("depth", currentDepth);        // For tree nodes
info.put("cyclic", true);               // When cycle detected
info.put("truncated", true);            // When depth limit reached
info.put("callers", nestedCallers);     // Nested list
info.put("callees", nestedCallees);     // Nested list
```

## Cycle Detection Strategies

### Graph View (Permanent Visited)

**Each function appears only once per direction**:
- Use `Set<String> visited` to track all seen functions
- Once in visited set, mark as cyclic on subsequent encounters
- Visited set persists across all branches
- Prevents duplicate nodes in the same direction

### Tree View (Temporary Visited)

**Same function can appear in different paths**:
- Use `Set<String> visited` to track current path only
- Add to visited when entering a node
- Remove from visited when leaving a node (backtracking)
- Detects cycles within a single path
- Allows same function in different branches

## Performance Considerations

### Node Count Limits

**Different limits for different views**:
```java
private static final int MAX_NODES_PER_DIRECTION = 250;  // Graph view
private static final int MAX_NODES_TREE = 500;           // Tree view (higher)
```

**Why tree limit is higher**:
- Tree view allows duplicate functions in different branches
- Graph view prevents all duplicates
- Tree provides more complete hierarchical picture

### Early Termination

**Check limits at multiple points**:
```java
// Check before starting recursion
if (depth <= 0 || nodeCount[0] >= MAX_NODES) {
    return List.of();
}

// Check during iteration
for (Function relatedFunc : related) {
    if (nodeCount[0] >= MAX_NODES) break;
    // Process function
}
```

### Timeout Management

**60-second default timeout for complex call graphs**:
- Large programs can have deeply nested call hierarchies
- Recursive functions can create complex cycles
- Monitor checks prevent infinite loops
- Return partial results with error on timeout

## Tool Usage Examples

### Analyzing Function Context

```json
// Get immediate context (1 level up and down)
{
  "programPath": "/program.exe",
  "functionAddress": "main",
  "depth": 1
}
// Returns: Both direct callers and direct callees
```

### Tracing Call Paths

```json
// Trace who ultimately calls this function
{
  "programPath": "/program.exe",
  "functionAddress": "process_data",
  "direction": "callers",
  "maxDepth": 5
}
// Returns: Hierarchical tree showing all call paths leading to process_data
```

### Finding Integration Points

```json
// Find functions that call both init_audio and init_video
{
  "programPath": "/program.exe",
  "functionAddresses": ["init_audio", "init_video"]
}
// Returns: List of functions that call both (likely initialization functions)
```

## Testing Considerations

### Test Data Requirements
- Programs with deep call hierarchies (5+ levels)
- Programs with recursive functions (direct and indirect)
- Programs with complex cross-calling patterns
- Functions with many callers/callees (100+)
- Mix of user-defined and library functions

### Integration Test Patterns

**Verify cycle detection**:
```java
// Test with recursive function
JsonNode tree = callTreeResult.get("tree");
boolean foundCycle = containsCyclicNode(tree);
assertTrue("Should detect cycle in recursive function", foundCycle);
```

**Verify depth limiting**:
```java
// Request depth 3, verify no nodes beyond depth 3
int maxDepthFound = findMaxDepth(tree);
assertTrue("Max depth should not exceed 3", maxDepthFound <= 3);
```

**Verify node count limits**:
```java
// Count total nodes in result
int totalNodes = countNodes(graphResult.get("callers"));
assertTrue("Should respect node limit", totalNodes <= MAX_NODES_PER_DIRECTION);
```

**Verify common caller intersection**:
```java
// Find common callers of func1 and func2
JsonNode commonCallers = result.get("commonCallers");
// Manually verify each caller actually calls both targets
for (JsonNode caller : commonCallers) {
    Function callerFunc = getFunction(caller.get("address").asText());
    assertTrue(callsFunction(callerFunc, func1));
    assertTrue(callsFunction(callerFunc, func2));
}
```

## Error Handling

### Function Resolution Errors
```java
Function function = resolveFunction(program, address);
if (function == null) {
    return createErrorResult("No function at address: " +
        AddressUtil.formatAddress(address));
}
```

### Timeout Errors
```java
try {
    // Build call graph with timeout monitor
} catch (CancelledException e) {
    return createErrorResult("Operation cancelled or timed out");
}
```

### Parameter Validation
```java
if (addressStrings.isEmpty()) {
    return createErrorResult("At least one function address is required");
}

if (!"callers".equalsIgnoreCase(direction) && !"callees".equalsIgnoreCase(direction)) {
    return createErrorResult("Invalid direction: '" + direction +
        "'. Must be 'callers' or 'callees'.");
}
```

## Important Notes

- **Graph vs Tree**: Graph prevents all duplicates per direction, tree allows duplicates across branches
- **Cycle Detection**: Graph uses permanent visited, tree uses temporary (backtracking) visited
- **Node Limits**: 250 per direction for graph, 500 total for tree
- **Depth Limits**: Maximum depth is 10 (clamped automatically)
- **Function Resolution**: Supports both exact addresses and symbol names via AddressUtil
- **Timeout**: 60-second default for all operations
- **Cancellation**: Always check monitor.checkCancelled() in loops and before long operations
- **Address Formatting**: Use AddressUtil.formatAddress() for all address outputs
- **Sorting**: Common callers sorted by address for consistent ordering
