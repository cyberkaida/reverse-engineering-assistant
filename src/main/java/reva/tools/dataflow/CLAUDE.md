# Data Flow Tools Package - CLAUDE.md

This file provides guidance for working with the data flow analysis tools package in ReVa (Reverse Engineering Assistant).

## Package Overview

The `reva.tools.dataflow` package provides comprehensive data flow analysis capabilities for reverse engineering. It leverages Ghidra's SSA (Static Single Assignment) form from the decompiler to trace how values flow through functions using Varnode def-use chains. The package enables backward slicing (finding origins) and forward slicing (finding uses) for program analysis.

## Key Tools for Data Flow Analysis

The DataFlowToolProvider implements three main tools:

### 1. trace-data-flow-backward
- **Purpose**: Trace where a value at an address comes from
- **Parameters**:
  - `programPath` (required) - Path to the program in Ghidra project
  - `address` (required) - Address within a function to trace backward from
- **Returns**: JSON object with operation list and terminators showing origins
- **Use Case**: Finding the source of a value (constants, parameters, memory loads, etc.)

### 2. trace-data-flow-forward
- **Purpose**: Trace where a value at an address flows to
- **Parameters**:
  - `programPath` (required) - Path to the program in Ghidra project
  - `address` (required) - Address within a function to trace forward from
- **Returns**: JSON object with operation list and terminators showing uses
- **Use Case**: Finding where a value is used (stores, function calls, returns, etc.)

### 3. find-variable-accesses
- **Purpose**: Find all reads and writes to a variable within a function
- **Parameters**:
  - `programPath` (required) - Path to the program in Ghidra project
  - `functionAddress` (required) - Address of the function to analyze
  - `variableName` (required) - Name of the variable to find accesses for
- **Returns**: JSON object with all read/write accesses to the variable
- **Use Case**: Understanding how a variable is used throughout a function

## Critical Implementation Patterns

### Decompiler Configuration for Data Flow

**CRITICAL: Must enable syntax tree for SSA/data flow analysis**:
```java
private DecompInterface createConfiguredDecompiler(Program program) {
    DecompInterface decompiler = new DecompInterface();
    decompiler.toggleCCode(false);          // Don't need C code for data flow
    decompiler.toggleSyntaxTree(true);      // CRITICAL: Required for SSA/data flow analysis
    decompiler.setSimplificationStyle("decompile");

    if (!decompiler.openProgram(program)) {
        return null;
    }
    return decompiler;
}
```

### Decompiler Lifecycle Management

**ALWAYS dispose of DecompInterface instances**:
```java
DecompInterface decompiler = createConfiguredDecompiler(program);
if (decompiler == null) {
    return createErrorResult("Failed to initialize decompiler");
}
try {
    // Use decompiler for analysis
} finally {
    decompiler.dispose(); // CRITICAL - prevents memory leaks
}
```

### Timeout Configuration

Use ConfigManager for timeout settings:
```java
private int getDecompilerTimeout() {
    try {
        ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
        if (configManager != null) {
            return configManager.getDecompilerTimeoutSeconds();
        }
    } catch (Exception e) {
        // Fall through to default
    }
    return DEFAULT_DECOMPILER_TIMEOUT_SECS;
}

// Use with TimeoutTaskMonitor
TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(timeout, TimeUnit.SECONDS);
DecompileResults results = decompiler.decompileFunction(function, timeout, monitor);
```

## Data Flow Slicing Techniques

### Varnode Discovery at Address

Find all varnodes (data flow values) at a specific address:
```java
private List<Varnode> findVarnodesAtAddress(HighFunction hf, Address targetAddress) {
    List<Varnode> varnodes = new ArrayList<>();

    Iterator<PcodeOpAST> ops = hf.getPcodeOps(targetAddress);
    while (ops.hasNext()) {
        PcodeOpAST op = ops.next();

        // Add output varnode
        Varnode output = op.getOutput();
        if (output != null) {
            varnodes.add(output);
        }

        // Add input varnodes (skip constants for forward slice seeds)
        for (int i = 0; i < op.getNumInputs(); i++) {
            Varnode input = op.getInput(i);
            if (input != null && !input.isConstant()) {
                varnodes.add(input);
            }
        }
    }

    return varnodes;
}
```

### Backward Slicing (Finding Origins)

Use DecompilerUtils for efficient backward slicing:
```java
private Set<PcodeOp> collectBackwardSlice(List<Varnode> seedVarnodes) {
    Set<PcodeOp> result = new HashSet<>();
    outer:
    for (Varnode seed : seedVarnodes) {
        Set<PcodeOp> slice = DecompilerUtils.getBackwardSliceToPCodeOps(seed);
        if (slice != null) {
            for (PcodeOp op : slice) {
                result.add(op);
                if (result.size() >= MAX_SLICE_SIZE) break outer;
            }
        }
    }
    return result;
}
```

### Forward Slicing (Finding Uses)

Use DecompilerUtils for efficient forward slicing:
```java
private Set<PcodeOp> collectForwardSlice(List<Varnode> seedVarnodes) {
    Set<PcodeOp> result = new HashSet<>();
    outer:
    for (Varnode seed : seedVarnodes) {
        Set<PcodeOp> slice = DecompilerUtils.getForwardSliceToPCodeOps(seed);
        if (slice != null) {
            for (PcodeOp op : slice) {
                result.add(op);
                if (result.size() >= MAX_SLICE_SIZE) break outer;
            }
        }
    }
    return result;
}
```

### Slice Size Limiting

**Prevent excessive slices with MAX_SLICE_SIZE**:
```java
private static final int MAX_SLICE_SIZE = 500;

// Break outer loop when limit reached
outer:
for (Varnode seed : seedVarnodes) {
    Set<PcodeOp> slice = DecompilerUtils.getBackwardSliceToPCodeOps(seed);
    if (slice != null) {
        for (PcodeOp op : slice) {
            result.add(op);
            if (result.size() >= MAX_SLICE_SIZE) break outer;
        }
    }
}
```

## Variable Analysis Patterns

### Finding Variables by Name

Search both local and global symbol maps:
```java
private HighVariable findVariableByName(HighFunction hf, String variableName) {
    // Search local symbols first
    LocalSymbolMap localSymbols = hf.getLocalSymbolMap();
    Iterator<HighSymbol> localIter = localSymbols.getSymbols();
    while (localIter.hasNext()) {
        HighSymbol sym = localIter.next();
        if (sym.getName().equals(variableName)) {
            return sym.getHighVariable();
        }
    }

    // Also search global symbols
    GlobalSymbolMap globalSymbols = hf.getGlobalSymbolMap();
    Iterator<HighSymbol> globalIter = globalSymbols.getSymbols();
    while (globalIter.hasNext()) {
        HighSymbol sym = globalIter.next();
        if (sym.getName().equals(variableName)) {
            return sym.getHighVariable();
        }
    }

    return null;
}
```

### Collecting Variable Accesses

Track both reads and writes using def-use chains:
```java
private List<Map<String, Object>> collectVariableAccesses(HighVariable var) {
    List<Map<String, Object>> accesses = new ArrayList<>();
    Set<Address> seenAddresses = new HashSet<>();

    Varnode[] instances = var.getInstances();
    if (instances == null) {
        return accesses;
    }

    for (Varnode instance : instances) {
        // Check for writes (definitions)
        PcodeOp def = instance.getDef();
        if (def != null) {
            Address addr = getOperationAddress(def);
            if (addr != null && !seenAddresses.contains(addr)) {
                seenAddresses.add(addr);
                accesses.add(buildAccessInfo(addr, "WRITE", def));
            }
        }

        // Check for reads (uses)
        Iterator<PcodeOp> uses = instance.getDescendants();
        while (uses.hasNext()) {
            PcodeOp use = uses.next();
            Address addr = getOperationAddress(use);
            if (addr != null && !seenAddresses.contains(addr)) {
                seenAddresses.add(addr);
                accesses.add(buildAccessInfo(addr, "READ", use));
            }
        }
    }

    // Sort by address
    accesses.sort((a, b) -> compareAddresses(
        (String) a.get("address"),
        (String) b.get("address")));

    return accesses;
}
```

### Variable Type Classification

Determine variable category for context:
```java
private String getVariableType(HighVariable var) {
    if (var instanceof HighParam) {
        return "parameter";
    } else if (var instanceof HighLocal) {
        return "local";
    } else if (var instanceof HighGlobal) {
        return "global";
    }
    return "unknown";
}
```

## Pcode Operation Processing

### Building Operation Information

Extract complete operation details including inputs/outputs:
```java
private List<Map<String, Object>> buildOperationList(Set<PcodeOp> ops) {
    List<Map<String, Object>> operations = new ArrayList<>();

    for (PcodeOp op : ops) {
        Map<String, Object> opInfo = new HashMap<>();

        Address addr = getOperationAddress(op);
        if (addr != null) {
            opInfo.put("address", AddressUtil.formatAddress(addr));
        }

        opInfo.put("opcode", op.getMnemonic());

        // Add output info
        Varnode output = op.getOutput();
        if (output != null) {
            opInfo.put("output", buildVarnodeInfo(output));
        }

        // Add input info
        List<Map<String, Object>> inputs = new ArrayList<>();
        for (int i = 0; i < op.getNumInputs(); i++) {
            Varnode input = op.getInput(i);
            if (input != null) {
                inputs.add(buildVarnodeInfo(input));
            }
        }
        if (!inputs.isEmpty()) {
            opInfo.put("inputs", inputs);
        }

        operations.add(opInfo);
    }

    // Sort by address
    operations.sort((a, b) -> compareAddresses(
        (String) a.getOrDefault("address", ""),
        (String) b.getOrDefault("address", "")));

    return operations;
}
```

### Varnode Information Extraction

Build detailed varnode metadata with type classification:
```java
private Map<String, Object> buildVarnodeInfo(Varnode vn) {
    Map<String, Object> info = new HashMap<>();

    if (vn.isConstant()) {
        info.put("type", "constant");
        info.put("value", "0x" + Long.toHexString(vn.getOffset()));
    } else if (vn.isRegister()) {
        info.put("type", "register");
        info.put("offset", vn.getOffset());
        info.put("size", vn.getSize());
    } else if (vn.isUnique()) {
        info.put("type", "temporary");
    } else if (vn.isAddress()) {
        info.put("type", "memory");
        info.put("address", AddressUtil.formatAddress(vn.getAddress()));
    } else {
        info.put("type", "other");
    }

    // Add high variable name if available
    HighVariable high = vn.getHigh();
    if (high != null && high.getName() != null) {
        info.put("variableName", high.getName());
    }

    return info;
}
```

### Extracting Operation Addresses

Get the source address for pcode operations:
```java
private Address getOperationAddress(PcodeOp op) {
    if (op.getSeqnum() != null) {
        return op.getSeqnum().getTarget();
    }
    return null;
}
```

## Terminator Detection

### Backward Slice Terminators

Identify data flow origins:
```java
private Map<String, Object> findBackwardTerminator(PcodeOp op) {
    int opcode = op.getOpcode();

    // Check for constant inputs
    for (int i = 0; i < op.getNumInputs(); i++) {
        Varnode input = op.getInput(i);
        if (input != null && input.isConstant()) {
            Map<String, Object> term = new HashMap<>();
            term.put("type", "CONSTANT");
            term.put("value", "0x" + Long.toHexString(input.getOffset()));
            return term;
        }
    }

    // Check for parameter
    Varnode output = op.getOutput();
    if (output != null) {
        HighVariable high = output.getHigh();
        if (high instanceof HighParam) {
            Map<String, Object> term = new HashMap<>();
            term.put("type", "PARAMETER");
            term.put("name", high.getName());
            term.put("slot", ((HighParam) high).getSlot());
            return term;
        }
        if (high instanceof HighGlobal) {
            Map<String, Object> term = new HashMap<>();
            term.put("type", "GLOBAL");
            term.put("name", high.getName());
            if (high.getRepresentative() != null) {
                term.put("address", AddressUtil.formatAddress(high.getRepresentative().getAddress()));
            }
            return term;
        }
    }

    // Check for memory load
    if (opcode == PcodeOp.LOAD) {
        Map<String, Object> term = new HashMap<>();
        term.put("type", "MEMORY_LOAD");
        Address addr = getOperationAddress(op);
        if (addr != null) {
            term.put("address", AddressUtil.formatAddress(addr));
        }
        return term;
    }

    return null;
}
```

### Forward Slice Terminators

Identify data flow sinks:
```java
private Map<String, Object> findForwardTerminator(PcodeOp op) {
    int opcode = op.getOpcode();

    if (opcode == PcodeOp.STORE) {
        Map<String, Object> term = new HashMap<>();
        term.put("type", "MEMORY_STORE");
        Address addr = getOperationAddress(op);
        if (addr != null) {
            term.put("address", AddressUtil.formatAddress(addr));
        }
        return term;
    }

    if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
        Map<String, Object> term = new HashMap<>();
        term.put("type", "FUNCTION_CALL");
        Varnode target = op.getInput(0);
        if (target != null && target.isAddress()) {
            term.put("targetAddress", AddressUtil.formatAddress(target.getAddress()));
        }
        Address addr = getOperationAddress(op);
        if (addr != null) {
            term.put("address", AddressUtil.formatAddress(addr));
        }
        return term;
    }

    if (opcode == PcodeOp.RETURN) {
        Map<String, Object> term = new HashMap<>();
        term.put("type", "RETURN");
        Address addr = getOperationAddress(op);
        if (addr != null) {
            term.put("address", AddressUtil.formatAddress(addr));
        }
        return term;
    }

    return null;
}
```

## Response Formats

### Data Flow Trace Response

Structure for trace-data-flow-backward and trace-data-flow-forward:
```json
{
    "programPath": "/example.exe",
    "function": "main",
    "functionAddress": "0x401000",
    "startAddress": "0x401234",
    "direction": "backward",
    "operationCount": 15,
    "operations": [
        {
            "address": "0x401230",
            "opcode": "COPY",
            "output": {
                "type": "register",
                "offset": 8,
                "size": 8,
                "variableName": "local_10"
            },
            "inputs": [
                {
                    "type": "constant",
                    "value": "0x0"
                }
            ]
        }
    ],
    "terminators": [
        {
            "type": "CONSTANT",
            "value": "0x0"
        },
        {
            "type": "PARAMETER",
            "name": "param_1",
            "slot": 0
        }
    ]
}
```

### Variable Accesses Response

Structure for find-variable-accesses:
```json
{
    "programPath": "/example.exe",
    "function": "main",
    "functionAddress": "0x401000",
    "variableName": "local_10",
    "variableType": "local",
    "dataType": "int",
    "accessCount": 5,
    "accesses": [
        {
            "address": "0x401230",
            "accessType": "WRITE",
            "operation": "COPY"
        },
        {
            "address": "0x401250",
            "accessType": "READ",
            "operation": "INT_ADD"
        }
    ]
}
```

## Error Handling Patterns

### Address Validation

Ensure address is within a function:
```java
Function function = program.getFunctionManager().getFunctionContaining(address);
if (function == null) {
    return createErrorResult("No function contains address: " +
        AddressUtil.formatAddress(address));
}
```

### Varnode Discovery Errors

Handle cases where no data flow information exists:
```java
List<Varnode> seedVarnodes = findVarnodesAtAddress(hf, targetAddress);
if (seedVarnodes.isEmpty()) {
    return createErrorResult("No data flow information at address: " +
        AddressUtil.formatAddress(targetAddress) +
        ". Try an address with an instruction that uses or defines a value.");
}
```

### Variable Not Found Errors

Provide helpful suggestions:
```java
HighVariable targetVar = findVariableByName(hf, variableName);
if (targetVar == null) {
    List<String> availableVars = getAvailableVariableNames(hf);
    return createErrorResult("Variable not found: " + variableName +
        ". Available variables: " + String.join(", ", availableVars));
}
```

### Decompilation Failure Handling

```java
DecompileResults results = decompileFunction(decompiler, function);
if (results == null || !results.decompileCompleted()) {
    String error = results != null ? results.getErrorMessage() : "unknown";
    return createErrorResult("Decompilation failed: " + error);
}

HighFunction hf = results.getHighFunction();
if (hf == null) {
    return createErrorResult("Could not get high-level function representation");
}
```

## Performance Considerations

### Slice Size Limits

Prevent memory exhaustion with bounded slices:
- `MAX_SLICE_SIZE = 500` operations maximum
- Break out of collection loops early when limit reached
- Use labeled `outer:` loops for multi-level break

### Deduplication Strategies

Avoid redundant data in results:
```java
Set<Address> seenAddresses = new HashSet<>();
// Check before adding to results
if (!seenAddresses.contains(addr)) {
    seenAddresses.add(addr);
    // Add to results
}
```

### Efficient Address Comparison

Parse hex addresses numerically for sorting:
```java
private int compareAddresses(String addrA, String addrB) {
    if (addrA == null || addrA.isEmpty()) return addrB == null || addrB.isEmpty() ? 0 : 1;
    if (addrB == null || addrB.isEmpty()) return -1;
    try {
        // Parse "0x" prefixed hex addresses numerically
        long valA = Long.parseUnsignedLong(addrA.startsWith("0x") ? addrA.substring(2) : addrA, 16);
        long valB = Long.parseUnsignedLong(addrB.startsWith("0x") ? addrB.substring(2) : addrB, 16);
        return Long.compareUnsigned(valA, valB);
    } catch (NumberFormatException e) {
        // Fall back to string comparison if not valid hex
        return addrA.compareTo(addrB);
    }
}
```

## Testing Considerations

### Integration Test Requirements

- Test backward slicing finds correct origins (constants, parameters, globals)
- Test forward slicing finds correct uses (stores, calls, returns)
- Test variable access tracking finds all reads and writes
- Validate terminator detection for all slice directions
- Test with functions that fail to decompile
- Test with addresses that have no data flow information
- Test slice size limiting with large functions

### Test Data Patterns

Create test programs with:
- Functions with multiple parameters and local variables
- Functions with global variable accesses
- Functions with memory loads and stores
- Functions with constant propagation
- Functions with function calls passing parameters
- Functions with return values

### Address Formatting Consistency

Verify all addresses use `AddressUtil.formatAddress()`:
```java
assertEquals("0x401234", result.get("address"));
```

## Important Notes

- **Syntax Tree Required**: Must enable `toggleSyntaxTree(true)` for SSA analysis
- **Memory Management**: Always dispose DecompInterface instances
- **Slice Size Limits**: Enforce MAX_SLICE_SIZE to prevent memory issues
- **Iterator Patterns**: LocalSymbolMap and GlobalSymbolMap return Iterator, not Iterable
- **Address Formatting**: Use AddressUtil.formatAddress() for all addresses in JSON
- **Terminator Types**: Backward (CONSTANT, PARAMETER, GLOBAL, MEMORY_LOAD) vs Forward (MEMORY_STORE, FUNCTION_CALL, RETURN)
- **Variable Types**: Classify as parameter, local, or global using instanceof checks
- **Deduplication**: Use Set<Address> to prevent duplicate entries in access tracking
- **Error Context**: Provide helpful suggestions (available variables, valid addresses)
- **Timeout Configuration**: Respect ConfigManager decompiler timeout settings
