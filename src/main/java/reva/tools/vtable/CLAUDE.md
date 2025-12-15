# Vtable Tools Package - CLAUDE.md

This file provides guidance for working with the vtable tools package in ReVa (Reverse Engineering Assistant).

## Package Overview

The `reva.tools.vtable` package provides tools for analyzing virtual function tables (vtables) in C++ binaries. Vtables are critical data structures for understanding C++ virtual method dispatch, class hierarchies, and polymorphic behavior. This package enables discovery, analysis, and caller identification for virtual methods through their vtable entries.

## Key Tools for Vtable Analysis

The VtableToolProvider implements three main tools:

### 1. analyze-vtable
- **Purpose**: Analyze a vtable at a given address to extract function pointers
- **Parameters**:
  - `programPath` (required)
  - `vtableAddress` (required) - Address of the vtable to analyze
  - `maxEntries` (optional, default: 200, max: 1000) - Maximum vtable entries to read
- **Returns**: JSON object with vtable structure, slot indices, offsets, and function information
- **Use Case**: Understanding vtable layout and discovering virtual methods

### 2. find-vtable-callers
- **Purpose**: Find all indirect calls that could invoke a function via its vtable slot
- **Parameters**:
  - `programPath` (required)
  - `functionAddress` (required) - Address or name of the virtual function
  - `vtableAddress` (optional) - Specific vtable address (will search if not provided)
  - `maxResults` (optional, default: 500, max: 10000) - Maximum caller results
- **Returns**: JSON with vtable slot information and potential caller sites
- **Use Case**: Discovering where virtual methods are actually invoked
- **Note**: Offset patterns optimized for x86/x64 instruction formats

### 3. find-vtables-containing-function
- **Purpose**: Find all vtables that contain a pointer to a given function
- **Parameters**:
  - `programPath` (required)
  - `functionAddress` (required) - Address or name of function to search for
- **Returns**: JSON with all vtables containing the function, slot indices, and possible class names
- **Use Case**: Identifying which classes implement a particular virtual method

## Vtable Detection and Analysis Patterns

### Structure-Based vs Memory-Based Analysis

The `analyze-vtable` tool uses two analysis strategies:

**Structure-Based Analysis** (preferred when available):
```java
// If a Structure datatype is defined at the vtable address
Data existingData = listing.getDataAt(vtableAddr);
if (existingData != null && existingData.getDataType() instanceof Structure) {
    Structure structure = (Structure) existingData.getDataType();
    // Use structure components for accurate field names and types
    DataTypeComponent[] components = structure.getComponents();
}
```

**Memory-Based Analysis** (fallback):
```java
// Read raw pointers from memory and probe for function pointers
for (int slot = 0; slot < maxEntries; slot++) {
    long pointerValue = readPointer(memory, current, pointerSize);
    Address targetAddr = toAddress(program, pointerValue);
    Function func = funcMgr.getFunctionAt(targetAddr);
    // Continue until consecutive non-function pointers
}
```

### Vtable Detection Heuristics

**Probe Pattern**:
```java
// Check VTABLE_PROBE_ENTRIES (5) consecutive entries
// Require MIN_VTABLE_FUNCTION_POINTERS (2) valid function pointers
private static final int VTABLE_PROBE_ENTRIES = 5;
private static final int MIN_VTABLE_FUNCTION_POINTERS = 2;
```

**RTTI Handling**:
```java
// Allow one non-function pointer (could be RTTI)
// Stop after two consecutive non-function pointers
if (consecutiveNonFunction > 1) {
    break; // End of vtable
}
```

### Finding Vtable Start Address

When a data reference points into a vtable, find the start by walking backwards:
```java
private Address findVtableStart(Program program, Address pointerAddr, TaskMonitor monitor) {
    // Walk backwards up to 100 entries
    // Stop when previous entries are not function pointers
    // Allow one non-function (RTTI) before actual start
    Address prev = current.subtractNoWrap(pointerSize);
    // Check if previous entry points to a function
}
```

## Indirect Call Pattern Matching

### Offset Extraction Patterns

The tool uses three regex patterns to extract offsets from x86/x64 operands:

**Hex Offset Pattern**: `[RAX + 0x20]`, `[RBX+0x10]`
```java
private static final Pattern HEX_OFFSET_PATTERN = Pattern.compile("\\+\\s*0x([0-9a-fA-F]+)\\s*\\]");
```

**Decimal Offset Pattern**: `[RAX + 32]`, `[RBX+16]`
```java
private static final Pattern DEC_OFFSET_PATTERN = Pattern.compile("\\+\\s*(\\d+)\\s*\\]");
```

**Zero Offset Pattern**: `[RAX]`, `[RBX]` (offset 0)
```java
private static final Pattern ZERO_OFFSET_PATTERN = Pattern.compile("\\[\\s*[A-Za-z]+\\s*\\]");
```

### Indirect Call Detection

```java
// Iterate all instructions and identify indirect calls
Instruction instr = iter.next();
FlowType flowType = instr.getFlowType();
if (!flowType.isCall() || !flowType.isComputed()) {
    continue; // Not an indirect call
}

// Extract offset from operand representation
String operandRep = instr.getDefaultOperandRepresentation(0);
Integer offset = extractOffsetFromOperand(operandRep);

// Match against target vtable slot offsets
if (offset != null && targetOffsets.contains(offset)) {
    // Found potential caller
}
```

## Class Name Discovery

### RTTI and Symbol-Based Identification

```java
private String guessClassNameFromVtable(Program program, Address vtableAddr) {
    // Check for symbol at vtable address
    var symbol = program.getSymbolTable().getPrimarySymbol(vtableAddr);
    if (symbol != null) {
        String name = symbol.getName();
        // Common vtable symbol patterns
        if (name.contains("vtable") || name.contains("vftable") || name.startsWith("??_7")) {
            return name;
        }
    }

    // Check for RTTI pointer before vtable (MSVC pattern)
    Address rttiAddr = vtableAddr.subtractNoWrap(pointerSize);
    var rttiSymbol = program.getSymbolTable().getPrimarySymbol(rttiAddr);
    if (rttiSymbol != null && (name.contains("RTTI") || name.contains("TypeDescriptor"))) {
        return name;
    }
}
```

### Common Symbol Patterns
- **GCC/Clang**: `vtable for ClassName` or `_ZTV9ClassName`
- **MSVC**: `??_7ClassName@@6B@` (mangled vtable name)
- **RTTI**: `typeinfo for ClassName` or `??_R4ClassName@@` (MSVC type descriptor)

## Memory and Address Handling

### Pointer Reading Pattern

```java
private long readPointer(Memory memory, Address addr, int pointerSize) throws MemoryAccessException {
    if (pointerSize == 8) {
        return memory.getLong(addr);
    } else {
        return memory.getInt(addr) & 0xFFFFFFFFL; // Unsigned 32-bit
    }
}
```

### Address Space Considerations

```java
private Address toAddress(Program program, long offset) {
    // Always uses default address space
    // Note: For programs with overlays or segments, this may resolve incorrectly
    // Acceptable for typical vtable analysis on standard executables
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
}
```

## Data Reference Analysis

### Finding Vtable Slots via References

```java
private List<VtableSlotInfo> findVtableSlotsForFunction(Program program, Address functionAddr,
        TaskMonitor monitor) {
    ReferenceManager refMgr = program.getReferenceManager();

    // Find all data references to this function
    ReferenceIterator refs = refMgr.getReferencesTo(functionAddr);
    while (refs.hasNext()) {
        Reference ref = refs.next();

        if (!ref.getReferenceType().isData()) {
            continue; // Only interested in data references (vtable entries)
        }

        Address refAddr = ref.getFromAddress();
        Address vtableStart = findVtableStart(program, refAddr, monitor);

        // Calculate slot index and offset
        long slotOffset = refAddr.subtract(vtableStart);
        int slotIndex = (int) (slotOffset / pointerSize);

        // Verify this looks like a vtable
        if (isLikelyVtable(program, vtableStart)) {
            results.add(new VtableSlotInfo(vtableStart, slotIndex, (int) slotOffset));
        }
    }
}
```

## Response Formats

### analyze-vtable Response
```json
{
    "programPath": "/binary.exe",
    "vtableAddress": "0x405000",
    "pointerSize": 8,
    "entryCount": 12,
    "hasStructure": true,
    "structureName": "VtableClassName",
    "entries": [
        {
            "slot": 0,
            "offset": "0x0",
            "address": "0x401000",
            "functionName": "ClassName::method1",
            "signature": "void method1(void)",
            "fieldName": "method1_ptr",
            "fieldType": "void *"
        }
    ]
}
```

When no structure is defined:
```json
{
    "hasStructure": false,
    "note": "No structure defined at this address. Use create-structure to define one."
}
```

### find-vtable-callers Response
```json
{
    "programPath": "/binary.exe",
    "functionAddress": "0x401000",
    "functionName": "ClassName::virtualMethod",
    "vtables": [
        {
            "vtableAddress": "0x405000",
            "slotIndex": 3,
            "slotOffset": "0x18"
        }
    ],
    "potentialCallerCount": 8,
    "note": "These are indirect calls with matching offsets - verify vtable usage at each site",
    "potentialCallers": [
        {
            "address": "0x402050",
            "instruction": "CALL qword ptr [RAX + 0x18]",
            "operand": "[RAX + 0x18]",
            "offset": "0x18",
            "function": "callerFunction",
            "functionAddress": "0x402000"
        }
    ]
}
```

### find-vtables-containing-function Response
```json
{
    "programPath": "/binary.exe",
    "functionAddress": "0x401000",
    "functionName": "ClassName::virtualMethod",
    "vtableCount": 2,
    "vtables": [
        {
            "vtableAddress": "0x405000",
            "slotIndex": 3,
            "slotOffset": "0x18",
            "possibleClassName": "vtable for BaseClass"
        },
        {
            "vtableAddress": "0x405100",
            "slotIndex": 3,
            "slotOffset": "0x18",
            "possibleClassName": "vtable for DerivedClass"
        }
    ]
}
```

## Performance and Timeout Management

### Timeout Configuration
```java
private static final int DEFAULT_TIMEOUT_SECONDS = 120;

private TaskMonitor createTimeoutMonitor() {
    return TimeoutTaskMonitor.timeoutIn(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
}

// Check for timeout during long operations
monitor.checkCancelled(); // Throws CancelledException if timed out
```

### Safety Limits
```java
private static final int MAX_SLOT_SEARCH_LIMIT = 1000;  // Max slots to search in a vtable
private static final int MAX_ENTRIES_LIMIT = 1000;      // Max entries parameter limit
private static final int MAX_RESULTS_LIMIT = 10000;     // Max results for caller search

// Clamp user input to safe ranges
maxEntries = clampValue(maxEntries, 1, MAX_ENTRIES_LIMIT);
```

## Testing Considerations

### Integration Test Requirements
- Test programs with C++ vtables (GCC/Clang and MSVC)
- Verify vtable structure detection with and without defined datatypes
- Test RTTI pointer handling (MSVC-style vtables)
- Validate indirect call matching for x86/x64 architectures
- Test with overlapping vtables and nested inheritance

### Test Data Setup
```java
// Create vtable in test program
Address vtableAddr = addr(0x405000);
int pointerSize = program.getDefaultPointerSize();

// Create function pointers in memory
for (int i = 0; i < 5; i++) {
    Address funcAddr = addr(0x401000 + (i * 0x100));
    createFunction(funcAddr, "virtualMethod" + i);

    Address entryAddr = vtableAddr.add(i * pointerSize);
    setPointer(entryAddr, funcAddr);
}
```

### Edge Cases to Test
- Empty vtables (only RTTI pointer)
- Very large vtables (100+ entries)
- Functions appearing in multiple vtables
- Vtables with no references
- Indirect calls with complex addressing modes
- Address space boundaries and overflow conditions

## Common Usage Patterns

### Virtual Method Investigation Workflow
1. `analyze-vtable` at a known vtable address to understand structure
2. `find-vtables-containing-function` for a specific virtual method
3. `find-vtable-callers` to discover all potential call sites
4. Verify each call site manually to confirm vtable usage

### Class Hierarchy Discovery
1. Identify vtable addresses through symbols or RTTI
2. Use `analyze-vtable` on each discovered vtable
3. Compare vtable structures to identify inheritance relationships
4. Use `find-vtables-containing-function` to track method overrides

## Important Notes

- **Architecture Dependency**: Offset extraction patterns are optimized for x86/x64 only
- **RTTI Handling**: Allows one non-function pointer at vtable start (common MSVC pattern)
- **Address Spaces**: Uses default address space; may not work correctly with overlays
- **Indirect Call Verification**: Results are potential callers; manual verification recommended
- **Structure Definitions**: Prefer defining structures at vtable addresses for accurate analysis
- **Timeout Management**: Large binaries may require timeout handling for caller searches
- **Thread Safety**: Uses TimeoutTaskMonitor with cancellation support

## Helper Classes

### VtableSlotInfo Record
```java
private record VtableSlotInfo(Address vtableAddr, int slotIndex, int offset) {}
```

Encapsulates information about a function's position within a vtable:
- `vtableAddr` - Starting address of the vtable
- `slotIndex` - Zero-based index of the slot (e.g., 0, 1, 2...)
- `offset` - Byte offset from vtable start (slotIndex × pointerSize)

## Error Handling Patterns

### Function Resolution Errors
```java
Function targetFunc = program.getFunctionManager().getFunctionAt(functionAddr);
if (targetFunc == null) {
    targetFunc = program.getFunctionManager().getFunctionContaining(functionAddr);
}
if (targetFunc == null) {
    return createErrorResult("No function at address: " + AddressUtil.formatAddress(functionAddr));
}
```

### Memory Access Errors
```java
try {
    long pointerValue = readPointer(memory, current, pointerSize);
    // Process pointer
} catch (MemoryAccessException e) {
    break; // End of readable memory - terminate vtable reading
}
```

### Timeout Handling
```java
try {
    // Long-running operation with monitor
    monitor.checkCancelled();
} catch (CancelledException e) {
    return createErrorResult("Operation cancelled or timed out");
}
```

## Address Formatting

Always use `AddressUtil.formatAddress()` for consistent formatting:
```java
import reva.util.AddressUtil;

result.put("vtableAddress", AddressUtil.formatAddress(vtableAddr));
result.put("address", AddressUtil.formatAddress(targetAddr));
// Returns "0x" + address.toString()
```
