# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the cross-references (xrefs) tools package.

## Package Overview

The `reva.tools.xrefs` package provides MCP tools for comprehensive cross-reference analysis in Ghidra programs. It enables finding and analyzing references to and from memory locations, symbols, and functions with optional decompilation context snippets for enhanced code understanding.

## Key Tools

- `find-cross-references` - Unified tool for finding incoming/outgoing references with filtering and context

## Cross-Reference Analysis Patterns

### Unified Reference Discovery
**Use the unified tool for comprehensive reference analysis**:
```java
// Single tool handles both directions with rich filtering options
String direction = getOptionalString(request, "direction", "both"); // "to", "from", or "both"
boolean includeFlow = getOptionalBoolean(request, "includeFlow", true);
boolean includeData = getOptionalBoolean(request, "includeData", true);
boolean includeContext = getOptionalBoolean(request, "includeContext", false);
```

### Reference Direction Handling
**Manage incoming and outgoing references separately**:
```java
ReferenceManager refManager = program.getReferenceManager();

// Get references TO this address (incoming)
if (includeTo && !address.isStackAddress() && !address.isRegisterAddress()) {
    ReferenceIterator refIter = refManager.getReferencesTo(address);
    while (refIter.hasNext()) {
        Reference ref = refIter.next();
        // Process incoming reference
    }
}

// Get references FROM this address (outgoing)
if (includeFrom) {
    Function function = program.getFunctionManager().getFunctionContaining(address);
    if (function != null) {
        // For functions, iterate through entire function body
        AddressSetView functionBody = function.getBody();
        for (Address addr : functionBody.getAddresses(true)) {
            Reference[] refs = refManager.getReferencesFrom(addr);
            // Process outgoing references from function
        }
    } else {
        // For non-function addresses, get direct references
        Reference[] refs = refManager.getReferencesFrom(address);
        // Process outgoing references
    }
}
```

## Reference Type Filtering

### Flow vs Data Reference Classification
**Use ReferenceType properties for accurate filtering**:
```java
// Apply reference type filters
if (!includeFlow && ref.getReferenceType().isFlow()) {
    continue; // Skip calls, jumps, branches
}
if (!includeData && !ref.getReferenceType().isFlow()) {
    continue; // Skip reads, writes, data references
}
```

### Reference Type Analysis
**Analyze reference characteristics for comprehensive information**:
```java
Map<String, Object> refInfo = new HashMap<>();
refInfo.put("referenceType", ref.getReferenceType().toString());
refInfo.put("isPrimary", ref.isPrimary());
refInfo.put("operandIndex", ref.getOperandIndex());
refInfo.put("sourceType", ref.getSource().toString());

// Reference classification
refInfo.put("isCall", ref.getReferenceType().isCall());
refInfo.put("isJump", ref.getReferenceType().isJump());
refInfo.put("isData", ref.getReferenceType().isData());
refInfo.put("isRead", ref.getReferenceType().isRead());
refInfo.put("isWrite", ref.getReferenceType().isWrite());
```

## Address Resolution and Symbol Analysis

### Comprehensive Address Information
**Provide complete address and symbol context**:
```java
// Basic address information
refInfo.put("fromAddress", AddressUtil.formatAddress(ref.getFromAddress()));
refInfo.put("toAddress", AddressUtil.formatAddress(ref.getToAddress()));

// Symbol information for both addresses
SymbolTable symbolTable = program.getSymbolTable();

Symbol fromSymbol = symbolTable.getPrimarySymbol(ref.getFromAddress());
if (fromSymbol != null) {
    Map<String, Object> fromSymbolInfo = new HashMap<>();
    fromSymbolInfo.put("name", fromSymbol.getName());
    fromSymbolInfo.put("type", fromSymbol.getSymbolType().toString());
    if (!fromSymbol.isGlobal()) {
        fromSymbolInfo.put("namespace", fromSymbol.getParentNamespace().getName(true));
    }
    refInfo.put("fromSymbol", fromSymbolInfo);
}
```

### Function Context Analysis
**Identify function relationships for references**:
```java
// Determine context for decompilation
Address contextAddress = isIncoming ? ref.getFromAddress() : ref.getToAddress();
Function contextFunction = program.getFunctionManager().getFunctionContaining(contextAddress);

if (contextFunction != null) {
    Map<String, Object> functionInfo = new HashMap<>();
    functionInfo.put("name", contextFunction.getName());
    functionInfo.put("entry", AddressUtil.formatAddress(contextFunction.getEntryPoint()));
    
    // Add function context information
    refInfo.put(isIncoming ? "fromFunction" : "toFunction", functionInfo);
}
```

## Decompilation Context Integration

### Line Number Mapping
**Use DecompilationContextUtil for address-to-line mapping**:
```java
import reva.util.DecompilationContextUtil;

// Get line number for address within function
if (includeContext && ref.getReferenceType().isFlow()) {
    int lineNumber = DecompilationContextUtil.getLineNumberForAddress(
        program, contextFunction, contextAddress);
        
    if (lineNumber > 0) {
        functionInfo.put("line", lineNumber);
        
        // Get surrounding context
        String context = DecompilationContextUtil.getDecompilationContext(
            program, contextFunction, lineNumber, contextLines);
        if (context != null) {
            functionInfo.put("context", context);
        }
    }
}
```

### Context Configuration
**Allow configurable context window sizes**:
```java
int contextLines = getOptionalInt(request, "contextLines", 2);
boolean includeContext = getOptionalBoolean(request, "includeContext", false);

// Only include context for flow references (calls, jumps)
if (includeContext && ref.getReferenceType().isFlow()) {
    // Add decompilation context
}
```

## Pagination and Performance

### Efficient Reference Collection
**Handle large reference sets with pagination**:
```java
// Collect all references first, then paginate
List<Map<String, Object>> allRefsTo = new ArrayList<>();
while (refIter.hasNext()) {
    Reference ref = refIter.next();
    // Apply filters and collect
    allRefsTo.add(createReferenceInfo(ref, program, includeContext, contextLines, true));
}

int totalToCount = allRefsTo.size();

// Apply pagination
int offset = getOptionalInt(request, "offset", 0);
int limit = getOptionalInt(request, "limit", 100);
int endIndex = Math.min(offset + limit, allRefsTo.size());

List<Map<String, Object>> referencesTo = new ArrayList<>();
if (offset < allRefsTo.size()) {
    referencesTo = allRefsTo.subList(offset, endIndex);
}
```

### Pagination Response Format
**Provide comprehensive pagination metadata**:
```java
resultData.put("pagination", Map.of(
    "offset", offset,
    "limit", limit,
    "totalToCount", totalToCount,
    "totalFromCount", totalFromCount,
    "hasMoreTo", offset + limit < totalToCount,
    "hasMoreFrom", offset + limit < totalFromCount
));
```

## Function-Scope Reference Analysis

### Function Body Iteration
**For function addresses, analyze entire function body**:
```java
Function function = program.getFunctionManager().getFunctionContaining(address);
if (function != null) {
    // Get all addresses in the function body
    AddressSetView functionBody = function.getBody();
    for (Address addr : functionBody.getAddresses(true)) {
        Reference[] refs = refManager.getReferencesFrom(addr);
        for (Reference ref : refs) {
            // Process each reference from the function
        }
    }
}
```

### Target Location Analysis
**Provide rich information about reference targets**:
```java
// Get symbol information for the target address
Symbol targetSymbol = symbolTable.getPrimarySymbol(address);
Map<String, Object> locationInfo = new HashMap<>();
locationInfo.put("address", AddressUtil.formatAddress(address));

if (targetSymbol != null) {
    locationInfo.put("symbol", targetSymbol.getName());
    locationInfo.put("symbolType", targetSymbol.getSymbolType().toString());
    if (!targetSymbol.isGlobal()) {
        locationInfo.put("namespace", targetSymbol.getParentNamespace().getName(true));
    }
}

// Check if this is a function entry point
Function targetFunction = program.getFunctionManager().getFunctionContaining(address);
if (targetFunction != null) {
    locationInfo.put("function", targetFunction.getName());
    if (targetFunction.getEntryPoint().equals(address)) {
        locationInfo.put("isFunctionEntry", true);
    }
}
```

## Error Handling Patterns

### Address Validation
**Validate addresses and handle special cases**:
```java
// Skip stack and register addresses for incoming references
if (includeTo && !address.isStackAddress() && !address.isRegisterAddress()) {
    // Process incoming references
}

// Validate address resolution
try {
    Address address = getAddressFromArgs(request, program, "location");
} catch (IllegalArgumentException e) {
    return createErrorResult("Invalid address or symbol: " + e.getMessage());
}
```

### Reference Processing Errors
**Handle decompilation and reference processing failures gracefully**:
```java
try {
    Map<String, Object> refInfo = createReferenceInfo(ref, program, 
                                                     includeContext, contextLines, isIncoming);
    allRefs.add(refInfo);
} catch (Exception e) {
    // Log error but continue processing other references
    logError("Error processing reference: " + ref, e);
}
```

## Response Structure Patterns

### Comprehensive Reference Information
**Standard reference data structure**:
```java
Map<String, Object> refInfo = new HashMap<>();
refInfo.put("fromAddress", AddressUtil.formatAddress(ref.getFromAddress()));
refInfo.put("toAddress", AddressUtil.formatAddress(ref.getToAddress()));
refInfo.put("referenceType", ref.getReferenceType().toString());
refInfo.put("isPrimary", ref.isPrimary());
refInfo.put("operandIndex", ref.getOperandIndex());
refInfo.put("sourceType", ref.getSource().toString());

// Classification flags
refInfo.put("isCall", ref.getReferenceType().isCall());
refInfo.put("isJump", ref.getReferenceType().isJump());
refInfo.put("isData", ref.getReferenceType().isData());
refInfo.put("isRead", ref.getReferenceType().isRead());
refInfo.put("isWrite", ref.getReferenceType().isWrite());
```

### Complete Result Structure
**Unified response format for cross-reference analysis**:
```java
Map<String, Object> resultData = new HashMap<>();
resultData.put("program", program.getName());
resultData.put("location", locationInfo);
resultData.put("referencesTo", referencesTo);
resultData.put("referencesFrom", referencesFrom);
resultData.put("pagination", paginationInfo);
```

## Testing Considerations

### Test Data Requirements
- Functions with various types of references (calls, jumps, data)
- Inter-function reference relationships
- Data references to strings and variables
- Functions with multiple incoming/outgoing references
- Large functions with many references for pagination testing

### Integration Test Patterns
**Verify reference accuracy and completeness**:
```java
// Validate reference discovery
JsonNode refsTo = jsonResult.get("referencesTo");
assertEquals(expectedCount, refsTo.size());

// Verify reference details
for (JsonNode ref : refsTo) {
    assertEquals(expectedToAddress, ref.get("toAddress").asText());
    assertEquals(expectedType, ref.get("referenceType").asText());
    assertEquals(expectedIsCall, ref.get("isCall").asBoolean());
}

// Test reference filtering
boolean foundFromMain = false;
for (JsonNode ref : refsTo) {
    JsonNode fromFunc = ref.get("fromFunction");
    if ("main".equals(fromFunc.get("name").asText())) {
        foundFromMain = true;
    }
}
assertTrue("Should find reference from main", foundFromMain);
```

### Performance Testing
- Test with functions having many references
- Verify pagination boundary conditions
- Test context generation performance
- Validate memory usage with large reference sets

## Performance Considerations

### Large Program Handling
- Use pagination for addresses with many references
- Limit context generation to flow references only
- Apply reference type filters to reduce processing
- Consider memory implications of collecting all references before pagination

### Reference Iterator Efficiency
**Use appropriate iteration patterns for different scenarios**:
```java
// For specific address references
ReferenceIterator refIter = refManager.getReferencesTo(address);
while (refIter.hasNext()) {
    Reference ref = refIter.next();
    // Process reference
}

// For function body references
AddressSetView functionBody = function.getBody();
for (Address addr : functionBody.getAddresses(true)) {
    Reference[] refs = refManager.getReferencesFrom(addr);
    // Process array of references
}
```

## Important Notes

- **Address Validation**: Skip stack and register addresses for incoming references
- **Function Scope**: For function addresses, analyze entire function body for outgoing references
- **Context Integration**: Use DecompilationContextUtil for line mapping and context
- **Reference Filtering**: Support both flow and data reference filtering
- **Pagination**: Essential for addresses with many references
- **Symbol Resolution**: Provide complete symbol and namespace information
- **Error Resilience**: Continue processing other references if individual reference fails
- **Memory Management**: DecompilationContextUtil handles decompiler disposal internally