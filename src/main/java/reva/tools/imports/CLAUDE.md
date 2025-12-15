# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the imports tools package.

## Package Overview

The `reva.tools.imports` package provides MCP tools for analyzing imported and exported symbols in binaries. It enables discovering external API dependencies, finding usage of specific imports, resolving thunk chains, and understanding export interfaces. This is essential for understanding binary dependencies and API surface areas during reverse engineering.

## Key Tools

- `list-imports` - List all imported functions from external libraries with filtering and grouping
- `list-exports` - List all exported symbols from the binary
- `find-import-references` - Find all locations where a specific imported function is called (including through thunks)
- `resolve-thunk` - Follow thunk chains to find actual target functions

## Import Analysis Patterns

### Basic Import Collection
**Use FunctionManager.getExternalFunctions() for import enumeration**:
```java
FunctionIterator externalFunctions = program.getFunctionManager().getExternalFunctions();

while (externalFunctions.hasNext()) {
    Function func = externalFunctions.next();
    ExternalLocation extLoc = func.getExternalLocation();

    // Get library information
    String library = extLoc != null ? extLoc.getLibraryName() : "<unknown>";

    // Get original import name (may differ from current name)
    if (extLoc != null) {
        String originalName = extLoc.getOriginalImportedName();
        if (originalName != null && !originalName.equals(func.getName())) {
            // Handle renamed imports
        }
    }
}
```

### Library Filtering
**Support case-insensitive partial matching**:
```java
// Apply library filter (case-insensitive partial match)
if (libraryFilter != null && !libraryFilter.isEmpty() &&
    !library.toLowerCase().contains(libraryFilter.toLowerCase())) {
    continue;
}
```

### Import Data Structure
**Standard import information format**:
```java
Map<String, Object> info = new HashMap<>();
info.put("name", func.getName());
info.put("library", library);

Address entryPoint = func.getEntryPoint();
if (entryPoint != null) {
    info.put("address", AddressUtil.formatAddress(entryPoint));
}

// Handle ordinal imports
if (extLoc != null) {
    String originalName = extLoc.getOriginalImportedName();
    if (originalName != null && !originalName.equals(func.getName())) {
        info.put("originalName", originalName);
        if (originalName.startsWith("Ordinal_")) {
            try {
                info.put("ordinal", Integer.parseInt(originalName.substring(8)));
            } catch (NumberFormatException e) {
                // Not a valid ordinal format
            }
        }
    }
}

if (func.getSignature() != null) {
    info.put("signature", func.getSignature().getPrototypeString());
}
```

### Grouping by Library
**Organize imports by library for better navigation**:
```java
boolean groupByLibrary = getOptionalBoolean(request, "groupByLibrary", true);

if (groupByLibrary) {
    // Group imports by library using LinkedHashMap to preserve order
    Map<String, List<Map<String, Object>>> grouped = new LinkedHashMap<>();
    for (Map<String, Object> imp : imports) {
        String library = (String) imp.get("library");
        grouped.computeIfAbsent(library, k -> new ArrayList<>()).add(imp);
    }

    // Convert to structured format
    List<Map<String, Object>> result = new ArrayList<>();
    for (Map.Entry<String, List<Map<String, Object>>> entry : grouped.entrySet()) {
        result.add(Map.of(
            "name", entry.getKey(),
            "importCount", entry.getValue().size(),
            "imports", entry.getValue()
        ));
    }
}
```

## Export Analysis Patterns

### Export Discovery
**Use SymbolTable.getExternalEntryPointIterator() for exports**:
```java
// For PE files, exports are detected via Ghidra's external entry points mechanism
// The PE loader calls SymbolTable.addExternalEntryPoint() for each exported symbol
SymbolTable symbolTable = program.getSymbolTable();
FunctionManager funcManager = program.getFunctionManager();

AddressIterator entryPoints = symbolTable.getExternalEntryPointIterator();
while (entryPoints.hasNext()) {
    Address addr = entryPoints.next();

    Map<String, Object> info = new HashMap<>();
    info.put("address", AddressUtil.formatAddress(addr));

    Symbol symbol = symbolTable.getPrimarySymbol(addr);
    if (symbol != null) {
        info.put("name", symbol.getName());
        info.put("symbolType", symbol.getSymbolType().toString());

        Function function = funcManager.getFunctionAt(addr);
        info.put("isFunction", function != null);
        if (function != null && function.getSignature() != null) {
            info.put("signature", function.getSignature().getPrototypeString());
        }
    }

    exports.add(info);
}
```

### Export vs Import Note
For PE files specifically, exports are correctly detected via `getExternalEntryPointIterator()`. The PE loader automatically registers all exported symbols as external entry points during analysis.

## Import Reference Analysis

### Finding Import Usage
**Locate all references to imported functions**:
```java
// Find matching imports by name (case-insensitive)
List<Function> matchingImports = findImportsByName(program, importName, libraryName);
if (matchingImports.isEmpty()) {
    return createErrorResult("Import not found: " + importName +
        (libraryName != null ? " in " + libraryName : ""));
}

// Build thunk map once for efficiency
Map<Function, List<Function>> thunkMap = buildThunkMap(program);

// Collect references to the import and its thunks
List<Map<String, Object>> references = collectImportReferences(
    program, matchingImports, thunkMap, maxResults);
```

### Thunk Map Construction
**Build efficient external function -> thunk mapping**:
```java
// Build a map from external functions to thunks that point to them
// This is O(n) where n = number of functions, done once per request
Map<Function, List<Function>> thunkMap = new HashMap<>();
FunctionIterator allFunctions = program.getFunctionManager().getFunctions(true);

while (allFunctions.hasNext()) {
    Function func = allFunctions.next();
    if (func.isThunk()) {
        Function target = func.getThunkedFunction(true); // Resolve fully
        if (target != null && target.isExternal()) {
            thunkMap.computeIfAbsent(target, k -> new ArrayList<>()).add(func);
        }
    }
}
```

### Reference Collection Through Thunks
**Find both direct and indirect (thunk) references**:
```java
ReferenceManager refManager = program.getReferenceManager();
Set<Address> seen = new HashSet<>(); // Avoid duplicate references

for (Function importFunc : matchingImports) {
    // Collect all addresses to check: the import and its thunks
    List<Address> targets = new ArrayList<>();

    Address importAddr = importFunc.getEntryPoint();
    if (importAddr != null) {
        targets.add(importAddr);
    }

    // Add thunk addresses
    List<Function> thunks = thunkMap.get(importFunc);
    if (thunks != null) {
        for (Function thunk : thunks) {
            Address thunkAddr = thunk.getEntryPoint();
            if (thunkAddr != null) {
                targets.add(thunkAddr);
            }
        }
    }

    // Get references to all targets
    for (Address target : targets) {
        ReferenceIterator refIter = refManager.getReferencesTo(target);
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            Address fromAddr = ref.getFromAddress();

            if (seen.contains(fromAddr)) continue;
            seen.add(fromAddr);

            // Build reference information
            Map<String, Object> refInfo = new HashMap<>();
            refInfo.put("fromAddress", AddressUtil.formatAddress(fromAddr));
            refInfo.put("referenceType", ref.getReferenceType().toString());
            refInfo.put("isCall", ref.getReferenceType().isCall());

            // Add containing function information
            Function containingFunc = funcManager.getFunctionContaining(fromAddr);
            if (containingFunc != null) {
                refInfo.put("function", containingFunc.getName());
                refInfo.put("functionAddress",
                    AddressUtil.formatAddress(containingFunc.getEntryPoint()));
            }

            references.add(refInfo);
        }
    }
}
```

## Thunk Resolution

### Following Thunk Chains
**Resolve thunk chains to find actual targets**:
```java
List<Map<String, Object>> chain = new ArrayList<>();
Function current = function;
int depth = 0;
int MAX_THUNK_CHAIN_DEPTH = 10;

while (current != null && depth < MAX_THUNK_CHAIN_DEPTH) {
    Map<String, Object> info = new HashMap<>();
    info.put("name", current.getName());

    Address entryPoint = current.getEntryPoint();
    if (entryPoint != null) {
        info.put("address", AddressUtil.formatAddress(entryPoint));
    }

    info.put("isThunk", current.isThunk());
    info.put("isExternal", current.isExternal());

    // Add external location information
    if (current.isExternal()) {
        ExternalLocation extLoc = current.getExternalLocation();
        if (extLoc != null) {
            info.put("library", extLoc.getLibraryName());
            String origName = extLoc.getOriginalImportedName();
            if (origName != null) {
                info.put("originalName", origName);
            }
        }
    }

    chain.add(info);

    // Follow thunk chain
    if (current.isThunk()) {
        Function next = current.getThunkedFunction(false);
        if (next != null && !next.equals(current)) {
            current = next;
            depth++;
        } else {
            break;
        }
    } else {
        break;
    }
}
```

### Thunk Resolution Results
**Provide chain information and final target**:
```java
Map<String, Object> finalTarget = chain.get(chain.size() - 1);
boolean isResolved = !Boolean.TRUE.equals(finalTarget.get("isThunk"));

Map<String, Object> result = new HashMap<>();
result.put("chain", chain);
result.put("chainLength", chain.size());
result.put("finalTarget", finalTarget);
result.put("isResolved", isResolved);
```

## Pagination Patterns

### Pagination Parameters
**Use consistent pagination with clamping**:
```java
private static final int DEFAULT_MAX_RESULTS = 500;
private static final int MAX_IMPORT_RESULTS = 2000;
private static final int MAX_EXPORT_RESULTS = 2000;
private static final int MAX_REFERENCE_RESULTS = 500;

int maxResults = clamp(
    getOptionalInt(request, "maxResults", DEFAULT_MAX_RESULTS),
    1,
    MAX_IMPORT_RESULTS
);
int startIndex = Math.max(0, getOptionalInt(request, "startIndex", 0));

// Clamp utility
private int clamp(int value, int min, int max) {
    return Math.max(min, Math.min(value, max));
}
```

### Collection and Pagination
**Collect all items, then paginate**:
```java
// Collect all items first (supports sorting/filtering)
List<Map<String, Object>> allImports = collectImports(program, libraryFilter);

// Apply pagination
List<Map<String, Object>> paginated = paginate(allImports, startIndex, maxResults);

// Pagination helper
private <T> List<T> paginate(List<T> list, int startIndex, int maxResults) {
    if (startIndex >= list.size()) {
        return new ArrayList<>();
    }
    int endIndex = Math.min(startIndex + maxResults, list.size());
    return new ArrayList<>(list.subList(startIndex, endIndex));
}
```

### Pagination Response
**Include pagination metadata in results**:
```java
Map<String, Object> result = new HashMap<>();
result.put("programPath", program.getDomainFile().getPathname());
result.put("totalCount", allImports.size());
result.put("startIndex", startIndex);
result.put("returnedCount", paginated.size());
result.put("imports", paginated);
```

## Sorting Patterns

### Import Sorting
**Sort by library first, then by name**:
```java
// Sort by library, then name (case-insensitive)
imports.sort((a, b) -> {
    int cmp = ((String) a.get("library")).compareToIgnoreCase((String) b.get("library"));
    return cmp != 0 ? cmp : ((String) a.get("name")).compareToIgnoreCase((String) b.get("name"));
});
```

### Export Sorting
**Sort exports alphabetically by name**:
```java
exports.sort((a, b) -> {
    String nameA = (String) a.getOrDefault("name", "");
    String nameB = (String) b.getOrDefault("name", "");
    return nameA.compareToIgnoreCase(nameB);
});
```

## Response Patterns

### Import List Response
```java
// Without grouping
{
  "programPath": "/program.exe",
  "totalCount": 150,
  "startIndex": 0,
  "returnedCount": 100,
  "imports": [
    {
      "name": "CreateFileW",
      "library": "KERNEL32.dll",
      "address": "0x00401000",
      "signature": "HANDLE CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)"
    }
  ]
}

// With grouping
{
  "programPath": "/program.exe",
  "totalCount": 150,
  "startIndex": 0,
  "returnedCount": 100,
  "libraries": [
    {
      "name": "KERNEL32.dll",
      "importCount": 45,
      "imports": [...]
    }
  ]
}
```

### Export List Response
```java
{
  "programPath": "/library.dll",
  "totalCount": 50,
  "startIndex": 0,
  "returnedCount": 50,
  "exports": [
    {
      "name": "ExportedFunction",
      "address": "0x10001000",
      "symbolType": "Function",
      "isFunction": true,
      "signature": "void ExportedFunction(int)"
    }
  ]
}
```

### Import References Response
```java
{
  "programPath": "/program.exe",
  "searchedImport": "CreateFileW",
  "matchedImports": [
    {
      "name": "CreateFileW",
      "library": "KERNEL32.dll",
      "address": "0x00401000"
    }
  ],
  "referenceCount": 5,
  "references": [
    {
      "fromAddress": "0x00401234",
      "referenceType": "UNCONDITIONAL_CALL",
      "isCall": true,
      "function": "open_file",
      "functionAddress": "0x00401200",
      "importName": "CreateFileW",
      "library": "KERNEL32.dll",
      "viaThunk": true,
      "thunkAddress": "0x00401000"
    }
  ]
}
```

### Thunk Resolution Response
```java
{
  "programPath": "/program.exe",
  "startAddress": "0x00401000",
  "chain": [
    {
      "name": "__imp_CreateFileW",
      "address": "0x00401000",
      "isThunk": true,
      "isExternal": false
    },
    {
      "name": "CreateFileW",
      "address": "0xEXT:00000000",
      "isThunk": false,
      "isExternal": true,
      "library": "KERNEL32.dll",
      "originalName": "CreateFileW"
    }
  ],
  "chainLength": 2,
  "finalTarget": {...},
  "isResolved": true
}
```

## Ordinal Import Handling

### Ordinal Detection
**Parse ordinal information from original import name**:
```java
String originalName = extLoc.getOriginalImportedName();
if (originalName != null && !originalName.equals(func.getName())) {
    info.put("originalName", originalName);

    // Check if it's an ordinal import (format: "Ordinal_123")
    if (originalName.startsWith("Ordinal_")) {
        try {
            int ordinal = Integer.parseInt(originalName.substring(8));
            info.put("ordinal", ordinal);
        } catch (NumberFormatException e) {
            // Not a valid ordinal format
        }
    }
}
```

## Helper Record Pattern

### Internal Data Structures
**Use records for internal helper data**:
```java
// Simple record to hold address with optional thunk info
private record AddressWithThunkInfo(Address address, Address thunkAddress) {}

// Usage
targets.add(new AddressWithThunkInfo(importAddr, null));
targets.add(new AddressWithThunkInfo(thunkAddr, thunkAddr));
```

## Testing Considerations

### Test Data Requirements
- Programs with imports from multiple libraries (DLLs, shared libraries)
- Programs with exported symbols (DLLs, shared libraries)
- Binaries with thunk functions (IAT stubs)
- Ordinal imports alongside named imports
- Functions that call imported APIs both directly and through thunks

### Integration Test Patterns
```java
@Test
public void testListImports() throws Exception {
    CallToolResult result = client.callTool(new CallToolRequest(
        "list-imports",
        Map.of("programPath", programPath, "maxResults", 100)
    ));

    JsonNode jsonResult = objectMapper.readTree(content.text());
    assertTrue("Should have imports", jsonResult.get("totalCount").asInt() > 0);

    // Verify import structure
    JsonNode imports = jsonResult.get("imports");
    for (JsonNode imp : imports) {
        assertTrue("Import should have name", imp.has("name"));
        assertTrue("Import should have library", imp.has("library"));
    }
}

@Test
public void testFindImportReferences() throws Exception {
    // Verify references found
    CallToolResult result = client.callTool(new CallToolRequest(
        "find-import-references",
        Map.of("programPath", programPath, "importName", "CreateFileW")
    ));

    JsonNode jsonResult = objectMapper.readTree(content.text());
    assertTrue("Should find references", jsonResult.get("referenceCount").asInt() > 0);

    // Verify reference details
    JsonNode refs = jsonResult.get("references");
    for (JsonNode ref : refs) {
        assertTrue("Reference should have fromAddress", ref.has("fromAddress"));
        assertTrue("Reference should have referenceType", ref.has("referenceType"));
    }
}
```

## Error Handling Patterns

### Import Not Found
```java
List<Function> matchingImports = findImportsByName(program, importName, libraryName);
if (matchingImports.isEmpty()) {
    return createErrorResult("Import not found: " + importName +
        (libraryName != null ? " in " + libraryName : ""));
}
```

### No Function at Address
```java
Function function = program.getFunctionManager().getFunctionAt(address);
if (function == null) {
    function = program.getFunctionManager().getFunctionContaining(address);
}
if (function == null) {
    return createErrorResult("No function found at address: " +
        AddressUtil.formatAddress(address));
}
```

## Performance Considerations

### Thunk Map Efficiency
- Build thunk map once per request, not per import
- O(n) construction where n = total number of functions
- Reuse map when finding references to multiple matching imports

### Reference Deduplication
- Use HashSet to track seen reference sources
- Avoids duplicate references when an import has multiple thunks
- Essential for accurate reference counts

### Pagination Limits
- Different limits for different tools based on typical usage
- Imports/exports: 500-2000 (large but bounded)
- References: 100-500 (potentially very large sets)
- Clamp values to prevent excessive memory usage

## Important Notes

- **External Functions**: Use `FunctionManager.getExternalFunctions()` for imports
- **External Entry Points**: Use `SymbolTable.getExternalEntryPointIterator()` for exports
- **Thunk Resolution**: Use `Function.getThunkedFunction(true)` for full resolution
- **Ordinal Imports**: Parse from `ExternalLocation.getOriginalImportedName()`
- **Library Filtering**: Case-insensitive partial matching for user convenience
- **Grouping**: Default to grouping imports by library for better organization
- **Thunk References**: Always check both direct references and references through thunks
- **Chain Depth**: Limit thunk chain following to prevent infinite loops
- **Sorting**: Sort results consistently (library then name, or alphabetically)
- **Address Formatting**: Use `AddressUtil.formatAddress()` for all addresses
