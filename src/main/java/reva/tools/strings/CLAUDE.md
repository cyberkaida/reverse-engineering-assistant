# Strings Tools Package - CLAUDE.md

This file provides guidance for working with the strings tools package in ReVa (Reverse Engineering Assistant).

## Package Overview

The `reva.tools.strings` package provides comprehensive string analysis capabilities for reverse engineering. It offers tools for discovering, searching, filtering, and analyzing strings in binary files through Ghidra's string analysis APIs. The package is designed for efficient handling of large binaries with pagination support and multiple search strategies.

## Registered Tools

The StringToolProvider implements four main tools (registered in `registerTools()`):

### 1. get-strings-count
- **Purpose**: Get total count of strings in a program (use before pagination)
- **Parameters**:
  - `programPath` (required) - Path in the Ghidra Project to the program
- **Returns**: JSON object with `count` field
- **Use Case**: Planning pagination strategy for large binaries

### 2. get-strings
- **Purpose**: Get paginated list of strings from a program
- **Parameters**:
  - `programPath` (required) - Path in the Ghidra Project to the program
  - `startIndex` (optional, default: 0) - Starting index for pagination (0-based)
  - `maxCount` (optional, default: 100) - Maximum number of strings to return
  - `includeReferencingFunctions` (optional, default: false) - Include list of functions that reference each string (max 100 per string)
- **Returns**: Array with pagination metadata followed by string objects
- **Use Case**: Systematic enumeration of all strings

### 3. get-strings-by-similarity
- **Purpose**: Get strings sorted by similarity to a search string
- **Parameters**:
  - `programPath` (required) - Path in the Ghidra Project to the program
  - `searchString` (required) - String to compare against for similarity (scored by longest common substring)
  - `startIndex` (optional, default: 0) - Starting index for pagination (0-based)
  - `maxCount` (optional, default: 100) - Maximum number of strings to return
  - `includeReferencingFunctions` (optional, default: false) - Include list of functions that reference each string (max 100 per string)
- **Returns**: Array with pagination metadata followed by similarity-sorted strings
- **Performance**: Collects ALL strings first, sorts by similarity, then paginates. Only adds referencing functions to the paginated subset for efficiency.
- **Use Case**: Finding related strings when you know a partial match

### 4. search-strings-regex
- **Purpose**: Search strings matching a regex pattern
- **Parameters**:
  - `programPath` (required) - Path in the Ghidra Project to the program
  - `regexPattern` (required) - Regular expression pattern to search for in strings
  - `startIndex` (optional, default: 0) - Starting index for pagination (0-based)
  - `maxCount` (optional, default: 100) - Maximum number of matching strings to return
  - `includeReferencingFunctions` (optional, default: false) - Include list of functions that reference each string (max 100 per string)
- **Returns**: Array with search metadata followed by matching strings
- **Use Case**: Pattern-based string discovery when you know the format

## Core Implementation Patterns

### String Information Extraction
Two overloaded methods provide flexibility:
```java
// Simple version (no referencing functions)
private Map<String, Object> getStringInfo(Data data)

// Full version (optionally include referencing functions)
private Map<String, Object> getStringInfo(Data data, Program program, boolean includeReferencingFunctions)
```

### Referencing Functions
When `includeReferencingFunctions` is true, the tool finds functions that reference each string:
- Limited to MAX_REFERENCING_FUNCTIONS (100) per string to prevent unbounded iteration
- Uses HashSet to deduplicate functions (a function may reference a string multiple times)
- Returns array of function objects with `name` and `address` fields

### Similarity-Based Search
Uses `SimilarityComparator` with longest common substring (LCS) scoring:
```java
// Phase 1: Collect all strings (without referencing functions for performance)
// Phase 2: Sort by similarity using SimilarityComparator
Collections.sort(allStringData, new SimilarityComparator<>(searchString,
    item -> (String) item.get("content")));
// Phase 3: Paginate the sorted results
// Phase 4: Add referencing functions ONLY for paginated subset (performance optimization)
```

**Performance optimization**: The tool stores Address objects temporarily in a `TEMP_ADDRESS_KEY` field during Phases 1-3 to avoid string parsing round-trips. This key is removed before JSON serialization in Phase 4.

### Regex Pattern Matching
Supports full Java regex syntax with proper validation:
```java
Pattern pattern;
try {
    pattern = Pattern.compile(regexPattern);
} catch (PatternSyntaxException e) {
    return createErrorResult("Invalid regex pattern: " + e.getMessage());
}

// Use Pattern.matcher().find() for substring matching
if (pattern.matcher(stringValue).find()) {
    // String matches pattern
}
```

## Memory Traversal for String Discovery

### Core Iteration Pattern
All tools use consistent memory traversal with enhanced for loop:
```java
DataIterator dataIterator = program.getListing().getDefinedData(true);
for (Data data : dataIterator) {
    if (data.getValue() instanceof String) {
        // Process string data
        Map<String, Object> stringInfo = getStringInfo(data, program, includeReferencingFunctions);
    }
}
```

### Pagination Implementation
Efficient pagination using enhanced for loop with early termination:
```java
int currentIndex = 0;
List<Map<String, Object>> stringData = new ArrayList<>();

for (Data data : dataIterator) {
    if (!(data.getValue() instanceof String)) {
        continue;
    }

    // Skip strings before the start index
    if (currentIndex++ < pagination.startIndex()) {
        continue;
    }

    // Stop after we've collected maxCount strings
    if (stringData.size() >= pagination.maxCount()) {
        break; // Early termination for performance
    }

    // Collect string data
    Map<String, Object> stringInfo = getStringInfo(data, program, includeReferencingFunctions);
    if (stringInfo != null) {
        stringData.add(stringInfo);
    }
}
```

## String Data Extraction

### String Info Structure
The `getStringInfo()` method extracts comprehensive string information:
```java
private Map<String, Object> getStringInfo(Data data, Program program, boolean includeReferencingFunctions) {
    String stringValue = (String) data.getValue();
    Map<String, Object> stringInfo = new HashMap<>();

    // Basic string properties
    stringInfo.put("address", AddressUtil.formatAddress(data.getAddress()));  // Uses AddressUtil!
    stringInfo.put("content", stringValue);
    stringInfo.put("length", stringValue.length());

    // Raw byte representation (with error handling)
    try {
        byte[] bytes = data.getBytes();
        if (bytes != null) {
            StringBuilder hexString = new StringBuilder();
            for (byte b : bytes) {
                hexString.append(String.format("%02x", b & 0xff));
            }
            stringInfo.put("hexBytes", hexString.toString());
            stringInfo.put("byteLength", bytes.length);
        }
    } catch (MemoryAccessException e) {
        stringInfo.put("bytesError", "Memory access error: " + e.getMessage());
    }

    // Data type information
    stringInfo.put("dataType", data.getDataType().getName());
    stringInfo.put("representation", data.getDefaultValueRepresentation());

    // Optional referencing functions
    if (includeReferencingFunctions && program != null) {
        List<Map<String, String>> referencingFunctions = getReferencingFunctions(program, data.getAddress());
        stringInfo.put("referencingFunctions", referencingFunctions);
        stringInfo.put("referenceCount", referencingFunctions.size());
    }

    return stringInfo;
}
```

### Supported String Types
Ghidra's string detection supports:
- `StringDataType` - Basic null-terminated strings
- `TerminatedStringDataType` - Strings with specific terminators
- Unicode strings (UTF-8, UTF-16)
- ASCII strings
- Custom string encodings defined in Ghidra

The tool works with any Data object where `data.getValue() instanceof String` returns true.

## Performance Considerations

### Pagination Strategy
- Always use `get-strings-count` first to determine total strings
- Request chunks of 100 strings maximum to prevent memory issues
- Use `startIndex` and `nextStartIndex` for efficient traversal

### Memory Management
```java
// get-strings and search-strings-regex: Efficient streaming iteration
DataIterator dataIterator = program.getListing().getDefinedData(true);
// Process strings one at a time during iteration, stop when maxCount reached

// get-strings-by-similarity: Requires full collection for sorting
// Collects ALL strings first, sorts, then paginates
// Only adds referencing functions to paginated subset to minimize overhead
```

### includeReferencingFunctions Performance Impact
- **Enabled**: Adds cross-reference lookup for each string (can be expensive for large binaries)
- **Limited**: Maximum 100 referencing functions per string (MAX_REFERENCING_FUNCTIONS constant)
- **Optimized in similarity search**: Only looks up references for paginated results, not all strings
- Use sparingly on large binaries or when string counts are high

### Tool Selection Guidelines
- Use `get-strings` for complete enumeration (streaming, memory-efficient)
- Use `get-strings-by-similarity` when you have a reference string (requires full collection)
- Use `search-strings-regex` for pattern-based discovery (streaming, early termination)
- Use `get-strings-count` for initial assessment before choosing a strategy

## Pattern Matching and Regex Support

### Regex Tool Features
- Full Java Pattern API support
- Proper syntax validation with helpful error messages
- Case-sensitive matching (use `(?i)` for case-insensitive)
- Multi-line patterns supported

### Common Regex Patterns
```java
// Email addresses
"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"

// URLs
"https?://[\\w.-]+(?:\\.[\\w\\.-]+)+[\\w\\-\\._~:/?#[\\]@!\\$&'\\(\\)\\*\\+,;=.]+"

// IP addresses
"\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"

// File paths
"[A-Za-z]:\\\\(?:[^\\\\/:*?\"<>|\\r\\n]+\\\\)*[^\\\\/:*?\"<>|\\r\\n]*"
```

### Error Handling
```java
try {
    pattern = Pattern.compile(regexPattern);
} catch (PatternSyntaxException e) {
    return createErrorResult("Invalid regex pattern: " + e.getMessage());
}
```

## Response Formats

### Standard String Object Format
Each string is returned as a JSON object with:
```json
{
    "address": "0x404000",
    "content": "Hello World",
    "length": 11,
    "hexBytes": "48656c6c6f20576f726c6400",
    "byteLength": 12,
    "dataType": "string",
    "representation": "\"Hello World\""
}
```

When `includeReferencingFunctions` is true, additional fields are included:
```json
{
    "referencingFunctions": [
        {"name": "main", "address": "0x401000"},
        {"name": "handleError", "address": "0x401200"}
    ],
    "referenceCount": 2
}
```

### get-strings and get-strings-by-similarity Response
Array format with pagination metadata first, then string objects:
```json
[
    {
        "startIndex": 0,
        "requestedCount": 100,
        "actualCount": 85,
        "nextStartIndex": 85
    },
    { /* string object 1 */ },
    { /* string object 2 */ },
    ...
]
```

### get-strings-by-similarity Additional Metadata
```json
{
    "searchComplete": true,  // true if all strings have been returned
    "startIndex": 0,
    "requestedCount": 100,
    "actualCount": 85,
    "nextStartIndex": 85
}
```

### search-strings-regex Response
Array format with search metadata first, then matching string objects:
```json
[
    {
        "regexPattern": "error|warning",
        "searchComplete": false,  // false if more matches exist
        "startIndex": 0,
        "requestedCount": 100,
        "actualCount": 100,
        "nextStartIndex": 100
    },
    { /* matching string object 1 */ },
    { /* matching string object 2 */ },
    ...
]
```

## Testing Considerations

### Unit Testing Patterns
Current tests in StringToolProviderTest.java:
- Constructor and inheritance verification
- Tool registration (verifies all 4 tools register without errors)
- `getStringInfo()` method with valid strings (using reflection)
- `getStringInfo()` method with non-string data (using reflection)

Mock objects used:
- `McpSyncServer` - Server instance
- `Program`, `Listing`, `DataIterator` - Program structure
- `Data`, `Address`, `DataType` - String data representation

### Integration Testing Requirements
Integration tests should validate:
- Actual string discovery in real Ghidra programs
- Pagination correctness with real data
- includeReferencingFunctions option with actual cross-references
- Regex pattern matching against real string content
- Similarity search ordering with real strings

### Key Testing Notes
- Use JUnit 4 (not JUnit 5)
- Integration tests require `java.awt.headless=false`
- Integration tests should use `forkEvery=1` to prevent conflicts
- Mock tests can verify logic without Ghidra environment

## Common Usage Patterns

### Discovery Workflow
1. `get-strings-count` to assess binary size
2. `get-strings` with small chunks to sample content
3. `get-strings-by-similarity` or `search-strings-regex` for targeted analysis
4. Use `includeReferencingFunctions` sparingly (performance impact)

### Error Handling
- Memory access exceptions: Caught and added to string object as `bytesError` field
- Invalid regex patterns: Returns error result with descriptive message
- Missing/invalid programs: Handled by `getProgramFromArgs()` helper (automatic)
- Empty search strings: Validated and returns error result

### Critical Utilities Used
**Always use these ReVa utilities**:
- `AddressUtil.formatAddress(address)` - **REQUIRED** for all address formatting in JSON output
- `getProgramFromArgs(request)` - **REQUIRED** for program resolution with helpful errors
- `getPaginationParams(request)` - Extract startIndex/maxCount with defaults
- `getOptionalBoolean(request, key, default)` - Extract optional boolean parameters
- `createJsonResult(data)` - Format successful responses
- `createErrorResult(message)` - Format error responses

### Address Formatting Example
```java
// ALWAYS use AddressUtil.formatAddress() for consistent output
stringInfo.put("address", AddressUtil.formatAddress(data.getAddress()));
// Returns "0x" + address.toString()
```

## Implementation Notes

### Constants
- `MAX_REFERENCING_FUNCTIONS = 100` - Limit references per string to prevent unbounded iteration
- `TEMP_ADDRESS_KEY = "_addressObj"` - Temporary key for Address objects during similarity search (removed before JSON serialization)

### Helper Methods
- `getStringInfo(Data)` - Simple version without referencing functions
- `getStringInfo(Data, Program, boolean)` - Full version with optional referencing functions
- `getReferencingFunctions(Program, Address)` - Get functions referencing an address (max 100, deduplicated)