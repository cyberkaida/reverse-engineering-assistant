# Strings Tools Package - CLAUDE.md

This file provides guidance for working with the strings tools package in ReVa (Reverse Engineering Assistant).

## Package Overview

The `reva.tools.strings` package provides comprehensive string analysis capabilities for reverse engineering. It offers tools for discovering, searching, filtering, and analyzing strings in binary files through Ghidra's string analysis APIs. The package is designed for efficient handling of large binaries with pagination support and multiple search strategies.

## Registered Tools

The StringToolProvider implements two tools (registered in `registerTools()`):

### 1. get-strings-count
- **Purpose**: Get total count of strings in a program (use before pagination)
- **Parameters**:
  - `programPath` (required) - Path in the Ghidra Project to the program
- **Returns**: JSON object with `count` field
- **Use Case**: Planning pagination strategy for large binaries

### 2. get-strings
- **Purpose**: Unified string retrieval with optional filtering/sorting
- **Parameters**:
  - `programPath` (required) - Path in the Ghidra Project to the program
  - `searchString` (optional) - Sort results by similarity to this string (LCS-based scoring). Mutually exclusive with `regexPattern`.
  - `regexPattern` (optional) - Filter results to strings matching this regex pattern. Mutually exclusive with `searchString`.
  - `startIndex` (optional, default: 0) - Starting index for pagination (0-based)
  - `maxCount` (optional, default: 100) - Maximum number of strings to return
  - `includeReferencingFunctions` (optional, default: false) - Include list of functions that reference each string (max 100 per string)
- **Modes**:
  - No search params → list all strings (paginated)
  - `searchString` provided → sort by similarity, then paginate
  - `regexPattern` provided → filter by regex, then paginate
  - Both provided → error (mutually exclusive)
- **Returns**: Array with pagination/search metadata followed by string objects

## Core Implementation Patterns

### Unified Tool with Mode Dispatch
The `registerStringsTool()` handler dispatches to three private methods based on parameters:
```java
if (searchString != null) {
    return handleSimilaritySearch(program, searchString, pagination, includeReferencingFunctions);
} else if (regexPattern != null) {
    return handleRegexSearch(program, regexPattern, pagination, includeReferencingFunctions);
} else {
    return handleListAll(program, pagination, includeReferencingFunctions);
}
```

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

### Similarity-Based Search (`handleSimilaritySearch`)
Uses `SimilarityComparator` with longest common substring (LCS) scoring:
- Phase 1: Collect all strings (without referencing functions for performance)
- Phase 2: Sort by similarity using SimilarityComparator
- Phase 3: Paginate the sorted results
- Phase 4: Add referencing functions ONLY for paginated subset (performance optimization)

**Performance optimization**: Stores Address objects temporarily in `TEMP_ADDRESS_KEY` field during Phases 1-3 to avoid string parsing round-trips. Removed before JSON serialization in Phase 4.

### Regex Pattern Matching (`handleRegexSearch`)
Supports full Java regex syntax with proper validation:
- Validates pattern is non-empty and compiles without error
- Uses `Pattern.matcher().find()` for substring matching
- Streams through strings with early termination at maxCount

## Response Formats

### Standard String Object Format
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

When `includeReferencingFunctions` is true:
```json
{
    "referencingFunctions": [
        {"name": "main", "address": "0x401000"}
    ],
    "referenceCount": 1
}
```

### List-all mode metadata
```json
{
    "startIndex": 0,
    "requestedCount": 100,
    "actualCount": 85,
    "nextStartIndex": 85
}
```

### Similarity mode metadata (adds `searchComplete`)
```json
{
    "searchComplete": true,
    "startIndex": 0,
    "requestedCount": 100,
    "actualCount": 85,
    "nextStartIndex": 85
}
```

### Regex mode metadata (adds `regexPattern` and `searchComplete`)
```json
{
    "regexPattern": "error|warning",
    "searchComplete": false,
    "startIndex": 0,
    "requestedCount": 100,
    "actualCount": 100,
    "nextStartIndex": 100
}
```

## Constants
- `MAX_REFERENCING_FUNCTIONS = 100` - Limit references per string
- `TEMP_ADDRESS_KEY = "_addressObj"` - Temporary key for Address objects during similarity search

## Critical Utilities Used
- `AddressUtil.formatAddress(address)` - **REQUIRED** for all address formatting
- `getProgramFromArgs(request)` - **REQUIRED** for program resolution
- `getPaginationParams(request)` - Extract startIndex/maxCount with defaults
- `getOptionalString(request, key, default)` - Extract optional string parameters
- `getOptionalBoolean(request, key, default)` - Extract optional boolean parameters
- `createJsonResult(data)` / `createErrorResult(message)` - Format responses
