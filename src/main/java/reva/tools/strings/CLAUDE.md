# Strings Tools Package - CLAUDE.md

This file provides guidance for working with the strings tools package in ReVa (Reverse Engineering Assistant).

## Package Overview

The `reva.tools.strings` package provides comprehensive string analysis capabilities for reverse engineering. It offers tools for discovering, searching, filtering, and analyzing strings in binary files through Ghidra's string analysis APIs. The package is designed for efficient handling of large binaries with pagination support and multiple search strategies.

## Key Tools for String Operations

The StringToolProvider implements four main tools:

### 1. get-strings-count
- **Purpose**: Get total count of strings in a program (use before pagination)
- **Parameters**: `programPath` (required)
- **Returns**: JSON object with `count` field
- **Use Case**: Planning pagination strategy for large binaries

### 2. get-strings
- **Purpose**: Get paginated list of strings from a program
- **Parameters**: 
  - `programPath` (required)
  - `startIndex` (optional, default: 0)
  - `maxCount` (optional, default: 100)
- **Returns**: Array with pagination metadata followed by string objects
- **Use Case**: Systematic enumeration of all strings

### 3. get-strings-by-similarity
- **Purpose**: Get strings sorted by similarity to a search string
- **Parameters**:
  - `programPath` (required)
  - `searchString` (required)
  - `startIndex` (optional, default: 0)
  - `maxCount` (optional, default: 100)
- **Returns**: Array with pagination metadata followed by similarity-sorted strings
- **Use Case**: Finding related strings when you know a partial match

### 4. search-strings-regex
- **Purpose**: Search strings matching a regex pattern
- **Parameters**:
  - `programPath` (required)
  - `regexPattern` (required)
  - `startIndex` (optional, default: 0)
  - `maxCount` (optional, default: 100)
- **Returns**: Array with search metadata followed by matching strings
- **Use Case**: Pattern-based string discovery when you know the format

## String Search and Filtering Patterns

### Similarity-Based Search
The similarity tool uses longest common substring matching:
```java
// Uses SimilarityComparator with dynamic programming algorithm
Collections.sort(stringData, new SimilarityComparator<>(searchString, item -> (String) item.get("content")));
```

### Regex Pattern Matching
Supports full Java regex syntax with proper error handling:
```java
Pattern pattern = Pattern.compile(regexPattern);
if (pattern.matcher(stringValue).find()) {
    // String matches pattern
}
```

## Memory Traversal for String Discovery

### Core Iteration Pattern
All tools use consistent memory traversal:
```java
DataIterator dataIterator = program.getListing().getDefinedData(true);
dataIterator.forEach(data -> {
    if (data.getValue() instanceof String) {
        // Process string data
        Map<String, Object> stringInfo = getStringInfo(data);
    }
});
```

### Pagination Implementation
Efficient pagination using atomic counters:
```java
AtomicInteger currentIndex = new AtomicInteger(0);
dataIterator.forEach(data -> {
    if (data.getValue() instanceof String) {
        int index = currentIndex.getAndIncrement();
        if (index < pagination.startIndex()) return;
        if (stringData.size() >= pagination.maxCount()) return;
        // Collect string data
    }
});
```

## Encoding Handling (ASCII, Unicode, etc.)

### String Data Extraction
The `getStringInfo()` method handles various string encodings:
```java
private Map<String, Object> getStringInfo(Data data) {
    String stringValue = (String) data.getValue();
    Map<String, Object> stringInfo = new HashMap<>();
    
    // Basic string properties
    stringInfo.put("content", stringValue);
    stringInfo.put("length", stringValue.length());
    
    // Raw byte representation
    byte[] bytes = data.getBytes();
    StringBuilder hexString = new StringBuilder();
    for (byte b : bytes) {
        hexString.append(String.format("%02x", b & 0xff));
    }
    stringInfo.put("hexBytes", hexString.toString());
    stringInfo.put("byteLength", bytes.length);
    
    // Data type information
    stringInfo.put("dataType", data.getDataType().getName());
    stringInfo.put("representation", data.getDefaultValueRepresentation());
    
    return stringInfo;
}
```

### Supported String Types
- `StringDataType` - Basic null-terminated strings
- `TerminatedStringDataType` - Strings with specific terminators
- Unicode strings (UTF-8, UTF-16)
- ASCII strings
- Custom string encodings defined in Ghidra

## Performance Considerations for Large Binaries

### Pagination Strategy
- Always use `get-strings-count` first to determine total strings
- Request chunks of 100 strings maximum to prevent memory issues
- Use `startIndex` and `nextStartIndex` for efficient traversal

### Memory Management
```java
// Efficient iteration without loading all strings into memory
DataIterator dataIterator = program.getListing().getDefinedData(true);
// Process strings one at a time during iteration
// Stop collection when maxCount reached
```

### Tool Selection Guidelines
- Use `get-strings` for complete enumeration
- Use `get-strings-by-similarity` when you have a reference string
- Use `search-strings-regex` only when you know the pattern exists
- Use `get-strings-count` for initial assessment

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

## Response Formats for String Data

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

### Pagination Metadata Format
```json
{
    "startIndex": 0,
    "requestedCount": 100,
    "actualCount": 85,
    "nextStartIndex": 85,
    "totalProcessed": 150
}
```

### Search Metadata Format (regex tool)
```json
{
    "regexPattern": "error|warning",
    "totalStringsProcessed": 1000,
    "totalMatches": 25,
    "startIndex": 0,
    "requestedCount": 100,
    "actualCount": 25,
    "skippedMatches": 0,
    "nextStartIndex": 25
}
```

## Testing Considerations

### Unit Testing Patterns
- Mock `DataIterator` and `Data` objects for controlled testing
- Test pagination boundaries (empty results, partial pages, exact pages)
- Test regex validation and error cases
- Test similarity scoring edge cases

### Integration Testing Requirements
- Use `RevaIntegrationTestBase` for full end-to-end testing
- Create test programs with known string content
- Validate actual string discovery against expected results
- Test with various string encodings and data types

### Test Data Setup
```java
// Create string data in test program
Listing listing = program.getListing();
Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
try {
    listing.createData(addr, new TerminatedStringDataType(), "Test String".length() + 1);
} catch (Exception e) {
    fail("Failed to create test string data");
}
```

### Performance Testing
- Test with large numbers of strings (1000+ strings)
- Verify pagination works correctly with large datasets
- Test regex performance with complex patterns
- Measure similarity search performance with long strings

## Common Usage Patterns

### Discovery Workflow
1. `get-strings-count` to assess binary size
2. `get-strings` with small chunks to sample content
3. `get-strings-by-similarity` or `search-strings-regex` for targeted analysis

### Error Recovery
- All tools handle memory access exceptions gracefully
- Invalid regex patterns return helpful error messages
- Missing programs provide clear diagnostic information

### Address Formatting
Always use `AddressUtil.formatAddress()` for consistent formatting:
```java
stringInfo.put("address", AddressUtil.formatAddress(data.getAddress()));
// Returns "0x" + address.toString()
```