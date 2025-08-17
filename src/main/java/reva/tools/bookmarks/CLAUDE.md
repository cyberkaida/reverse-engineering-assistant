# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the bookmarks tools package.

## Package Overview

The `reva.tools.bookmarks` package provides MCP tools for bookmark management in Ghidra programs. It enables creation, retrieval, modification, and deletion of bookmarks which are essential for tracking important locations, notes, and analysis findings during reverse engineering workflows.

## Key Tools

- `set-bookmark` - Create or update bookmarks at specific addresses
- `get-bookmarks` - Retrieve bookmarks by address, range, or filters
- `remove-bookmark` - Delete specific bookmarks
- `search-bookmarks` - Search bookmarks by text, type, category, or location
- `list-bookmark-categories` - List all categories for a bookmark type

## Bookmark Management Patterns

### Bookmark Creation and Updates

**Always use transactions for bookmark modifications**:
```java
int transactionId = program.startTransaction("Set Bookmark");
try {
    BookmarkManager bookmarkMgr = program.getBookmarkManager();
    
    // Remove existing bookmark of same type/category if exists
    Bookmark existing = bookmarkMgr.getBookmark(address, type, category);
    if (existing != null) {
        bookmarkMgr.removeBookmark(existing);
    }
    
    // Create new bookmark
    Bookmark bookmark = bookmarkMgr.setBookmark(address, type, category, comment);
    program.endTransaction(transactionId, true);
} catch (Exception e) {
    program.endTransaction(transactionId, false);
    throw e;
}
```

### BookmarkManager API Usage

**Get BookmarkManager instance from Program**:
```java
BookmarkManager bookmarkMgr = program.getBookmarkManager();
```

**Core bookmark operations**:
```java
// Create bookmark
Bookmark bookmark = bookmarkMgr.setBookmark(address, type, category, comment);

// Get specific bookmark
Bookmark bookmark = bookmarkMgr.getBookmark(address, type, category);

// Get all bookmarks at address
Bookmark[] bookmarks = bookmarkMgr.getBookmarks(address);

// Remove bookmark
bookmarkMgr.removeBookmark(bookmark);

// Iterate through all bookmarks
Iterator<Bookmark> iter = bookmarkMgr.getBookmarksIterator();
while (iter.hasNext()) {
    Bookmark bookmark = iter.next();
    // Process bookmark
}

// Iterate through bookmarks of specific type
Iterator<Bookmark> iter = bookmarkMgr.getBookmarksIterator(type);
```

## Bookmark Type Handling and Categorization

### Standard Bookmark Types
Common bookmark types used in reverse engineering:
- `"Note"` - General annotations and observations
- `"Warning"` - Potential issues or concerns
- `"TODO"` - Tasks to be completed
- `"Bug"` - Identified bugs or problems
- `"Analysis"` - Analysis results and findings
- `"Error"` - Error conditions or failures
- `"Info"` - Informational markers

### Category Organization
Categories provide additional organization within bookmark types:
```java
// Examples of category usage
bookmarkMgr.setBookmark(address, "Note", "Crypto", "AES encryption function");
bookmarkMgr.setBookmark(address, "TODO", "Reverse", "Analyze this function");
bookmarkMgr.setBookmark(address, "Warning", "Security", "Potential buffer overflow");
```

### Empty Category Handling
```java
String category = bookmark.getCategory();
if (category == null || category.isEmpty()) {
    category = "(no category)"; // Normalize for display
}
```

## Address Resolution for Bookmark Placement

### Using AbstractToolProvider Helper Methods
**Leverage parent class address resolution**:
```java
// Resolves addresses, symbols, and validates input
Address address = getAddressFromArgs(request, program, "addressOrSymbol");
```

### Manual Address Resolution Pattern
```java
// For symbol resolution
SymbolTable symbolTable = program.getSymbolTable();
Symbol symbol = symbolTable.getGlobalSymbols(symbolName).next();
if (symbol != null) {
    address = symbol.getAddress();
}

// For hex address parsing
try {
    address = program.getAddressFactory().getAddress(addressString);
} catch (Exception e) {
    throw new IllegalArgumentException("Invalid address: " + addressString);
}
```

## Comment and Description Management

### Bookmark Comment Best Practices
```java
// Store descriptive comments
String comment = "Function implements RC4 key scheduling algorithm";
Bookmark bookmark = bookmarkMgr.setBookmark(address, "Analysis", "Crypto", comment);

// Retrieve and validate comments
String comment = bookmark.getComment();
if (comment == null) {
    comment = ""; // Handle null comments gracefully
}
```

### Comment Search Implementation
```java
// Case-insensitive comment searching
if (searchText != null && !searchText.isEmpty()) {
    String comment = bookmark.getComment();
    if (comment == null || !comment.toLowerCase().contains(searchText.toLowerCase())) {
        continue; // Skip bookmark if comment doesn't match
    }
}
```

## Response Formats for Bookmark Data

### Bookmark Serialization Pattern
**Consistent bookmark-to-map conversion**:
```java
private Map<String, Object> bookmarkToMap(Bookmark bookmark) {
    Map<String, Object> map = new HashMap<>();
    map.put("id", bookmark.getId());
    map.put("address", bookmark.getAddress().toString()); // Use toString() for address formatting
    map.put("type", bookmark.getTypeString());
    map.put("category", bookmark.getCategory());
    map.put("comment", bookmark.getComment());
    return map;
}
```

### Collection Response Format
**Structured responses with metadata**:
```java
Map<String, Object> result = new HashMap<>();
result.put("bookmarks", bookmarkList);           // List of bookmark objects
result.put("count", bookmarkList.size());        // Total count for convenience
result.put("maxResults", maxResults);            // Search limit (if applicable)
return createJsonResult(result);
```

### Success Response Pattern
```java
Map<String, Object> result = new HashMap<>();
result.put("success", true);
result.put("id", bookmark.getId());
result.put("address", address.toString());
result.put("type", type);
result.put("category", category);
result.put("comment", comment);
return createJsonResult(result);
```

## Bookmark Search and Filtering Patterns

### Multi-Criteria Filtering
```java
private boolean matchesFilters(Bookmark bookmark, String typeFilter, String categoryFilter) {
    if (typeFilter != null && !bookmark.getTypeString().equals(typeFilter)) {
        return false;
    }
    if (categoryFilter != null && !bookmark.getCategory().equals(categoryFilter)) {
        return false;
    }
    return true;
}
```

### Address Range Filtering
```java
// Create address set for range filtering
AddressSet searchRange = new AddressSet(startAddress, endAddress);

// Check if bookmark is in range
if (searchRange != null && !searchRange.contains(bookmark.getAddress())) {
    continue; // Skip bookmark outside range
}
```

### Result Limiting and Pagination
```java
Iterator<Bookmark> iter = bookmarkMgr.getBookmarksIterator();
while (iter.hasNext() && results.size() < maxResults) {
    Bookmark bookmark = iter.next();
    
    // Apply filters
    if (matchesCriteria(bookmark)) {
        results.add(bookmarkToMap(bookmark));
    }
}
```

## Error Handling Patterns

### Transaction Error Handling
```java
try {
    int transactionId = program.startTransaction("Bookmark Operation");
    try {
        // Perform bookmark operations
        program.endTransaction(transactionId, true);
        return createJsonResult(result);
    } catch (Exception e) {
        program.endTransaction(transactionId, false);
        throw e;
    }
} catch (Exception e) {
    logError("Error in bookmark operation", e);
    return createErrorResult("Failed to perform bookmark operation: " + e.getMessage());
}
```

### Bookmark Not Found Handling
```java
Bookmark bookmark = bookmarkMgr.getBookmark(address, type, category);
if (bookmark == null) {
    return createErrorResult("No bookmark found at address " + address +
        " with type " + type + " and category " + category);
}
```

### Address Resolution Error Handling
```java
Address address;
try {
    address = getAddressFromArgs(request, program, "addressOrSymbol");
} catch (IllegalArgumentException e) {
    return createErrorResult("Invalid address or symbol: " + e.getMessage());
}
```

## Testing Considerations

### Integration Test Patterns
**Validate actual bookmark state changes in Ghidra**:
```java
@Test
public void testSetAndGetBookmark() throws Exception {
    // Set bookmark through MCP tool
    CallToolResult setResult = client.callTool(setRequest);
    assertFalse("Set bookmark should succeed", setResult.isError());
    
    // Verify bookmark exists in program state
    BookmarkManager bookmarkMgr = program.getBookmarkManager();
    Bookmark bookmark = bookmarkMgr.getBookmark(testAddress, "Note", "Analysis");
    assertNotNull("Bookmark should exist in program", bookmark);
    assertEquals("Bookmark comment should match", expectedComment, bookmark.getComment());
}
```

### Test Data Requirements
- Valid addresses within program memory map
- Existing symbols for symbol-based address resolution
- Various bookmark types and categories for filtering tests
- Programs with existing bookmarks for search/removal tests

### Bookmark State Verification
```java
// Verify bookmark creation
Bookmark createdBookmark = bookmarkMgr.getBookmark(address, type, category);
assertNotNull("Bookmark should be created", createdBookmark);
assertEquals("Comment should match", expectedComment, createdBookmark.getComment());

// Verify bookmark removal
bookmarkMgr.removeBookmark(bookmark);
Bookmark removedBookmark = bookmarkMgr.getBookmark(address, type, category);
assertNull("Bookmark should be removed", removedBookmark);
```

### MCP Response Testing
```java
// Parse and validate MCP response structure
String jsonResponse = ((TextContent) result.content().get(0)).text();
JsonNode responseNode = objectMapper.readTree(jsonResponse);
JsonNode bookmarksNode = responseNode.get("bookmarks");

assertEquals("Should have expected bookmark count", expectedCount, bookmarksNode.size());
assertEquals("Bookmark data should match", expectedComment, 
    bookmarksNode.get(0).get("comment").asText());
```

## Parameter Extraction Patterns

### Required Parameters
```java
// Use helper methods for consistent parameter extraction
String type = getString(request, "type");
String comment = getString(request, "comment");
Address address = getAddressFromArgs(request, program, "addressOrSymbol");
```

### Optional Parameters with Defaults
```java
String category = getOptionalString(request, "category", "");
int maxResults = getOptionalInt(request, "maxResults", 100);
List<String> types = getOptionalStringList(request.arguments(), "types", null);
```

### Complex Parameter Extraction
```java
// Handle nested objects like address ranges
Map<String, Object> addressRange = getOptionalMap(request.arguments(), "addressRange", null);
if (addressRange != null) {
    String startStr = (String) addressRange.get("start");
    String endStr = (String) addressRange.get("end");
    
    Address start = getAddressFromArgs(Map.of("addressOrSymbol", startStr), program, "addressOrSymbol");
    Address end = getAddressFromArgs(Map.of("addressOrSymbol", endStr), program, "addressOrSymbol");
}
```

## Important Notes

- **Transaction Safety**: All bookmark modifications must be wrapped in transactions
- **Address Validation**: Always validate addresses exist in the program's memory map
- **Category Handling**: Handle null/empty categories consistently across operations
- **Iterator Usage**: BookmarkManager returns Iterator objects, use while loops for iteration
- **Error Context**: Provide specific error messages including address, type, and category info
- **Memory Efficiency**: Use result limiting for large bookmark collections
- **State Consistency**: Verify bookmark operations persist correctly in program database
- **Symbol Resolution**: Support both hex addresses and symbol names for flexibility