# CLAUDE.md - Comments Tools Package

This file provides guidance for working with the comments tools package in ReVa, which handles comment management operations in Ghidra programs.

## Package Overview

The `reva.tools.comments` package provides MCP tools for managing comments in Ghidra programs. Comments are essential for reverse engineering documentation, allowing analysts to annotate code with notes, observations, and analysis results. The package supports all five Ghidra comment types and provides comprehensive comment management capabilities.

## Comment Management Capabilities

### Core Tools
- **set-comment**: Set or update comments at specific addresses
- **get-comments**: Retrieve comments from addresses or address ranges
- **remove-comment**: Remove specific comments from addresses
- **search-comments**: Search for comments containing specific text

### Supported Operations
- Create new comments at any valid address
- Update existing comments while preserving other comment types
- Remove specific comment types without affecting others
- Search across all or filtered comment types
- Bulk retrieval from address ranges
- Symbol-based addressing for convenience

## Comment Type Handling

Ghidra supports five distinct comment types, each with specific positioning and purposes:

```java
private static final Map<String, Integer> COMMENT_TYPES = Map.of(
    "pre", CodeUnit.PRE_COMMENT,         // Before the code unit
    "eol", CodeUnit.EOL_COMMENT,         // End of line
    "post", CodeUnit.POST_COMMENT,       // After the code unit
    "plate", CodeUnit.PLATE_COMMENT,     // Block comment above code unit
    "repeatable", CodeUnit.REPEATABLE_COMMENT  // Repeats at references
);
```

### Comment Type Usage Patterns
- **EOL comments**: Most common, appear at end of disassembly lines
- **Pre comments**: Appear immediately before code units
- **Post comments**: Appear after code units, useful for detailed explanations
- **Plate comments**: Block-style comments for major sections or functions
- **Repeatable comments**: Automatically appear at all references to the address

## CodeUnit Comment Management

### Setting Comments
Comments are set using Ghidra's Listing interface within transactions:

```java
int transactionId = program.startTransaction("Set Comment");
try {
    Listing listing = program.getListing();
    listing.setComment(address, commentType, comment);
    program.endTransaction(transactionId, true);
} catch (Exception e) {
    program.endTransaction(transactionId, false);
    throw e;
}
```

### Retrieving Comments
Comments can be retrieved for single addresses or ranges:

```java
// Single address
CodeUnit codeUnit = listing.getCodeUnitAt(address);
String comment = codeUnit.getComment(commentType);

// Iterating over range
CodeUnitIterator codeUnits = listing.getCodeUnits(addressSet, true);
while (codeUnits.hasNext()) {
    CodeUnit cu = codeUnits.next();
    for (int type : commentTypes) {
        String comment = cu.getComment(type);
        if (comment != null && !comment.isEmpty()) {
            // Process comment
        }
    }
}
```

### Removing Comments
Comments are removed by setting them to null:

```java
listing.setComment(address, commentType, null);
```

## Address Resolution for Comment Placement

The package uses `AddressUtil.resolveAddressOrSymbol()` for flexible address specification:

### Supported Address Formats
- **Hex addresses**: "0x401000", "401000"
- **Symbol names**: "main", "FUN_401000"
- **Offset expressions**: "main+0x10"

### Address Resolution Pattern
```java
Address address = AddressUtil.resolveAddressOrSymbol(program, addressOrSymbol);
if (address == null) {
    return createErrorResult("Invalid address or symbol: " + addressOrSymbol);
}
```

### Address Range Handling
For range operations, both start and end addresses must be resolved:

```java
Address start = AddressUtil.resolveAddressOrSymbol(program, startStr);
Address end = AddressUtil.resolveAddressOrSymbol(program, endStr);
if (start == null || end == null) {
    return createErrorResult("Invalid address range");
}
AddressSetView addresses = new AddressSet(start, end);
```

## Comment Retrieval and Search Patterns

### Range-Based Retrieval
The `get-comments` tool supports both single address and range queries:

```java
// Single address
AddressSetView addresses = new AddressSet(address, address);

// Address range
AddressSetView addresses = new AddressSet(start, end);

// Iterate over code units in range
CodeUnitIterator codeUnits = listing.getCodeUnits(addresses, true);
```

### Comment Search Implementation
The search tool uses Ghidra's comment address iterators for efficiency:

```java
for (int type : commentTypes) {
    AddressIterator commentAddrs = listing.getCommentAddressIterator(
        type, program.getMemory(), true);
    
    while (commentAddrs.hasNext() && results.size() < maxResults) {
        Address addr = commentAddrs.next();
        String comment = listing.getComment(type, addr);
        
        if (comment != null) {
            String commentLower = caseSensitive ? comment : comment.toLowerCase();
            if (commentLower.contains(searchText)) {
                // Add to results
            }
        }
    }
}
```

### Search Optimization
- Uses iterator-based approach for memory efficiency
- Supports case-sensitive and case-insensitive search
- Implements result limiting to prevent overwhelming responses
- Early termination when maximum results reached

## Transaction Patterns for Comment Modifications

All comment modifications must occur within Ghidra transactions:

### Standard Transaction Pattern
```java
int transactionId = program.startTransaction("Operation Description");
try {
    // Perform comment operations
    listing.setComment(address, commentType, comment);
    
    // Success - commit transaction
    program.endTransaction(transactionId, true);
    return createSuccessResult();
} catch (Exception e) {
    // Failure - rollback transaction
    program.endTransaction(transactionId, false);
    throw e;
}
```

### Transaction Naming
Use descriptive transaction names for better undo history:
- "Set Comment" - for setting new comments
- "Remove Comment" - for removing comments
- "Update Comment" - for modifying existing comments

### Error Handling in Transactions
Always ensure transactions are properly closed even on exceptions:

```java
try {
    // Transaction operations
} catch (Exception e) {
    program.endTransaction(transactionId, false);
    logError("Error message", e);
    return createErrorResult("Failed operation: " + e.getMessage());
}
```

## Response Formats for Comment Data

### Set Comment Response
```json
{
    "success": true,
    "address": "0x401000",
    "commentType": "eol",
    "comment": "Function entry point"
}
```

### Get Comments Response
```json
{
    "comments": [
        {
            "address": "0x401000",
            "commentType": "eol", 
            "comment": "Function entry point"
        },
        {
            "address": "0x401004",
            "commentType": "pre",
            "comment": "Save registers"
        }
    ],
    "count": 2
}
```

### Search Results Response
```json
{
    "searchText": "function",
    "caseSensitive": false,
    "results": [
        {
            "address": "0x401000",
            "commentType": "eol",
            "comment": "Function entry point",
            "codeUnit": "PUSH EBP"
        }
    ],
    "count": 1,
    "maxResults": 100
}
```

### Error Response Format
```json
{
    "error": "Invalid comment type: invalid. Must be one of: pre, eol, post, plate, repeatable"
}
```

## Testing Considerations

### Integration Test Patterns
Integration tests validate actual program state changes:

```java
@Test
public void testSetAndGetComment() throws Exception {
    withMcpClient(createMcpTransport(), client -> {
        // Set comment via MCP
        CallToolResult setResult = client.callTool(setRequest);
        assertFalse("Set comment should succeed", setResult.isError());
        
        // Verify in program state
        Listing listing = program.getListing();
        String actualComment = listing.getComment(CodeUnit.EOL_COMMENT, testAddress);
        assertEquals("Comment should be set correctly", "Test comment", actualComment);
        
        // Verify via MCP get
        CallToolResult getResult = client.callTool(getRequest);
        // Parse and validate JSON response
    });
}
```

### Test Data Setup
```java
@Before
public void setUpTestData() throws Exception {
    programPath = program.getDomainFile().getPathname();
    env.open(program);
    
    // Register with program manager
    ghidra.app.services.ProgramManager programManager = 
        tool.getService(ghidra.app.services.ProgramManager.class);
    if (programManager != null) {
        programManager.openProgram(program);
    }
    
    // Register with server manager
    if (serverManager != null) {
        serverManager.programOpened(program, tool);
    }
}
```

### Address Selection for Tests
Use program's minimum address for reliable test addresses:

```java
Address testAddress = program.getMinAddress();
String addressStr = testAddress.toString();
```

### Validation Patterns
- Verify comment content matches expected text
- Check comment type is correctly set
- Validate address formatting in responses
- Ensure proper JSON structure in responses
- Test error conditions with invalid inputs

## Common Implementation Patterns

### Parameter Validation
```java
Integer commentType = COMMENT_TYPES.get(commentTypeStr.toLowerCase());
if (commentType == null) {
    return createErrorResult("Invalid comment type: " + commentTypeStr +
        ". Must be one of: pre, eol, post, plate, repeatable");
}
```

### Comment Type Name Resolution
```java
private String getCommentTypeName(int commentType) {
    for (Map.Entry<String, Integer> entry : COMMENT_TYPES.entrySet()) {
        if (entry.getValue() == commentType) {
            return entry.getKey();
        }
    }
    return "unknown";
}
```

### Helper Method Usage
Use AbstractToolProvider helper methods for consistent parameter extraction:

```java
Program program = getProgramFromArgs(request);
Address address = getAddressFromArgs(request, program, "addressOrSymbol");
String commentType = getOptionalString(request, "commentType", "eol");
boolean caseSensitive = getOptionalBoolean(request, "caseSensitive", false);
int maxResults = getOptionalInt(request, "maxResults", 100);
```

## Best Practices

### Comment Management
- Use appropriate comment types for different documentation needs
- Preserve existing comments when updating (don't overwrite other types)
- Use descriptive transaction names for better undo history
- Handle null comments gracefully in searches and retrievals

### Error Handling
- Validate comment types against supported values
- Check address resolution before proceeding with operations
- Provide clear error messages with valid options
- Always rollback transactions on failures

### Performance Considerations
- Use comment address iterators for large-scale searches
- Implement result limiting for search operations
- Early termination when maximum results reached
- Efficient range-based operations using AddressSet

### API Usage
- Always use transactions for comment modifications
- Use `listing.setComment(address, type, null)` to remove comments
- Leverage CodeUnitIterator for range operations
- Use AddressUtil for consistent address formatting and resolution