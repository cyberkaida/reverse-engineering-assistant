# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the memory tools package.

## Package Overview

The `reva.tools.memory` package provides MCP tools for memory analysis and manipulation in Ghidra programs. It handles reading memory content, listing memory blocks, and provides utilities for safe memory access patterns.

## Key Tools

- `get-memory-blocks` - List all memory blocks with properties and permissions
- `read-memory` - Read memory content at specific addresses with flexible formatting

## Memory Block Analysis

### Memory Block Properties
Memory blocks provide comprehensive information about memory segments:
```java
Map<String, Object> blockInfo = new HashMap<>();
blockInfo.put("name", block.getName());
blockInfo.put("start", block.getStart().toString());
blockInfo.put("end", block.getEnd().toString());
blockInfo.put("size", block.getSize());
blockInfo.put("readable", block.isRead());
blockInfo.put("writable", block.isWrite());
blockInfo.put("executable", block.isExecute());
blockInfo.put("initialized", block.isInitialized());
blockInfo.put("volatile", block.isVolatile());
blockInfo.put("mapped", block.isMapped());
blockInfo.put("overlay", block.isOverlay());
```

### Memory Block Types and Properties
Understanding memory block characteristics:
- **Initialized**: Block contains actual data from the binary
- **Mapped**: Block is mapped to a physical memory region
- **Overlay**: Block is an overlay memory space
- **Volatile**: Block contents may change during execution
- **Permissions**: Read, write, execute flags determine access rights

## Memory Reading Patterns

### Safe Memory Access
**ALWAYS use MemoryUtil.readMemoryBytes() for safe memory reading**:
```java
import reva.util.MemoryUtil;

byte[] bytes = MemoryUtil.readMemoryBytes(program, address, length);
if (bytes == null) {
    return createErrorResult("Memory access error at address: " + address);
}
```

### Memory Access Exception Handling
Memory operations must handle potential failures gracefully:
```java
try {
    int read = memory.getBytes(address, bytes);
    if (read != length) {
        // Handle partial reads - return truncated data
        byte[] actualBytes = new byte[read];
        System.arraycopy(bytes, 0, actualBytes, 0, read);
        return actualBytes;
    }
} catch (MemoryAccessException e) {
    return null; // Indicates memory access failure
}
```

### Chunked Memory Processing
For large memory regions, use chunked processing to avoid memory issues:
```java
import reva.util.MemoryUtil;

MemoryUtil.processMemoryInChunks(
    program, 
    startAddress, 
    totalLength, 
    chunkSize, 
    chunk -> {
        // Process each chunk of memory
        String hexData = MemoryUtil.formatHexString(chunk);
        // Handle chunk data
    }
);
```

## Address Space Handling

### Address Resolution
Use AbstractToolProvider helper methods for address resolution:
```java
// Supports both addresses and symbol names
Address address = getAddressFromArgs(request, program, "addressOrSymbol");
```

### Address Formatting
**ALWAYS use AddressUtil.formatAddress() for consistent address formatting**:
```java
import reva.util.AddressUtil;

String formattedAddress = AddressUtil.formatAddress(address);
// Returns "0x" + address.toString()
```

### Memory Block Lookup
Utility methods for finding memory blocks:
```java
// Find block by name
MemoryBlock block = MemoryUtil.findBlockByName(program, "blockName");

// Find block containing address
MemoryBlock containingBlock = MemoryUtil.getBlockContaining(program, address);
```

## Memory Data Formatting

### Hex Formatting
Format byte arrays as hex strings for display:
```java
String hexString = MemoryUtil.formatHexString(bytes);
// Returns: "41 42 43 44" for bytes {0x41, 0x42, 0x43, 0x44}
```

### Byte Array Conversion
Convert bytes to integer lists for JSON serialization:
```java
List<Integer> byteValues = MemoryUtil.byteArrayToIntList(bytes);
// Returns: [65, 66, 67, 68] for bytes {0x41, 0x42, 0x43, 0x44}
```

### Flexible Output Formats
Support multiple output formats in memory reading tools:
```java
String format = getOptionalString(request, "format", "hex");

Map<String, Object> result = new HashMap<>();
result.put("address", address.toString());
result.put("length", bytes.length);

if ("hex".equals(format) || "both".equals(format)) {
    result.put("hex", MemoryUtil.formatHexString(bytes));
}

if ("bytes".equals(format) || "both".equals(format)) {
    result.put("bytes", MemoryUtil.byteArrayToIntList(bytes));
}
```

## Memory Analysis Best Practices

### Length Validation
Always validate memory read lengths:
```java
int length = getOptionalInt(request, "length", 16);
if (length <= 0) {
    return createErrorResult("Invalid length: " + length);
}
```

### Memory Boundary Checking
Respect memory block boundaries and permissions:
```java
MemoryBlock block = memory.getBlock(address);
if (block == null) {
    return createErrorResult("Address not in any memory block: " + address);
}

if (!block.isRead()) {
    return createErrorResult("Memory block is not readable: " + block.getName());
}
```

### Partial Read Handling
Handle cases where full read length is not available:
```java
byte[] bytes = MemoryUtil.readMemoryBytes(program, address, requestedLength);
if (bytes != null && bytes.length < requestedLength) {
    // Log or notify about partial read
    logInfo("Partial read: requested " + requestedLength + ", got " + bytes.length);
}
```

## Memory Map Visualization

### Block Iteration Patterns
Iterate through memory blocks systematically:
```java
Memory memory = program.getMemory();
List<Map<String, Object>> blockData = new ArrayList<>();

for (MemoryBlock block : memory.getBlocks()) {
    Map<String, Object> blockInfo = createBlockInfo(block);
    blockData.add(blockInfo);
}
```

### Memory Layout Analysis
Analyze memory layout and gaps:
```java
private void analyzeMemoryLayout(Program program) {
    Memory memory = program.getMemory();
    MemoryBlock[] blocks = memory.getBlocks();
    
    for (int i = 0; i < blocks.length - 1; i++) {
        MemoryBlock current = blocks[i];
        MemoryBlock next = blocks[i + 1];
        
        long gap = next.getStart().getOffset() - current.getEnd().getOffset() - 1;
        if (gap > 0) {
            logInfo("Memory gap: " + gap + " bytes between " + 
                   current.getName() + " and " + next.getName());
        }
    }
}
```

## Virtual vs Physical Addresses

### Address Space Context
Understand different address spaces in Ghidra:
```java
Address address = getAddressFromArgs(request, program, "addressOrSymbol");
String addressSpace = address.getAddressSpace().getName();
// Common spaces: ram, overlay:ram, register, stack, hash
```

### Address Space Validation
Validate address spaces for memory operations:
```java
if (!address.getAddressSpace().isMemorySpace()) {
    return createErrorResult("Address is not in memory space: " + address);
}
```

## Error Handling Patterns

### Memory Access Errors
Provide specific error messages for memory access failures:
```java
byte[] bytes = MemoryUtil.readMemoryBytes(program, address, length);
if (bytes == null) {
    return createErrorResult("Memory access error at address: " + 
                           AddressUtil.formatAddress(address) + 
                           " - check if address is valid and readable");
}
```

### Block Access Validation
Validate memory block access before operations:
```java
MemoryBlock block = memory.getBlock(address);
if (block == null) {
    return createErrorResult("Address " + AddressUtil.formatAddress(address) + 
                           " is not within any memory block");
}

if (!block.isInitialized()) {
    return createErrorResult("Memory block '" + block.getName() + 
                           "' is not initialized - no data available");
}
```

## Response Format Standards

### Memory Block Response
Standard format for memory block information:
```java
Map<String, Object> response = Map.of(
    "success", true,
    "programPath", program.getDomainFile().getPathname(),
    "blocks", blockDataList,
    "totalBlocks", blockDataList.size(),
    "memorySize", calculateTotalMemorySize(memory)
);
```

### Memory Read Response
Standard format for memory read operations:
```java
Map<String, Object> response = Map.of(
    "success", true,
    "programPath", program.getDomainFile().getPathname(),
    "address", AddressUtil.formatAddress(address),
    "requestedLength", requestedLength,
    "actualLength", bytes.length,
    "hex", MemoryUtil.formatHexString(bytes),
    "blockName", block.getName()
);
```

## Testing Considerations

### Integration Test Setup
Memory tools require specific test data setup:
```java
@Before
public void setUpTestData() throws Exception {
    programPath = program.getDomainFile().getPathname();
    
    // Verify test memory block exists
    MemoryBlock testBlock = program.getMemory().getBlock("test");
    assertNotNull("Test memory block should exist", testBlock);
    assertEquals("Test block should start at expected address", 
                expectedAddress, testBlock.getStart().getOffset());
}
```

### Memory State Validation
Validate memory state in tests:
```java
@Test
public void testMemoryBlockProperties() throws Exception {
    MemoryBlock[] blocks = program.getMemory().getBlocks();
    assertTrue("Program should have at least one memory block", blocks.length > 0);
    
    // Test specific block properties
    MemoryBlock textBlock = findBlockByName(program, ".text");
    assertNotNull("Text block should exist", textBlock);
    assertTrue("Text block should be executable", textBlock.isExecute());
    assertTrue("Text block should be readable", textBlock.isRead());
}
```

### Memory Access Testing
Test memory access patterns and error conditions:
```java
@Test
public void testMemoryReadBoundaries() throws Exception {
    Address startAddress = program.getMinAddress();
    MemoryBlock block = program.getMemory().getBlock(startAddress);
    
    // Test valid read
    byte[] data = MemoryUtil.readMemoryBytes(program, startAddress, 16);
    assertNotNull("Should be able to read from start address", data);
    
    // Test read beyond block end
    Address beyondEnd = block.getEnd().add(1);
    byte[] invalidData = MemoryUtil.readMemoryBytes(program, beyondEnd, 16);
    assertNull("Should not be able to read beyond block end", invalidData);
}
```

## Important Notes

- **Safe Memory Access**: Always use MemoryUtil helper methods for memory operations
- **Address Formatting**: Use AddressUtil.formatAddress() for consistent output
- **Error Handling**: Provide specific error messages for different failure modes
- **Performance**: Use chunked processing for large memory operations
- **Block Properties**: Check memory block permissions before access attempts
- **Address Spaces**: Validate address spaces for memory operations
- **Partial Reads**: Handle cases where requested length exceeds available data
- **Memory Layout**: Consider memory gaps and overlays in analysis