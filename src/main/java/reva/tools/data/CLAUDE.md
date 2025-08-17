# Data Tools Package - CLAUDE.md

This file provides guidance to Claude Code when working with ReVa's data tools package. The data tools provide comprehensive data analysis and manipulation capabilities for Ghidra programs through MCP tools.

## Package Overview

The `reva.tools.data` package provides MCP tools for data operations in Ghidra programs, including:
- Data retrieval and analysis at specific addresses or symbols
- Data type application and management
- Label creation and symbol management
- Data unit creation and modification
- Memory content examination

### Key Classes
- `DataToolProvider` - Main tool provider implementing data-related MCP tools
- `DataTypeParserUtil` - Utility for parsing and resolving data types from strings
- `AddressUtil` - Utility for address formatting and resolution

## Available MCP Tools

### 1. get-data
Retrieves data information at a specific address or symbol location.

**Parameters:**
- `programPath` (string, required) - Path to the Ghidra program
- `addressOrSymbol` (string, required) - Address (e.g., "0x00400000") or symbol name (e.g., "main")

**Response includes:**
- Address and data type information
- Symbol details (if applicable)
- Raw bytes in hexadecimal format
- Data representation and value
- Length and type metadata

### 2. apply-data-type
Applies a data type to a specific address or symbol location.

**Parameters:**
- `programPath` (string, required) - Path to the Ghidra program
- `addressOrSymbol` (string, required) - Target address or symbol
- `dataTypeString` (string, required) - Data type specification (e.g., "char**", "int[10]")
- `archiveName` (string, optional) - Specific data type archive to search

**Transaction handling:**
- Automatically clears existing data units
- Creates new data with specified type
- Returns success status and applied type details

### 3. create-label
Creates a new label/symbol at a specific address.

**Parameters:**
- `programPath` (string, required) - Path to the Ghidra program
- `addressOrSymbol` (string, required) - Target address or existing symbol
- `labelName` (string, required) - Name for the new label
- `setAsPrimary` (boolean, optional, default: true) - Whether to make this the primary symbol

## Data Type Management

### Data Type String Formats
Support for various data type specifications:
```java
// Basic types
"int", "char", "short", "long", "float", "double"

// Pointer types
"char*", "int**", "void*"

// Array types
"int[10]", "char[256]", "byte[4]"

// Structure and complex types
"struct MyStruct", "union MyUnion"
```

### Data Type Resolution Priority
1. Target program's data type manager
2. Other open programs' data type managers
3. Built-in data type manager (fallback)
4. Standalone data type archives (if available)

### Example Usage
```java
// Parse a data type from string
DataType dataType = DataTypeParserUtil.parseDataTypeObjectFromString("char**", "");

// Apply data type with transaction
int txId = program.startTransaction("Apply Data Type");
try {
    Listing listing = program.getListing();
    listing.clearCodeUnits(address, address.add(dataType.getLength() - 1), false);
    Data createdData = listing.createData(address, dataType);
    // ... handle result
} finally {
    program.endTransaction(txId, success);
}
```

## Address and Symbol Resolution

### Address Formatting
Always use `AddressUtil.formatAddress(address)` for consistent output:
```java
import reva.util.AddressUtil;

// Format address for JSON response
String formattedAddress = AddressUtil.formatAddress(address); // Returns "0x" + address.toString()
```

### Address/Symbol Resolution
The tools support flexible input for addresses and symbols:
```java
// Resolve either address or symbol to Address object
Address targetAddress = AddressUtil.resolveAddressOrSymbol(program, "main");
Address targetAddress = AddressUtil.resolveAddressOrSymbol(program, "0x401000");
```

**Resolution Priority:**
1. Symbol name lookup (exact match)
2. Address parsing (with or without "0x" prefix)

## Data Retrieval Patterns

### Getting Data Information
```java
// Get data at or containing an address
Data data = AddressUtil.getContainingData(program, address);

// Extract comprehensive data information
Map<String, Object> dataInfo = new HashMap<>();
dataInfo.put("address", AddressUtil.formatAddress(data.getAddress()));
dataInfo.put("dataType", data.getDataType().getName());
dataInfo.put("length", data.getLength());
dataInfo.put("representation", data.getDefaultValueRepresentation());

// Get raw bytes safely
try {
    byte[] bytes = data.getBytes();
    StringBuilder hexString = new StringBuilder();
    for (byte b : bytes) {
        hexString.append(String.format("%02x", b & 0xff));
    }
    dataInfo.put("hexBytes", hexString.toString());
} catch (MemoryAccessException e) {
    dataInfo.put("hexBytesError", "Memory access error: " + e.getMessage());
}
```

## Transaction Management for Data Modifications

### Safe Data Modification Pattern
```java
int transactionID = program.startTransaction("Operation Description");
boolean success = false;

try {
    // Perform data modifications
    Listing listing = program.getListing();
    
    // Clear existing data if needed
    if (listing.getDataAt(targetAddress) != null) {
        listing.clearCodeUnits(targetAddress, 
            targetAddress.add(dataType.getLength() - 1), false);
    }
    
    // Create new data
    Data createdData = listing.createData(targetAddress, dataType);
    if (createdData == null) {
        throw new Exception("Failed to create data at address: " + targetAddress);
    }
    
    success = true;
    return createSuccessResult(createdData);
    
} catch (Exception e) {
    return createErrorResult("Error: " + e.getMessage());
} finally {
    program.endTransaction(transactionID, success);
}
```

### Label Creation Pattern
```java
int transactionID = program.startTransaction("Create Label");
boolean success = false;

try {
    SymbolTable symbolTable = program.getSymbolTable();
    
    // Create the label
    Symbol symbol = symbolTable.createLabel(address, labelName,
        program.getGlobalNamespace(), SourceType.USER_DEFINED);
    
    if (symbol == null) {
        throw new Exception("Failed to create label at address: " + address);
    }
    
    // Set as primary if requested
    if (setAsPrimary && !symbol.isPrimary()) {
        symbol.setPrimary();
    }
    
    success = true;
    
} finally {
    program.endTransaction(transactionID, success);
}
```

## Response Format Standards

### Successful Data Retrieval Response
```json
{
  "address": "0x00401000",
  "dataType": "int",
  "length": 4,
  "symbolName": "myVariable",
  "symbolNamespace": "Global",
  "hexBytes": "12345678",
  "representation": "305419896",
  "valueType": "Integer",
  "value": "305419896"
}
```

### Successful Data Type Application Response
```json
{
  "success": true,
  "address": "0x00401000",
  "dataType": "char*",
  "dataTypeDisplayName": "char *",
  "length": 8
}
```

### Error Response Format
```json
{
  "error": "Could not find data type: invalid_type. Try using the get-data-type-archives and get-data-types tools to find available data types."
}
```

## Testing Considerations

### Integration Test Setup
```java
@Before
public void setUpTestData() throws Exception {
    programPath = program.getDomainFile().getPathname();
    
    int txId = program.startTransaction("Setup test data");
    try {
        Listing listing = program.getListing();
        SymbolTable symbolTable = program.getSymbolTable();
        
        // Create test addresses and data
        Address testAddress = program.getAddressFactory()
            .getDefaultAddressSpace().getAddress(0x01000100);
        
        // Create test data
        listing.createData(testAddress, new IntegerDataType(), 4);
        
        // Create test symbols
        symbolTable.createLabel(testAddress, "test_symbol",
            program.getGlobalNamespace(), SourceType.USER_DEFINED);
            
    } finally {
        program.endTransaction(txId, true);
    }
}
```

### Validation Patterns
```java
// Validate data creation
Data data = listing.getDataAt(address);
assertNotNull("Data should exist at address", data);
assertEquals("Data type should match", expectedType, data.getDataType().getName());

// Validate symbol creation  
List<Symbol> symbols = symbolTable.getLabelOrFunctionSymbols(labelName, null);
assertFalse("Symbol should exist", symbols.isEmpty());
assertEquals("Symbol should be at correct address", expectedAddress, symbols.get(0).getAddress());

// Validate data type equivalence
assertTrue("Data types should be equivalent", 
    expectedDataType.isEquivalent(actualDataType));
```

## Error Handling Best Practices

### Parameter Validation
```java
// Use AbstractToolProvider helper methods with exception handling
try {
    Program program = getProgramFromArgs(request);
    Address targetAddress = getAddressFromArgs(request, program, "addressOrSymbol");
    String dataTypeString = getString(request, "dataTypeString");
    
    if (dataTypeString.trim().isEmpty()) {
        return createErrorResult("Data type string cannot be empty");
    }
    
} catch (IllegalArgumentException | ProgramValidationException e) {
    return createErrorResult(e.getMessage());
}
```

### Data Type Parsing Error Handling
```java
try {
    DataType dataType = DataTypeParserUtil.parseDataTypeObjectFromString(
        dataTypeString, archiveName);
    if (dataType == null) {
        return createErrorResult("Could not find data type: " + dataTypeString +
            ". Try using the get-data-type-archives and get-data-types tools to find available data types.");
    }
} catch (Exception e) {
    return createErrorResult("Error parsing data type: " + e.getMessage() +
        ". Try using the get-data-type-archives and get-data-types tools to find available data types.");
}
```

## Common Usage Patterns

### Data Analysis Workflow
1. Use `get-data` to examine existing data at an address/symbol
2. Analyze the current data type and structure
3. Use `apply-data-type` to correct or enhance data typing
4. Use `create-label` to add meaningful symbols for better analysis

### Memory Structure Analysis
1. Start with known entry points or symbols
2. Examine data layout using `get-data`
3. Apply appropriate data types to structure the data
4. Create labels for important data structures
5. Iterate through related addresses to map complete structures

## Integration Notes

- Extends `AbstractToolProvider` for consistent parameter handling
- Uses `AddressUtil` for all address formatting and resolution
- Leverages `DataTypeParserUtil` for robust data type parsing
- Implements proper transaction management for all modifications
- Provides comprehensive error messages with actionable suggestions
- Supports both address and symbol-based operations consistently