# CLAUDE.md - Structure Tools Package

This file provides guidance for working with the structures tools package in ReVa (Reverse Engineering Assistant).

## Package Overview

The `reva.tools.structures` package provides comprehensive tools for creating, manipulating, and analyzing data structures in Ghidra programs through the MCP server. It enables AI-assisted reverse engineering by providing structured access to Ghidra's data type management capabilities.

### Core Capabilities
- Parse C-style structure definitions and create them in Ghidra
- Validate C structure syntax without creating the structures
- Create empty structures and unions with customizable properties
- Add fields to existing structures with full data type support
- Apply structures to memory addresses for data interpretation
- List and search existing structures with filtering
- Manage structure lifecycle (creation, modification, deletion)
- Parse entire C header files with multiple structure definitions

## Structure Analysis Tools

### Available Tools

1. **parse-c-structure** - Parse and create structures from C-style definitions
2. **validate-c-structure** - Validate C-style structure definitions without creating them
3. **create-structure** - Create new empty structures or unions
4. **add-structure-field** - Add fields to existing structures with bitfield support
5. **get-structure-info** - Get detailed information about a structure
6. **list-structures** - List all structures with filtering options
7. **apply-structure** - Apply a structure at a specific memory address
8. **delete-structure** - Delete a structure from the program
9. **parse-c-header** - Parse entire C header files and create all structures

### Structure Definition Creation

#### Creating Structures from C Definitions
```java
// Parse complex C structure
String cDefinition = """
    struct NetworkPacket {
        uint32_t magic;
        uint16_t version;
        uint16_t type;
        uint32_t length;
        char data[256];
        uint32_t checksum;
    };
""";

// The tool will automatically:
// 1. Parse the C definition using CParser
// 2. Resolve data types in the program's DataTypeManager
// 3. Create the structure in the specified category
// 4. Return detailed information about the created structure
```

#### Manual Structure Creation
```java
// Create empty structure for gradual field addition
Map<String, Object> args = new HashMap<>();
args.put("programPath", programPath);
args.put("name", "CustomStruct");
args.put("type", "structure"); // or "union"
args.put("packed", true);      // Enable structure packing
args.put("category", "/Custom/Protocols");
args.put("description", "Custom protocol structure");
```

### Field Management

#### Adding Regular Fields
```java
// Add standard field to structure
Map<String, Object> args = new HashMap<>();
args.put("programPath", programPath);
args.put("structureName", "NetworkPacket");
args.put("fieldName", "timestamp");
args.put("dataType", "uint64");
args.put("comment", "Packet creation timestamp");
// offset is optional - omit to append to end
```

#### Adding Bitfield Fields
```java
// Add bitfield with specific bit sizing
Map<String, Object> bitfield = new HashMap<>();
bitfield.put("bitSize", 3);      // 3 bits for this field
bitfield.put("bitOffset", 0);    // Optional bit offset within byte

Map<String, Object> args = new HashMap<>();
args.put("programPath", programPath);
args.put("structureName", "Flags");
args.put("fieldName", "priority");
args.put("dataType", "uchar");   // Base type for bitfield
args.put("bitfield", bitfield);
args.put("comment", "Priority level (0-7)");
```

#### Data Type Parsing
The package uses multiple parsing strategies for maximum compatibility:
```java
// Primary: Use program's DataTypeManager directly
DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
DataType fieldType = parser.parse(dataTypeStr);

// Fallback: Use utility parser for broader compatibility
if (fieldType == null) {
    fieldType = DataTypeParserUtil.parseDataTypeObjectFromString(dataTypeStr, "");
}
```

### Structure Member Analysis

#### Field Information Structure
Each structure field returns comprehensive information:
```java
Map<String, Object> fieldInfo = new HashMap<>();
fieldInfo.put("ordinal", comp.getOrdinal());           // Field position
fieldInfo.put("offset", comp.getOffset());             // Byte offset
fieldInfo.put("length", comp.getLength());             // Field size
fieldInfo.put("fieldName", comp.getFieldName());       // Field name
fieldInfo.put("comment", comp.getComment());           // Field comment
fieldInfo.put("dataType", fieldType.getDisplayName()); // Type name
fieldInfo.put("dataTypeSize", fieldType.getLength());  // Type size

// Bitfield-specific information
if (comp.isBitFieldComponent()) {
    BitFieldDataType bitfield = (BitFieldDataType) fieldType;
    fieldInfo.put("isBitfield", true);
    fieldInfo.put("bitSize", bitfield.getBitSize());
    fieldInfo.put("bitOffset", bitfield.getBitOffset());
    fieldInfo.put("baseDataType", bitfield.getBaseDataType().getDisplayName());
}
```

### Size and Alignment Handling

#### Structure Properties
```java
// Basic structure information
Map<String, Object> info = new HashMap<>();
info.put("name", dt.getName());
info.put("displayName", dt.getDisplayName());
info.put("size", dt.getLength());                     // Total structure size
info.put("categoryPath", dt.getCategoryPath().getPath());
info.put("description", dt.getDescription());

// Composite-specific properties
if (dt instanceof Composite) {
    Composite composite = (Composite) dt;
    info.put("isUnion", dt instanceof Union);
    info.put("numComponents", composite.getNumComponents());
    
    if (dt instanceof Structure) {
        Structure struct = (Structure) dt;
        info.put("isPacked", struct.isPackingEnabled());
        // Packed structures minimize padding between fields
    }
}
```

#### Memory Application
```java
// Apply structure to memory address for data interpretation
int txId = program.startTransaction("Apply Structure");
try {
    Listing listing = program.getListing();
    
    // Optional: Clear existing data at address
    if (clearExisting) {
        Data existingData = listing.getDataAt(address);
        if (existingData != null) {
            listing.clearCodeUnits(address, 
                address.add(existingData.getLength() - 1), false);
        }
    }
    
    // Create structured data at address
    Data data = listing.createData(address, structureDataType);
    program.endTransaction(txId, true);
} catch (Exception e) {
    program.endTransaction(txId, false);
    throw e;
}
```

### Nested Structure Support

#### Finding Structures by Name
```java
private DataType findDataTypeByName(DataTypeManager dtm, String name) {
    // Direct lookup first (fastest)
    DataType dt = dtm.getDataType(name);
    if (dt != null) {
        return dt;
    }
    
    // Search all categories if not found directly
    Iterator<DataType> iter = dtm.getAllDataTypes();
    while (iter.hasNext()) {
        DataType dataType = iter.next();
        if (dataType.getName().equals(name)) {
            return dataType;
        }
    }
    
    return null;
}
```

#### C Header Parsing Strategy
```java
// Parse entire header file with multiple structures
DataType dt = parser.parse(headerContent);
if (dt != null) {
    // Single structure parse successful
    DataType resolved = dtm.resolve(dt, DataTypeConflictHandler.REPLACE_HANDLER);
    createdTypes.add(createStructureInfo(resolved));
} else {
    // Fallback: Parse line by line for multiple definitions
    String[] lines = headerContent.split("\n");
    StringBuilder currentDef = new StringBuilder();
    
    for (String line : lines) {
        currentDef.append(line.trim()).append("\n");
        
        // Complete definition found (ends with semicolon)
        if (line.trim().endsWith(";")) {
            try {
                DataType lineDt = parser.parse(currentDef.toString());
                if (lineDt != null) {
                    DataType resolved = dtm.resolve(lineDt, DataTypeConflictHandler.REPLACE_HANDLER);
                    createdTypes.add(createStructureInfo(resolved));
                }
            } catch (Exception e) {
                // Log error but continue with remaining definitions
                Msg.warn(this, "Failed to parse definition: " + currentDef.toString());
            }
            currentDef = new StringBuilder(); // Reset for next definition
        }
    }
}
```

### Response Formats

#### Structure Information Response
```json
{
  "name": "NetworkPacket",
  "displayName": "NetworkPacket",
  "size": 268,
  "categoryPath": "/Custom/Protocols",
  "description": "Network packet structure",
  "isUnion": false,
  "numComponents": 5,
  "isPacked": true,
  "fields": [
    {
      "ordinal": 0,
      "offset": 0,
      "length": 4,
      "fieldName": "magic",
      "dataType": "uint32",
      "dataTypeSize": 4,
      "isBitfield": false,
      "comment": "Magic number"
    }
  ],
  "cRepresentation": "struct NetworkPacket {\n    uint32 magic;\n    ...\n};"
}
```

#### Validation Response
```json
{
  "valid": true,
  "parsedType": "TestStruct",
  "displayName": "TestStruct",
  "size": 36,
  "fieldCount": 2,
  "isUnion": false
}
```

#### List Structures Response
```json
{
  "count": 15,
  "structures": [
    {
      "name": "CustomStruct",
      "size": 32,
      "categoryPath": "/Custom",
      "numComponents": 3
    }
  ]
}
```

### C Representation Generation

The package automatically generates C-style representations:
```java
private String generateCRepresentation(Structure struct) {
    StringBuilder sb = new StringBuilder();
    sb.append("struct ").append(struct.getName()).append(" {\n");
    
    for (int i = 0; i < struct.getNumComponents(); i++) {
        DataTypeComponent comp = struct.getComponent(i);
        sb.append("    ");
        
        DataType fieldType = comp.getDataType();
        if (comp.isBitFieldComponent()) {
            // Bitfield representation
            BitFieldDataType bitfield = (BitFieldDataType) fieldType;
            sb.append(bitfield.getBaseDataType().getDisplayName());
            sb.append(" ").append(comp.getFieldName());
            sb.append(" : ").append(bitfield.getBitSize());
        } else {
            // Regular field representation
            sb.append(fieldType.getDisplayName());
            sb.append(" ").append(comp.getFieldName());
        }
        
        sb.append(";");
        
        if (comp.getComment() != null) {
            sb.append(" // ").append(comp.getComment());
        }
        
        sb.append("\n");
    }
    
    sb.append("};");
    return sb.toString();
}
```

## Testing Considerations

### Integration Test Requirements
- Tests validate actual Ghidra program state changes, not just MCP responses
- Use `DataType.isEquivalent()` to compare structures before/after changes
- Verify structure creation with `findDataTypeByName()` helper
- Test field addition by checking `Structure.getNumComponents()`
- Validate structure application at memory addresses with `Listing.getDataAt()`

### Test Pattern Examples
```java
@Test
public void testStructureCreation() throws Exception {
    // Create structure through MCP tool
    Map<String, Object> arguments = new HashMap<>();
    arguments.put("programPath", programPath);
    arguments.put("cDefinition", "struct TestStruct { int field1; char field2[32]; };");
    
    CallToolResult result = client.callTool(new CallToolRequest("parse-c-structure", arguments));
    
    // Validate MCP response
    assertMcpResultNotError(result, "Result should not be an error");
    
    // Validate actual program state
    DataTypeManager dtm = program.getDataTypeManager();
    DataType dt = findDataTypeByName(dtm, "TestStruct");
    assertNotNull("Structure should exist in program", dt);
    assertTrue("Should be a Structure", dt instanceof Structure);
    
    Structure struct = (Structure) dt;
    assertEquals("Should have 2 components", 2, struct.getNumComponents());
}
```

### Memory Safety
- Always use transactions for structure modifications
- Validate memory addresses before applying structures
- Handle decompilation failures gracefully
- Use `DataTypeConflictHandler.REPLACE_HANDLER` for consistent updates

### Common Patterns
- Use helper methods from `AbstractToolProvider` (getString, getOptionalInt, etc.)
- Wrap parameter extraction in try-catch blocks
- Return structured JSON with success flags and detailed information
- Always format addresses using `AddressUtil.formatAddress(address)`
- Use consistent error reporting with `createErrorResult()`

## Key APIs and Utilities

### Essential Ghidra APIs
- `CParser` - Parse C-style structure definitions
- `DataTypeManager` - Manage program data types and categories
- `StructureDataType` / `UnionDataType` - Create composite data types
- `DataTypeParser` - Parse data type strings with full program context
- `CategoryPath` - Organize structures in hierarchical categories
- `BitFieldDataType` - Handle bitfield components in structures

### Utility Methods
- `DataTypeParserUtil.createDataTypeInfo()` - Create standardized data type information
- `AddressUtil.formatAddress()` - Consistent address formatting for JSON output
- `findDataTypeByName()` - Locate structures across all categories
- `createStructureInfo()` / `createDetailedStructureInfo()` - Generate comprehensive structure metadata

### Transaction Management
Always use proper transaction handling for structure modifications:
```java
int txId = program.startTransaction("Operation Description");
try {
    // Perform structure modifications
    program.endTransaction(txId, true);  // Commit changes
} catch (Exception e) {
    program.endTransaction(txId, false); // Rollback on error
    throw e;
}
```