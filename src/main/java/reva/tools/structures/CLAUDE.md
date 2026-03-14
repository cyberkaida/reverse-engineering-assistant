# CLAUDE.md - Structure Tools Package

This file provides guidance for working with the structures tools package in ReVa (Reverse Engineering Assistant).

## Package Overview

The `reva.tools.structures` package provides tools for creating, manipulating, and analyzing data structures in Ghidra programs through the MCP server. It uses C-style definitions as the primary interface for structure creation and modification.

### Core Capabilities
- Parse C-style structure definitions and create or replace them in Ghidra
- Validate C structure syntax without creating the structures
- Apply structures to memory addresses for data interpretation
- List and search existing structures with filtering
- **Safe deletion with reference checking** (prevents breaking function signatures)
- Parse entire C header files with multiple structure definitions

## Structure Analysis Tools

### Available Tools (7 total)

1. **parse-c-structure** - Parse and create or replace structures from C-style definitions (create-or-replace semantics)
2. **validate-c-structure** - Validate C-style structure definitions without creating them
3. **get-structure-info** - Get detailed information about a structure, including C representation
4. **list-structures** - List all structures with filtering options
5. **apply-structure** - Apply a structure at a specific memory address
6. **delete-structure** - Delete a structure (with reference checking and force option)
7. **parse-c-header** - Parse entire C header files and create all structures

### Structure Definition Creation

#### Creating Structures from C Definitions
```java
// Parse complex C structure (creates new or replaces existing)
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
// 2. Check if a structure with this name already exists
// 3. If exists: clear fields and rebuild from new definition
// 4. If new: resolve into the program's DataTypeManager
// 5. Return detailed information about the created/modified structure
```

#### Modifying Existing Structures
Use `parse-c-structure` with the same structure name to replace an existing structure:

```java
// Original structure: struct Graphics_Engine { void *mouseDevice; int displayMode; };

// Replace with updated definition
Map<String, Object> args = new HashMap<>();
args.put("programPath", programPath);
args.put("cDefinition", """
    struct Graphics_Engine {
        MouseDevice *mouseDevice;    // Changed type from void*
        int displayMode;              // Kept unchanged
        DisplayBuffer *frameBuffer;   // Added new field
        uint32_t refreshRate;         // Added new field
    };
""");

// The tool will:
// 1. Parse the C definition
// 2. Find the existing structure by name
// 3. Clear all existing fields
// 4. Rebuild structure with new layout
// 5. Preserve structure references in code
```

**Best practices:**
- Read the structure with `get-structure-info` first to see current layout
- Structure name in C definition must match existing structure for replacement
- Fields are completely replaced (not merged)

### C Header Parsing Strategy
```java
// Parse entire header file with multiple structures
DataType dt = parser.parse(headerContent);
if (dt != null) {
    // Single structure parse successful
    DataType resolved = dtm.resolve(dt, DataTypeConflictHandler.REPLACE_HANDLER);
    createdTypes.add(createStructureInfo(resolved));
} else {
    // Fallback: Parse line by line for multiple definitions
    // ...
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
  "cRepresentation": "struct NetworkPacket {\n    uint32 magic;\n    ...\n};",
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
  ]
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

### Safe Structure Deletion

The `delete-structure` tool includes comprehensive reference checking to prevent accidental breakage of code that uses the structure.

#### Reference Checking
Before deletion, the tool automatically checks for references in:
- **Function signatures**: Return types and parameter types
- **Function variables**: Local and global variables
- **Memory instances**: Applied structure instances at memory addresses

#### Forced Deletion
```java
// Force deletion despite references
Map<String, Object> args = new HashMap<>();
args.put("programPath", programPath);
args.put("structureName", "Graphics_Engine");
args.put("force", true);  // Override safety check
```

## Testing Considerations

### Integration Test Requirements
- Tests validate actual Ghidra program state changes, not just MCP responses
- Use `DataType.isEquivalent()` to compare structures before/after changes
- Verify structure creation with `findDataTypeByName()` helper
- Test field addition by checking `Structure.getNumComponents()`
- Validate structure application at memory addresses with `Listing.getDataAt()`

### Memory Safety
- Always use transactions for structure modifications
- Validate memory addresses before applying structures
- Use `DataTypeConflictHandler.REPLACE_HANDLER` for consistent updates

## Key APIs and Utilities

### Essential Ghidra APIs
- `CParser` - Parse C-style structure definitions
- `DataTypeManager` - Manage program data types and categories
- `CategoryPath` - Organize structures in hierarchical categories
- `BitFieldDataType` - Handle bitfield components in structures

### Utility Methods
- `DataTypeParserUtil.createDataTypeInfo()` - Create standardized data type information
- `AddressUtil.formatAddress()` - Consistent address formatting for JSON output
- `findDataTypeByName()` - Locate structures across all categories
- `createStructureInfo()` / `createDetailedStructureInfo()` - Generate comprehensive structure metadata
- `generateCRepresentation()` - Generate C representation for structures and unions
