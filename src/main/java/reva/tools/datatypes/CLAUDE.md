# CLAUDE.md - DataType Tools Package

This file provides guidance to Claude Code when working with the datatypes tools package in ReVa.

## Package Overview

The `reva.tools.datatypes` package provides MCP tools for data type management and operations in Ghidra. It enables AI-assisted exploration and manipulation of data type archives, including built-in types, program-specific types, and user-defined types.

### Key Components
- `DataTypeToolProvider` - MCP tool provider for data type operations
- `DataTypeParserUtil` - Utility for parsing and finding data types from string representations

## Core Data Type Management Tools

### Available Tools

#### 1. `get-data-type-archives`
Lists all available data type archives for a program.

**Parameters:**
- `programPath` (required): Path in the Ghidra Project

**Returns:** Multi-JSON result with metadata and archive information including:
- Built-in data type manager (always first)
- Target program's data type manager
- Other open programs' data type managers
- Standalone data type archives (if available)

#### 2. `get-data-types`
Retrieves data types from a specific archive with pagination and filtering.

**Parameters:**
- `programPath` (required): Path in the Ghidra Project
- `archiveName` (required): Name of the data type archive
- `categoryPath` (optional): Category path to list from (default: "/")
- `includeSubcategories` (optional): Include subcategories (default: false)
- `startIndex` (optional): Pagination start index (default: 0)
- `maxCount` (optional): Maximum results to return (default: 100)

#### 3. `get-data-type-by-string`
Finds a data type by its string representation (e.g., "char**", "int[10]").

**Parameters:**
- `programPath` (required): Path in the Ghidra Project
- `dataTypeString` (required): String representation of the data type
- `archiveName` (optional): Specific archive to search in

## DataTypeManager API Usage

### Finding Data Type Managers

Use `DataTypeParserUtil.findDataTypeManager()` for locating data type managers:

```java
// Find by name with program context prioritization
DataTypeManager dtm = DataTypeParserUtil.findDataTypeManager(archiveName, programPath);

// Priority order:
// 1. Specified program's data type manager
// 2. Other open programs' data type managers  
// 3. Standalone data type managers (via DataTypeArchiveService)
// 4. Built-in data type manager (fallback)
```

### Data Type Manager Types

1. **BUILT_IN** - Always available, contains basic types (int, char, etc.)
2. **PROGRAM** - Program-specific data types and user-defined types
3. **FILE_ARCHIVE** - Standalone archive files loaded in Ghidra

## Data Type Creation and Parsing Patterns

### Parsing Data Types from Strings

```java
// For MCP responses (returns metadata map)
Map<String, Object> result = DataTypeParserUtil.parseDataTypeFromString(
    dataTypeString, archiveName, programPath);

// For internal use (returns actual DataType object)
DataType dt = DataTypeParserUtil.parseDataTypeObjectFromString(
    dataTypeString, archiveName);
```

### Supported String Formats
- Basic types: `int`, `char`, `float`, `double`
- Pointers: `char*`, `int**`, `void*`
- Arrays: `int[10]`, `char[256]`
- Complex types: Custom structures and typedefs

### Data Type Search Priority

1. **Built-in types** - Searched first for basic types
2. **Target program types** - Program-specific and user-defined types
3. **Other program types** - Types from other open programs
4. **Standalone archives** - External type libraries (if plugin available)

## Built-in vs User-Defined Data Type Handling

### Built-in Data Types
- Always available via `BuiltInDataTypeManager.getDataTypeManager()`
- Contains fundamental types (byte, int, char, short, long, float, double)
- Provides basic pointer and array support
- Used as fallback when specific archives aren't found

### Program-Specific Data Types
- Accessed via `program.getDataTypeManager()`
- Contains user-defined structures, enums, typedefs
- Program-specific customizations and imports
- Highest priority for target program

### Standalone Archives
- Loaded through `DataTypeArchiveService` (requires GUI environment)
- External type libraries (.gdt files)
- Shared across multiple programs
- Optional - tools work without plugin availability

## Category Management and Organization

### Category Navigation

```java
// Get root category
Category root = dtm.getRootCategory();

// Navigate by path
CategoryPath path = new CategoryPath("/Structure/MyStructs");
Category category = dtm.getCategory(path);

// Recursive data type collection
private void addDataTypesRecursively(Category category, List<DataType> dataTypes) {
    for (DataType dt : category.getDataTypes()) {
        dataTypes.add(dt);
    }
    for (Category subCategory : category.getCategories()) {
        addDataTypesRecursively(subCategory, dataTypes);
    }
}
```

### Common Category Paths
- `/` - Root category
- `/Structure` - User-defined structures
- `/Enum` - Enumeration types
- `/FunctionDefinition` - Function pointer types
- `/TypeDef` - Type definitions

## Response Formats for Data Type Information

### Data Type Metadata Structure

```java
// Created by DataTypeParserUtil.createDataTypeInfo()
Map<String, Object> info = new HashMap<>();
info.put("name", dt.getName());                    // Simple name
info.put("displayName", dt.getDisplayName());      // Full display name
info.put("categoryPath", dt.getCategoryPath().getPath()); // Category location
info.put("description", dt.getDescription());      // Type description
info.put("id", dt.getUniversalID().getValue());    // Unique identifier
info.put("size", dt.getLength());                  // Size in bytes
info.put("alignment", dt.getAlignment());          // Memory alignment
info.put("dataTypeName", dt.getClass().getSimpleName()); // Implementation class
info.put("sourceArchiveName", dt.getSourceArchive().getName()); // Origin archive
```

### Multi-JSON Result Pattern

```java
// Metadata first, then data items
List<Object> resultData = new ArrayList<>();
resultData.add(metadataInfo);  // Count, pagination, search criteria
resultData.addAll(dataItems);  // Actual data type information
return createMultiJsonResult(resultData);
```

## Data Type Validation and Error Handling

### Common Validation Patterns

```java
// Always validate program first
try {
    Program program = getProgramFromArgs(request);
    String archiveName = getString(request, "archiveName");
} catch (IllegalArgumentException e) {
    return createErrorResult(e.getMessage());
}

// Handle missing data type managers gracefully
DataTypeManager dtm = DataTypeParserUtil.findDataTypeManager(archiveName, programPath);
if (dtm == null) {
    return createErrorResult("Data type archive not found: " + archiveName);
}
```

### Error Scenarios
- Invalid program path → "Program not found: {path}"
- Missing archive → "Data type archive not found: {name}"
- Invalid category → "Category not found: {path}"
- Parse failure → "Could not find or parse data type: {string}"
- Service unavailable → "Data type archive service is not available"

## Testing Considerations

### Integration Test Requirements
- Fork tests to prevent configuration conflicts
- Use `RevaIntegrationTestBase` for Ghidra environment setup
- Test with built-in types first (always available)
- Validate both success and error scenarios

### Key Test Scenarios

```java
// Test built-in type availability (core requirement)
@Test
public void testBuiltInDataTypeManagerAvailability() {
    DataTypeManager builtInDTM = BuiltInDataTypeManager.getDataTypeManager();
    assertNotNull("Built-in data type manager should always be available", builtInDTM);
    assertTrue("Built-in data type manager should have data types", 
              builtInDTM.getDataTypeCount(true) > 0);
}

// Test basic type parsing (prevents regression)
String[] basicTypes = {"byte", "int", "char", "short", "long", "float", "double"};
String[] pointerTypes = {"byte *", "char *", "int *", "void *"};
```

### Headless Environment Considerations
- Built-in types always work (no GUI required)
- Program types work when program is loaded
- Standalone archives require GUI environment
- Tools should gracefully handle missing DataTypeArchiveService

## API Integration Examples

### Finding and Applying Data Types

```java
// Find data type from string representation
DataType dataType = DataTypeParserUtil.parseDataTypeObjectFromString(
    "char*", "");  // Empty archiveName searches all

// Apply to program location (separate tool)
// Use apply-data-type tool with programPath, addressOrSymbol, dataTypeString

// Get type information for MCP response
Map<String, Object> typeInfo = DataTypeParserUtil.createDataTypeInfo(dataType);
```

### Working with Categories

```java
// List types in specific category
Category category = dtm.getCategory(new CategoryPath("/Structure"));
List<DataType> structures = new ArrayList<>();
for (DataType dt : category.getDataTypes()) {
    structures.add(dt);
}

// Recursive category traversal
addDataTypesRecursively(dtm.getRootCategory(), allTypes);
```

## Important Notes

### Serialization Safety
- Never include actual DataType objects in MCP responses
- DataType objects contain circular references causing serialization issues
- Always use `DataTypeParserUtil.createDataTypeInfo()` for safe metadata extraction

### Built-in Type Priority
- Built-in types are searched first to ensure basic types are always found
- Prevents "No data type managers available" errors in headless environments
- Provides consistent behavior across different Ghidra configurations

### Program Context Requirement
- All tools require `programPath` parameter for proper data type manager resolution
- Program context determines search priority and available types
- Enables proper scoping of user-defined types to specific programs