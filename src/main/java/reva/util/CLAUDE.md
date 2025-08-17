# CLAUDE.md - ReVa Util Package

This file provides guidance for working with the foundational utility classes in the `reva.util` package. These utilities are used throughout ALL tool providers and form the backbone of ReVa's consistent behavior patterns.

## Package Overview

The `reva.util` package contains critical utility classes that provide:
- **Consistent address formatting** across all tools via `AddressUtil`
- **Program validation and lookup** with helpful error messages via `ProgramLookupUtil`
- **Data type parsing** from string representations via `DataTypeParserUtil`
- **Decompilation context mapping** and cross-reference analysis via `DecompilationContextUtil`
- **Safe memory access patterns** via `MemoryUtil`
- **Symbol validation and filtering** via `SymbolUtil`
- **Service registry patterns** for dependency injection via `RevaInternalServiceRegistry`
- **MCP schema creation utilities** via `SchemaUtil`
- **Debug logging with configuration** via `DebugLogger`
- **Decompilation comparison and diffing** via `DecompilationDiffUtil`
- **Function similarity analysis** via `SimilarityComparator`

**CRITICAL**: All tool providers MUST use these utilities instead of direct Ghidra API calls to ensure consistency across the entire ReVa ecosystem.

## Core Utility Classes

### AddressUtil - Standard Address Formatting

**PRIMARY RULE**: ALWAYS use `AddressUtil.formatAddress()` for all JSON output.

```java
import reva.util.AddressUtil;

// CORRECT - Always use this for JSON output
String formattedAddress = AddressUtil.formatAddress(address);
// Returns: "0x404000"

// WRONG - Direct address.toString() is inconsistent
String wrongFormat = address.toString(); // May not have 0x prefix
```

#### Key Methods:

```java
// Format address with consistent "0x" prefix for JSON
String formatted = AddressUtil.formatAddress(address);

// Parse address string (handles "0x" prefix automatically)
Address addr = AddressUtil.parseAddress(program, "0x404000");
Address addr2 = AddressUtil.parseAddress(program, "404000"); // Also works

// Validate address string
boolean valid = AddressUtil.isValidAddress(program, addressString);

// Resolve address OR symbol name to Address
Address resolved = AddressUtil.resolveAddressOrSymbol(program, "main");
Address resolved2 = AddressUtil.resolveAddressOrSymbol(program, "0x404000");

// Get containing function/data
Function func = AddressUtil.getContainingFunction(program, address);
Data data = AddressUtil.getContainingData(program, address);
```

#### Usage Pattern in Tools:

```java
public Map<String, Object> executeTool(Map<String, Object> arguments) {
    // Parse input address
    String addressString = getString(arguments, "address");
    Address address = AddressUtil.parseAddress(program, addressString);
    
    if (address == null) {
        throw new IllegalArgumentException("Invalid address: " + addressString);
    }
    
    // ... tool logic ...
    
    // Format output addresses
    Map<String, Object> result = new HashMap<>();
    result.put("address", AddressUtil.formatAddress(address));
    result.put("functionStart", AddressUtil.formatAddress(function.getEntryPoint()));
    
    return result;
}
```

### ProgramLookupUtil - Program Validation with Error Messages

**PRIMARY RULE**: Use `ProgramLookupUtil.getValidatedProgram()` for all program lookups.

```java
import reva.util.ProgramLookupUtil;
import reva.tools.ProgramValidationException;

try {
    Program program = ProgramLookupUtil.getValidatedProgram(programPath);
    // Program is guaranteed to be valid and open
} catch (ProgramValidationException e) {
    // Error message includes helpful suggestions
    throw new IllegalArgumentException(e.getMessage());
}
```

#### Features:
- **Automatic program discovery** from open programs and project
- **Helpful error messages** with suggestions for similar program names
- **Consistent error formatting** across all tools

#### Example Error Messages:
```
Program not found: /Hatchery.ex

Did you mean one of these?
  - /Hatchery.exe
  - /Hatchery_backup.exe

Available programs:
  - /Hatchery.exe
  - /Sample.exe
  - /folder/program.exe
```

### DataTypeParserUtil - Data Type String Parsing

**PRIMARY RULE**: Use this utility for all data type string parsing, never parse directly.

```java
import reva.util.DataTypeParserUtil;

// Parse data type for tool use (returns DataType object)
DataType dataType = DataTypeParserUtil.parseDataTypeObjectFromString("char*", "");

// Parse data type for MCP response (returns Map with metadata)
Map<String, Object> dataTypeInfo = DataTypeParserUtil.parseDataTypeFromString(
    "int[10]", "", programPath);

// Create data type info map from existing DataType
Map<String, Object> info = DataTypeParserUtil.createDataTypeInfo(dataType);
```

#### Supported Data Type Formats:
- Basic types: `int`, `char`, `void`, `float`, `double`
- Pointers: `char*`, `int**`, `void*`
- Arrays: `int[10]`, `char[256]`
- Complex types: `struct MyStruct`, `enum Color`

#### Search Priority Order:
1. Built-in data types (int, char, etc.)
2. Target program's data types
3. Other open program data types
4. Loaded data type archives

#### Usage Pattern:

```java
public Map<String, Object> changeDataType(Map<String, Object> arguments) {
    String dataTypeString = getString(arguments, "dataType");
    String programPath = getString(arguments, "programPath");
    
    try {
        // Parse the data type
        DataType newDataType = DataTypeParserUtil.parseDataTypeObjectFromString(
            dataTypeString, "");
        
        if (newDataType == null) {
            throw new IllegalArgumentException(
                "Could not find data type: " + dataTypeString);
        }
        
        // Apply the data type...
        
        // Return metadata (not the DataType object itself)
        Map<String, Object> result = new HashMap<>();
        result.put("dataType", DataTypeParserUtil.createDataTypeInfo(newDataType));
        
        return result;
    } catch (Exception e) {
        throw new IllegalArgumentException("Data type parsing failed: " + e.getMessage());
    }
}
```

### DecompilationContextUtil - Decompilation Context and Cross-References

**PRIMARY RULE**: Use this utility to map addresses to decompilation line numbers and provide context.

```java
import reva.util.DecompilationContextUtil;

// Get line number for an address in decompiled function
int lineNumber = DecompilationContextUtil.getLineNumberForAddress(
    program, function, address);

// Get context around a specific line
String context = DecompilationContextUtil.getDecompilationContext(
    program, function, lineNumber, 2); // 2 lines of context

// Get enhanced incoming references with line numbers and context
List<Map<String, Object>> refs = DecompilationContextUtil.getEnhancedIncomingReferences(
    program, targetFunction, true); // include context

// Get enhanced references to any address
List<Map<String, Object>> refs = DecompilationContextUtil.getEnhancedReferencesTo(
    program, targetAddress, false); // no context
```

#### Enhanced Reference Format:
```java
{
    "fromAddress": "0x404020",
    "fromFunction": "main",
    "fromLine": 15,
    "context": "14    if (argc > 1) {\n15        result = processArg(argv[1]);\n16    } else {",
    "referenceType": "UNCONDITIONAL_CALL",
    "fromSymbol": "main_call_site_1",
    "fromSymbolType": "LABEL"
}
```

#### Usage for Cross-Reference Tools:
```java
public Map<String, Object> getReferencesWithContext(Map<String, Object> arguments) {
    String addressString = getString(arguments, "address");
    boolean includeContext = getOptionalBoolean(arguments, "includeContext", false);
    
    Address address = AddressUtil.parseAddress(program, addressString);
    
    List<Map<String, Object>> enhancedRefs = 
        DecompilationContextUtil.getEnhancedReferencesTo(program, address, includeContext);
    
    Map<String, Object> result = new HashMap<>();
    result.put("address", AddressUtil.formatAddress(address));
    result.put("references", enhancedRefs);
    result.put("referenceCount", enhancedRefs.size());
    
    return result;
}
```

### MemoryUtil - Safe Memory Access

**PRIMARY RULE**: Use these utilities for safe memory operations with proper error handling.

```java
import reva.util.MemoryUtil;

// Read memory safely (returns null on error)
byte[] bytes = MemoryUtil.readMemoryBytes(program, address, 16);
if (bytes == null) {
    throw new IllegalArgumentException("Cannot read memory at " + 
        AddressUtil.formatAddress(address));
}

// Format bytes as hex string
String hexString = MemoryUtil.formatHexString(bytes);
// Result: "48 65 6C 6C 6F 20 57 6F 72 6C 64 00"

// Convert to integer list for JSON
List<Integer> intList = MemoryUtil.byteArrayToIntList(bytes);

// Find memory blocks
MemoryBlock block = MemoryUtil.findBlockByName(program, ".text");
MemoryBlock containingBlock = MemoryUtil.getBlockContaining(program, address);

// Process large memory regions in chunks
MemoryUtil.processMemoryInChunks(program, startAddress, length, 4096, 
    chunk -> {
        // Process each chunk safely
        String hex = MemoryUtil.formatHexString(chunk);
        // ... process hex data ...
    });
```

#### Memory Tool Pattern:
```java
public Map<String, Object> readMemory(Map<String, Object> arguments) {
    String addressString = getString(arguments, "address");
    int length = getInt(arguments, "length");
    
    Address address = AddressUtil.parseAddress(program, addressString);
    
    byte[] bytes = MemoryUtil.readMemoryBytes(program, address, length);
    if (bytes == null) {
        throw new IllegalArgumentException("Cannot read " + length + 
            " bytes at " + AddressUtil.formatAddress(address));
    }
    
    Map<String, Object> result = new HashMap<>();
    result.put("address", AddressUtil.formatAddress(address));
    result.put("length", bytes.length);
    result.put("hexString", MemoryUtil.formatHexString(bytes));
    result.put("bytes", MemoryUtil.byteArrayToIntList(bytes));
    
    return result;
}
```

### SymbolUtil - Symbol Validation

**PRIMARY RULE**: Use this utility to filter out Ghidra's default symbol names.

```java
import reva.util.SymbolUtil;

// Check if symbol is a default Ghidra name
boolean isDefault = SymbolUtil.isDefaultSymbolName("FUN_00404000"); // true
boolean isDefault2 = SymbolUtil.isDefaultSymbolName("main"); // false

// Filter out default names when listing symbols
List<Symbol> userSymbols = allSymbols.stream()
    .filter(symbol -> !SymbolUtil.isDefaultSymbolName(symbol.getName()))
    .collect(Collectors.toList());
```

#### Recognized Default Patterns:
- `FUN_xxxxxxxx` - Functions
- `LAB_xxxxxxxx` - Labels  
- `SUB_xxxxxxxx` - Subroutines
- `DAT_xxxxxxxx` - Data
- `EXT_xxxxxxxx` - External references
- `PTR_xxxxxxxx` - Pointers
- `ARRAY_xxxxxxxx` - Arrays

### RevaInternalServiceRegistry - Service Dependency Injection

**PRIMARY RULE**: Use this registry to access core ReVa services without tight coupling.

```java
import reva.util.RevaInternalServiceRegistry;
import reva.plugin.ConfigManager;

// Get configuration service
ConfigManager config = RevaInternalServiceRegistry.getService(ConfigManager.class);
if (config != null) {
    int timeout = config.getDecompilerTimeoutSeconds();
    boolean debugMode = config.isDebugMode();
}

// Register service (typically done during plugin initialization)
RevaInternalServiceRegistry.registerService(MyService.class, myServiceImpl);

// Unregister when shutting down
RevaInternalServiceRegistry.unregisterService(MyService.class);
```

#### Available Services:
- `ConfigManager.class` - ReVa configuration management
- `RevaPlugin.class` - Main plugin instance
- Custom services registered by components

### SchemaUtil - MCP Schema Creation

**PRIMARY RULE**: Use this utility for consistent MCP tool schema definitions.

```java
import reva.util.SchemaUtil;
import io.modelcontextprotocol.spec.McpSchema;

// Create schema using builder pattern
McpSchema.JsonSchema schema = SchemaUtil.builder()
    .stringProperty("programPath", "Path to the program")
    .stringProperty("address", "Address to analyze")
    .booleanProperty("includeContext", "Include decompilation context", false)
    .integerProperty("maxResults", "Maximum number of results", 100)
    .required("programPath")
    .required("address")
    .build();

// Or create properties manually
Map<String, Object> properties = new HashMap<>();
properties.put("name", SchemaUtil.stringProperty("Symbol name to search for"));
properties.put("caseSensitive", SchemaUtil.booleanPropertyWithDefault(
    "Case sensitive search", false));

McpSchema.JsonSchema manualSchema = SchemaUtil.createSchema(
    properties, List.of("name"));
```

#### Schema Helper Methods:
```java
// String properties
SchemaUtil.stringProperty(description)
SchemaUtil.stringPropertyWithDefault(description, defaultValue)

// Boolean properties  
SchemaUtil.booleanProperty(description)
SchemaUtil.booleanPropertyWithDefault(description, defaultValue)

// Integer properties
SchemaUtil.integerProperty(description)
SchemaUtil.integerPropertyWithDefault(description, defaultValue)

// Object properties
SchemaUtil.createOptionalObjectProperty(description, properties)
```

### DebugLogger - Configuration-Aware Debug Logging

**PRIMARY RULE**: Use this logger instead of direct Ghidra `Msg` calls for debug output.

```java
import reva.util.DebugLogger;

// Basic debug logging (only outputs if debug mode enabled)
DebugLogger.debug(this, "Processing function: " + function.getName());

// Debug with exception
DebugLogger.debug(this, "Decompilation failed", exception);

// Specialized debug logging
DebugLogger.debugConnection(this, "Client connected from " + clientIP);
DebugLogger.debugPerformance(this, "Function analysis", durationMs);
DebugLogger.debugToolExecution(this, "rename-variables", "START", 
    "Processing 5 variables");

// Check if debug is enabled (avoid expensive operations)
if (DebugLogger.isDebugEnabled()) {
    String expensiveDebugInfo = buildDetailedAnalysis();
    DebugLogger.debug(this, expensiveDebugInfo);
}
```

#### Debug Categories:
- `debug()` - General debug messages
- `debugConnection()` - MCP connection and transport logging  
- `debugPerformance()` - Performance timing information
- `debugToolExecution()` - Tool lifecycle and execution status

### DecompilationDiffUtil - Decompilation Comparison

**PRIMARY RULE**: Use this utility to compare before/after decompilation and show meaningful changes.

```java
import reva.util.DecompilationDiffUtil;

// Compare decompilations with context
DecompilationDiffUtil.DiffResult diff = DecompilationDiffUtil.createDiff(
    beforeDecompilation, afterDecompilation, 2); // 2 lines context

if (diff.hasChanges()) {
    // Convert to JSON-safe map
    Map<String, Object> diffMap = DecompilationDiffUtil.toMap(diff);
    
    result.put("diff", diffMap);
    result.put("decompilationChanged", true);
} else {
    result.put("decompilationChanged", false);
}
```

#### Diff Result Structure:
```java
{
    "hasChanges": true,
    "summary": "3 lines modified, 1 line added",
    "changedLineCount": 4,
    "snippets": [
        {
            "startLine": 13,
            "endLine": 18,
            "beforeContent": "  13\tint var1;\n  14\tint var2;\n  15\tif (argc > 1) {\n",
            "afterContent": "  13\tint argc_count;\n  14\tint result;\n  15\tif (argc > 1) {\n",
            "changedLines": [13, 14]
        }
    ]
}
```

### SimilarityComparator - Function/Symbol Similarity Analysis

**PRIMARY RULE**: Use this comparator to sort search results by similarity to user input.

```java
import reva.util.SimilarityComparator;

// Create comparator for function name similarity
SimilarityComparator<Function> comparator = new SimilarityComparator<>(
    searchString, 
    new SimilarityComparator.StringExtractor<Function>() {
        @Override
        public String extract(Function function) {
            return function.getName();
        }
    }
);

// Sort functions by similarity to search term
List<Function> functions = getFunctions();
functions.sort(comparator);

// Most similar functions will be at the beginning of the list
```

#### Usage in Search Tools:
```java
public Map<String, Object> searchFunctions(Map<String, Object> arguments) {
    String searchTerm = getString(arguments, "searchTerm");
    
    List<Function> allFunctions = getAllFunctions(program);
    
    // Sort by similarity to search term
    SimilarityComparator<Function> comparator = new SimilarityComparator<>(
        searchTerm,
        function -> function.getName()
    );
    
    allFunctions.sort(comparator);
    
    // Take top N results
    List<Function> topResults = allFunctions.stream()
        .limit(maxResults)
        .collect(Collectors.toList());
    
    return formatFunctionResults(topResults);
}
```

## Common Utility Patterns

### 1. Address Handling Pattern
```java
// Input validation and parsing
String addressString = getString(arguments, "address");
Address address = AddressUtil.parseAddress(program, addressString);
if (address == null) {
    throw new IllegalArgumentException("Invalid address: " + addressString);
}

// Tool processing...

// Output formatting
result.put("address", AddressUtil.formatAddress(address));
```

### 2. Program Validation Pattern
```java
public Map<String, Object> executeTool(Map<String, Object> arguments) {
    try {
        String programPath = getString(arguments, "programPath");
        Program program = ProgramLookupUtil.getValidatedProgram(programPath);
        
        // Tool logic here...
        
    } catch (ProgramValidationException e) {
        throw new IllegalArgumentException(e.getMessage());
    }
}
```

### 3. Safe Memory Access Pattern
```java
// Check if we can read memory
byte[] bytes = MemoryUtil.readMemoryBytes(program, address, length);
if (bytes == null) {
    throw new IllegalArgumentException("Cannot read memory at " + 
        AddressUtil.formatAddress(address));
}

// Process bytes safely
String hex = MemoryUtil.formatHexString(bytes);
List<Integer> intList = MemoryUtil.byteArrayToIntList(bytes);
```

### 4. Debug Logging Pattern
```java
public Map<String, Object> executeTool(Map<String, Object> arguments) {
    String toolName = "my-tool";
    DebugLogger.debugToolExecution(this, toolName, "START", 
        "Arguments: " + arguments.keySet());
    
    try {
        long startTime = System.currentTimeMillis();
        
        // Tool logic...
        
        long duration = System.currentTimeMillis() - startTime;
        DebugLogger.debugPerformance(this, toolName + " execution", duration);
        DebugLogger.debugToolExecution(this, toolName, "SUCCESS", 
            "Processed in " + duration + "ms");
        
        return result;
    } catch (Exception e) {
        DebugLogger.debugToolExecution(this, toolName, "ERROR", e.getMessage());
        throw e;
    }
}
```

### 5. Data Type Processing Pattern
```java
// Parse data type string
String dataTypeString = getString(arguments, "dataType");
DataType newDataType = DataTypeParserUtil.parseDataTypeObjectFromString(
    dataTypeString, "");

if (newDataType == null) {
    // Build helpful error message
    throw new IllegalArgumentException(
        "Could not find data type '" + dataTypeString + "'. " +
        "Supported formats: int, char*, int[10], struct MyStruct");
}

// Apply data type...

// Return metadata (never the DataType object itself)
result.put("dataType", DataTypeParserUtil.createDataTypeInfo(newDataType));
```

## Error Handling Guidelines

### 1. Use Utility Error Messages
```java
// GOOD - Utility provides helpful error with suggestions
try {
    Program program = ProgramLookupUtil.getValidatedProgram(programPath);
} catch (ProgramValidationException e) {
    throw new IllegalArgumentException(e.getMessage()); // Includes suggestions
}

// BAD - Generic error without context
Program program = RevaProgramManager.getProgramByPath(programPath);
if (program == null) {
    throw new IllegalArgumentException("Program not found: " + programPath);
}
```

### 2. Validate Addresses Properly
```java
// GOOD - Uses utility with proper validation
Address address = AddressUtil.parseAddress(program, addressString);
if (address == null) {
    throw new IllegalArgumentException("Invalid address format: " + addressString + 
        ". Expected format: 0x404000 or 404000");
}

// BAD - Direct parsing without validation
try {
    Address address = program.getAddressFactory().getAddress(addressString);
} catch (Exception e) {
    throw new IllegalArgumentException("Invalid address");
}
```

### 3. Handle Memory Access Safely
```java
// GOOD - Uses utility with null check
byte[] bytes = MemoryUtil.readMemoryBytes(program, address, length);
if (bytes == null) {
    throw new IllegalArgumentException("Cannot read " + length + 
        " bytes at " + AddressUtil.formatAddress(address) + 
        ". Address may be invalid or memory unmapped.");
}

// BAD - Direct memory access without error handling
byte[] bytes = new byte[length];
program.getMemory().getBytes(address, bytes); // Can throw exception
```

## Testing Considerations

### 1. Utility Method Testing
```java
@Test
public void testAddressFormatting() {
    // Test address formatting consistency
    Address addr = program.getAddressFactory().getAddress("0x404000");
    String formatted = AddressUtil.formatAddress(addr);
    assertEquals("0x404000", formatted);
    
    // Test parsing round-trip
    Address parsed = AddressUtil.parseAddress(program, formatted);
    assertEquals(addr, parsed);
}

@Test
public void testProgramLookupErrorMessages() {
    // Test helpful error messages
    try {
        ProgramLookupUtil.getValidatedProgram("/NonExistent.exe");
        fail("Expected ProgramValidationException");
    } catch (ProgramValidationException e) {
        // Error message should include suggestions
        assertTrue(e.getMessage().contains("Available programs:"));
    }
}
```

### 2. Mock Service Registry for Tests
```java
@Before
public void setUp() {
    // Clear registry for clean test state
    RevaInternalServiceRegistry.clearAllServices();
    
    // Register mock services
    ConfigManager mockConfig = Mockito.mock(ConfigManager.class);
    when(mockConfig.isDebugMode()).thenReturn(false);
    when(mockConfig.getDecompilerTimeoutSeconds()).thenReturn(30);
    RevaInternalServiceRegistry.registerService(ConfigManager.class, mockConfig);
}

@After
public void tearDown() {
    RevaInternalServiceRegistry.clearAllServices();
}
```

### 3. Test Memory Utilities
```java
@Test
public void testMemoryUtilities() {
    // Test safe memory reading
    Address validAddress = program.getMinAddress();
    byte[] bytes = MemoryUtil.readMemoryBytes(program, validAddress, 16);
    assertNotNull("Should read memory at valid address", bytes);
    
    // Test formatting
    String hex = MemoryUtil.formatHexString(bytes);
    assertFalse("Hex string should not be empty", hex.isEmpty());
    
    // Test invalid address handling
    Address invalidAddress = program.getAddressFactory().getAddress("0xFFFFFFFF");
    byte[] invalidBytes = MemoryUtil.readMemoryBytes(program, invalidAddress, 16);
    assertNull("Should return null for invalid address", invalidBytes);
}
```

## Integration Patterns

### 1. Tool Provider Integration
```java
public class MyToolProvider extends AbstractToolProvider {
    
    @Override
    protected Map<String, Object> executeTool(String toolName, Map<String, Object> arguments) {
        // Always validate program first
        String programPath = getString(arguments, "programPath");
        Program program = ProgramLookupUtil.getValidatedProgram(programPath);
        
        // Use utility methods for consistent behavior
        String addressString = getString(arguments, "address");
        Address address = AddressUtil.parseAddress(program, addressString);
        
        // Process with utilities...
        
        // Format output consistently
        Map<String, Object> result = new HashMap<>();
        result.put("programPath", programPath);
        result.put("address", AddressUtil.formatAddress(address));
        
        return result;
    }
}
```

### 2. Service Access Pattern
```java
public class MyComponent {
    
    private ConfigManager getConfig() {
        ConfigManager config = RevaInternalServiceRegistry.getService(ConfigManager.class);
        if (config == null) {
            throw new IllegalStateException("ConfigManager not available");
        }
        return config;
    }
    
    public void performOperation() {
        if (DebugLogger.isDebugEnabled()) {
            DebugLogger.debug(this, "Starting operation");
        }
        
        int timeout = getConfig().getDecompilerTimeoutSeconds();
        // ... use timeout in operation ...
    }
}
```

## Important Notes

- **NEVER bypass these utilities** - They ensure consistency across all ReVa tools
- **All tools MUST use `AddressUtil.formatAddress()`** for address output in JSON
- **All tools MUST use `ProgramLookupUtil.getValidatedProgram()`** for program validation
- **Debug logging MUST use `DebugLogger`** to respect configuration settings
- **Memory access MUST use `MemoryUtil`** for safety and error handling
- **Data type parsing MUST use `DataTypeParserUtil`** for consistency
- **These utilities are the foundation** - breaking changes here affect ALL tools
- **Test utility methods thoroughly** - they are used everywhere
- **Service registry provides loose coupling** - use it for accessing ReVa services
- **Schema utilities ensure consistent MCP schemas** - use the builder pattern when possible