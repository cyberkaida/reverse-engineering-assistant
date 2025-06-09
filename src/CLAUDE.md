# Testing Guidelines
- Integration tests go in `test.slow`, unit tests in `test`
- Unit tests should test things that don't require a Ghidra environment
- **CRITICAL**: Integration tests should validate actual Ghidra program state changes, not just MCP tool responses
- Use `Function.getParameters()` and `Function.getAllVariables()` to validate variable changes
- Use `DataType.isEquivalent()` to compare datatypes before/after changes

# Address Formatting
- **ALWAYS use `AddressUtil.formatAddress(address)`** for consistent address formatting in JSON output
- This ensures all addresses have the "0x" prefix format consistently across all ReVa tools
- Import: `import reva.util.AddressUtil;`
- Format: `AddressUtil.formatAddress(address)` returns `"0x" + address.toString()`

# Decompiler Tool Implementation Pattern
## Adding New Tools to DecompilerToolProvider.java
1. Create `register[ToolName]Tool()` method following existing patterns
2. Call it from `registerTools()` method
3. Use `HighFunctionDBUtil.updateDBVariable()` for persisting variable changes
4. Follow the `rename-variables` pattern for consistency
5. Handle decompilation with proper error handling and transaction management

## Key APIs
- `DataTypeParserUtil.parseDataTypeObjectFromString()` - parse datatype strings like "char*", "int[10]"
- `HighFunctionDBUtil.updateDBVariable(symbol, newName, newDataType, SourceType.USER_DEFINED)` - persist changes
- `DecompInterface` - get decompiled function and high-level representation
- `LocalSymbolMap.getSymbols()` returns Iterator, not Iterable - use while loop, not for-each

## Common Patterns
- Always use transactions when modifying program state
- Handle decompilation failures gracefully with try-catch
- Validate parameters before processing (non-empty mappings, valid function, etc.)
- Return structured JSON with success flags and updated decompilation
- Follow MCP tool schema patterns for consistency
- Use AbstractToolProvider helper methods (getString, getInt, getOptionalInt, getOptionalBoolean) for all parameters to handle type conversion and validation
- Wrap parameter extraction in try-catch blocks to convert IllegalArgumentException to user-friendly createErrorResult calls

# JUnit Version
- Use JUnit 4 for all tests (imports: `org.junit.Test`, `org.junit.Before`)
- Avoid JUnit 5 annotations (`@ParameterizedTest`, etc.) - causes compilation errors
