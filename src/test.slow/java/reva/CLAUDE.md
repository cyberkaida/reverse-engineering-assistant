# Integration Test Implementation Guidelines

## Test Writing Principles

### Critical Requirements
- **CRITICAL**: Integration tests should validate actual Ghidra program state changes, not just MCP tool responses
- When writing integration tests, follow the pattern: setup program → call tool → validate program modifications
- If the tool modifies the program, validate the actual modification occurred in Ghidra
- Don't write useless tests - each test must have a clear purpose and validate meaningful functionality

### Test Structure Pattern
```java
@Test
public void testToolModification() throws Exception {
    // 1. Setup: Create program state
    // 2. Capture: Record state before modification
    // 3. Execute: Call MCP tool
    // 4. Validate: Check program state actually changed
    // 5. Secondary: Verify MCP response is correct
}
```

### State Validation Examples
- **Variable changes**: Use `Function.getAllVariables()` and compare before/after
- **Parameter changes**: Use `Function.getParameters()` 
- **DataType changes**: Use `DataType.isEquivalent()` to compare types
- **Comment changes**: Check actual comment exists in program
- **Function changes**: Verify function properties were modified

### Required Test Patterns
- Always use the shared test environment from `RevaIntegrationTestBase`
- Call `client.initialize()` before any tool calls
- Use `withMcpClient(createMcpTransport(), client -> { ... })` pattern
- Capture program state BEFORE tool execution
- Validate program state AFTER tool execution
- Test both success and failure cases where appropriate

### Anti-Patterns to Avoid
- Testing only MCP JSON response without checking program state
- Tests that don't verify the core functionality they claim to test
- Tests that only check response format without validating behavior
- Duplicate tests that don't add additional value
