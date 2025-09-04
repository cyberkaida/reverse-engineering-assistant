# Integration Test Development Guidelines

## Test Design Philosophy

- **State Validation**: Always validate actual Ghidra program state changes, not just MCP tool responses
- **Purpose-Driven Testing**: Only write tests that verify meaningful functionality
- **End-to-End Validation**: Set up program state, execute tools, validate both response and program modifications

## Critical Testing Requirements

1. **Program State Validation**:
   - Use `Function.getParameters()` and `Function.getAllVariables()` to validate variable changes
   - Use `DataType.isEquivalent()` to compare datatypes before/after changes
   - Check actual symbol table entries, not just tool responses

2. **Shared Test Environment**:
   - Tests use shared Ghidra environment for faster execution
   - Each test gets a fresh program via `createDefaultProgram()`
   - MCP server persists across tests within the same class

3. **Test Isolation**:
   - Fork every test to prevent configuration conflicts
   - Programs are automatically registered/unregistered with MCP server
   - Always wrap program modifications in transactions

## Test Requirements
- Tests run with `java.awt.headless=false` (GUI environment required)
- **You are not finished until all tests pass!**
