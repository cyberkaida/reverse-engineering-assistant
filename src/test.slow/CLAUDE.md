# Integration Test Guidelines

## Shared Test Environment Architecture
Integration tests use a shared Ghidra environment to significantly speed up execution and provide stable test conditions:

### Test Lifecycle
- **@BeforeClass**: Sets up shared TestEnv, PluginTool, and MCP server once for all tests
- **@Before**: Creates fresh Program for each test, reuses shared instances
- **@After**: Cleans up test program, keeps shared environment running
- **@AfterClass**: Shuts down shared environment after all tests complete

### Test Setup Pattern
1. **Shared Environment**: Automatically handles MCP server and plugin setup
2. **Fresh Programs**: Each test gets a fresh program via `createDefaultProgram(getName(), ...)`
3. **Auto-registration**: Program is automatically registered with shared MCP server
4. **Client Pattern**: Use `withMcpClient(createMcpTransport(), client -> { ... })` for MCP calls
5. **Initialization**: Always call `client.initialize()` before making tool calls

## Critical Testing Requirements

### State Validation
- **CRITICAL**: Integration tests must validate actual Ghidra program state changes, not just MCP tool responses
- **Before/After Pattern**: Capture program state before tool execution, validate changes afterward
- **Specific Checks**: Use `Function.getParameters()`, `Function.getAllVariables()`, `DataType.isEquivalent()`

### Example State Validation Pattern
```java
@Test
public void testVariableRename() throws Exception {
    withMcpClient(createMcpTransport(), client -> {
        client.initialize();
        
        // Capture state BEFORE tool execution
        Variable[] beforeVars = testFunction.getAllVariables();
        String originalName = beforeVars[0].getName();
        
        // Execute MCP tool
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", programPath);
        args.put("oldName", originalName);
        args.put("newName", "renamed_var");
        CallToolResult result = client.callTool(new CallToolRequest("rename-variables", args));
        
        // Validate ACTUAL program state changed
        Variable[] afterVars = testFunction.getAllVariables();
        assertEquals("Variable name should be changed", "renamed_var", afterVars[0].getName());
        
        // Also validate MCP response (secondary)
        assertTrue("Tool should report success", 
            result.content().get(0).text().contains("success"));
    });
}
```

## Performance Benefits
- **Faster execution**: No Ghidra restart between tests within a class (saves 5-10 seconds per test)
- **Stable connections**: MCP server persists across all tests in a single test class
- **Resource efficiency**: Single Ghidra instance serves all tests in the same class
- **Reliable state**: Fresh program per test ensures test isolation
- **Lazy initialization**: Shared environment created only when first test runs

## Test Environment Configuration
- **Fork Policy**: `forkEvery 1` prevents configuration conflicts between test classes
- **Headless Setting**: Integration tests run with `java.awt.headless=false`
- **Server Setup**: Shared MCP server runs on dynamic port to avoid conflicts
- **Tool Registration**: Plugin tools automatically register with server manager

## Success Indicators and Debugging
- Look for `INFO Registered tool with MCP server: Test Tool` in logs
- MCP server shows `INFO MCP server started successfully` once at class start
- Each test creates fresh program without restarting server
- Client initialization should complete without timeout

## Common Issues and Solutions
- **Tool Registration**: Shared plugin is already registered with server - no need to re-register
- **Transaction Management**: Always wrap program modifications in transactions
- **Program Cleanup**: Programs are automatically unregistered from server in @After
- **Port Conflicts**: Use dynamic port allocation in shared test environment
- **State Isolation**: Each test gets fresh program but shared Ghidra environment

## Don't Write Useless Tests
- Tests must have a clear purpose and validate meaningful functionality
- Focus on testing tool behavior and program state changes
- Avoid tests that only validate JSON structure without checking program modifications
- Each test should contribute to overall confidence in the system's correctness