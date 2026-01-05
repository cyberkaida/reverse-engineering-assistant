# Integration Test Guidelines

## Base Class and Infrastructure
All integration tests extend `RevaIntegrationTestBase` which provides:
- Shared Ghidra environment (TestEnv, PluginTool, MCP server) across all tests in a class
- Fresh `Program` instance for each test with pre-configured memory block at 0x01000000
- MCP client utilities and helper methods for calling tools
- Automatic program registration/unregistration with the MCP server

## Test Environment Configuration
**Build Configuration** (build.gradle):
- Tests use `forkEvery 1` - each test runs in its own JVM to prevent state conflicts
- Tests require `java.awt.headless=false` - GUI environment required for Ghidra
- Run with: `gradle integrationTest --info`

**Shared Environment Pattern**:
- `@BeforeClass` (static): Lazy initialization of shared TestEnv, PluginTool, and MCP server
- `@Before` (instance): Creates fresh Program, registers with server, opens in tool
- `@After` (instance): Unregisters and releases program, keeps shared environment running
- `@AfterClass` (static): Shuts down shared environment after all tests complete

## Writing Integration Tests

### Basic Test Structure
```java
public class MyToolIntegrationTest extends RevaIntegrationTestBase {
    private String programPath;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();

        // Set up test data in program using transactions
        int txId = program.startTransaction("Setup test data");
        try {
            // Create functions, data, symbols, etc.
        } finally {
            program.endTransaction(txId, true);
        }

        // Open program in tool (usually needed for tools to find it)
        env.open(program);
    }

    @Test
    public void testMyTool() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Call the MCP tool
            CallToolResult result = client.callTool(
                new CallToolRequest("my-tool", Map.of("programPath", programPath))
            );

            // Validate MCP response
            assertMcpResultNotError(result, "Tool should not error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertEquals(expectedValue, json.get("field").asText());

            // **CRITICAL**: Validate actual program state changes
            FunctionManager fm = program.getFunctionManager();
            Function func = fm.getFunctionAt(testAddr);
            assertEquals("Expected name", func.getName());
        });
    }
}
```

### Critical Validation Pattern
**DO NOT** only check MCP tool responses. **ALWAYS** validate actual Ghidra program state:
- Use `Function.getParameters()` and `Function.getAllVariables()` to verify variable changes
- Use `DataType.isEquivalent()` to compare datatypes before/after modifications
- Use `FunctionManager`, `Listing`, `SymbolTable`, etc. to verify state changes
- Example: After renaming a function, check `program.getFunctionManager().getFunctionAt(addr).getName()`

### Helper Methods Available
- `createMcpTransport()` - Creates HTTP transport to MCP server
- `withMcpClient(transport, client -> {...})` - Execute operations with auto-closing client
- `parseJsonContent(String)` - Parse JSON from MCP TextContent
- `assertMcpResultNotError(result, message)` - Assert MCP result is not an error
- `callMcpTool(toolName, args)` - Simplified tool call that returns content string
- `getAvailableTools()` - List all registered tools

### Common Patterns
- **Addresses**: Use addresses within the default memory block (0x01000000 to 0x01001000)
- **Transactions**: Always wrap program modifications in `startTransaction()` / `endTransaction()`
- **Program registration**: Base class handles registration, but may need `env.open(program)` for ProgramManager
- **Error testing**: Use `assertTrue(result.isError())` to verify expected errors
- **JSON parsing**: Use `objectMapper.readTree()` or `parseJsonContent()` helper

## Performance Benefits
- **Faster execution**: Shared environment eliminates 5-10 second Ghidra startup per test
- **Stable connections**: MCP server runs once per test class, not per test
- **Resource efficiency**: Single Ghidra instance serves all tests in a class
- **Test isolation**: Fresh program per test prevents state leakage

## Common Issues
- **Fork requirement**: Tests run in separate JVMs (forkEvery=1) - don't rely on static state between tests
- **Headless mode**: Tests fail if run with `java.awt.headless=true`
- **Transaction leaks**: Always close transactions in finally blocks
- **Program not found**: Ensure `env.open(program)` is called if tools can't find the program
- **JSON parsing**: Use helper methods, don't parse manually