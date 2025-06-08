# Integration Test Guidelines

## Shared Test Environment
Integration tests now use a shared Ghidra environment to significantly speed up execution:

- **@BeforeClass**: Sets up shared TestEnv, PluginTool, and MCP server once for all tests
- **@Before**: Creates fresh Program for each test, reuses shared instances
- **@After**: Cleans up test program, keeps shared environment running
- **@AfterClass**: Shuts down shared environment after all tests complete

## Test Setup Pattern
1. Shared environment automatically handles MCP server and plugin setup
2. Each test gets a fresh program via `createDefaultProgram(getName(), ...)`
3. Program is automatically registered with shared MCP server
4. Use `withMcpClient(createMcpTransport(), client -> { ... })` pattern for MCP calls
5. Always call `client.initialize()` before making tool calls

## Benefits of Shared Environment
- **Faster execution**: No Ghidra restart between tests within a class (saves 5-10 seconds per test)
- **Stable connections**: MCP server persists across all tests in a single test class
- **Resource efficiency**: Single Ghidra instance serves all tests in the same class
- **Reliable state**: Fresh program per test ensures test isolation
- **Lazy initialization**: Shared environment is created only when first test runs

## Success Indicators
- Look for `INFO Registered tool with MCP server: Test Tool` in logs
- MCP server shows `INFO MCP server started successfully` once at class start
- Each test creates fresh program without restarting server

## Common Issues
- Tool registration: Shared plugin is already registered with server
- Transaction management: Always wrap program modifications in transactions
- Program cleanup: Programs are automatically unregistered from server in @After