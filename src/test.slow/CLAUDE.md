# Integration Test Guidelines

## Test Setup Pattern
1. In `@Before` method, set `programPath = program.getDomainFile().getPathname()`
2. Add test data to the program within transactions
3. Open the program in the tool's ProgramManager:
```java
// Open the program in the tool's ProgramManager so it can be found by RevaProgramManager
env.open(program);

// Also open it directly in the tool's ProgramManager service to ensure it's available
ghidra.app.services.ProgramManager programManager = tool.getService(ghidra.app.services.ProgramManager.class);
if (programManager != null) {
    programManager.openProgram(program);
}

// Register the program with the server manager so it can be found by the tools
if (serverManager != null) {
    serverManager.programOpened(program);
}
```
4. Use `withMcpClient(createMcpTransport(), client -> { ... })` pattern for MCP calls
5. Always call `client.initialize()` before making tool calls

## Success Indicators
- Look for `INFO Program opened: [testName] (RevaPlugin)` in logs - this indicates successful registration

## Common Issues
- Tool registration: Verify tools are registered before calling them  
- Transaction management: Always wrap program modifications in transactions