# Integration Test Guidelines

## Program Registration (CRITICAL)
- **ESSENTIAL**: After creating/modifying a program, you MUST register it properly for MCP tools to find it
- Add these calls after program setup:
```java
// Open the program in the tool's ProgramManager so it can be found by RevaProgramManager
env.open(program);

// Also open it directly in the tool's ProgramManager service to ensure it's available
ghidra.app.services.ProgramManager programManager = tool.getService(ghidra.app.services.ProgramManager.class);
if (programManager != null) {
    programManager.openProgram(program);
}

// Register the program directly with RevaProgramManager for test environments
reva.plugin.RevaProgramManager.registerProgram(program);

// Register the program with the server manager so it can be found by the tools
if (serverManager != null) {
    serverManager.programOpened(program);
}
```

## Test Setup Pattern
1. In `@Before` method, set `programPath = program.getDomainFile().getPathname()`
2. Add test data to the program within transactions
3. **REGISTER THE PROGRAM** using the code above
4. Use `withMcpClient(createMcpTransport(), client -> { ... })` pattern for MCP calls
5. Always call `client.initialize()` before making tool calls

## Success Indicators
- Look for `INFO Program opened: [testName] (RevaPlugin)` in logs - this indicates successful registration
- If you see `WARN Could not find program: /testName` - the registration step was missed

## Common Issues
- **Program registration**: Most common issue - always add the registration calls after program setup
- Tool registration: Verify tools are registered before calling them  
- Transaction management: Always wrap program modifications in transactions