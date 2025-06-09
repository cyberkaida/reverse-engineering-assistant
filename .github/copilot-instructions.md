- This is a Ghidra extensions for Ghidra 11.3 and later called "ReVa", the Reverse Engineering Assistant.
- The extension provides a Model Context Protocol (MCP) server for Ghidra. The server is implemented in Java and uses the MCP Java SDK.
- Remember that MCP is in development, so make sure to check the MCP documentation for the latest information.

Some good resources include:
- [The MCP Java SDK](https://modelcontextprotocol.io/sdk/java/mcp-server)
- [Ghidra on GitHub](https://github.com/NationalSecurityAgency/ghidra)

- If you want to find a Ghidra API, start from the FlatProgramAPI or the ProgramPlugin API in the Ghidra repo. Use the GitHub tools to search for Ghidra documentation.
- We don't use a gradle wrapper, so just run `gradle` in the root directory to build the project. We do have the Java tools installed in VSCode so you can just check for errors with VSCode instead.
- When writing tests, use the Ghidra test framework. The tests are in the `src/test` directory. It is easy to run them with `gradle test --info` and the integration tests with `gradle integrationTest --info`.
- You can use standard gradle test filtering to run specific tests with both of the test targets.
- We target Ghidra 11.3 and later. Note we should use Java 21.