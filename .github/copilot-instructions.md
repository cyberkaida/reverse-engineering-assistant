This is a Ghidra extensions for Ghidra 11.3 and later called "ReVa", the Reverse Engineering Assistant.

The extension provides a Model Context Protocol (MCP) server for Ghidra. The server is implemented in Java and uses the MCP Java SDK.

Remember the life cycle of Ghidra extensions and always reference the Ghidra documentation for the latest information.
We need the core MCP server to be static so it is tied to the lifetime of Ghidra.
Some program specific data can be exposed as resources and tied to the lifetime of the program.
Make sure that tools are available in the static context and not tied to a single program lifetime,
they should take the program path as a parameter when needed.

Remember that MCP is in development, so make sure to check the MCP documentation for the latest information.

Some good resources include:
- [The MCP Java SDK](https://modelcontextprotocol.io/sdk/java/mcp-server)
- [Ghidra on GitHub](https://github.com/NationalSecurityAgency/ghidra)

If you want to find a Ghidra API, start from the FlatProgramAPI or the ProgramPlugin API in the Ghidra repo. Use the GitHub tools to search for Ghidra documentation.

We don't use a gradle wrapper, so just run `gradle` in the root directory to build the project. We do have the Java tools installed in VSCode so you can just check for errors with VSCode instead.

When writing tests, use the Ghidra test framework. The tests are in the `src/test` directory. It is easy to run them with `gradle test --info`.

We target Ghidra 11.3 and later. Note we should use Java 21.