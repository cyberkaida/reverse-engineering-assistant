# Developer notes

These are some notes documenting annoying or complex parts of developing for ReVa and
the general architecture of ReVa. It is assumed you read the [README.md](/README.md) before
reading this.

## Architecture Overview

ReVa (Reverse Engineering Assistant) is a Ghidra extension that provides a Model Context Protocol (MCP) server for interacting with Ghidra programmatically. The extension follows a modular architecture with the following key components:

### Core Components

1. **Plugin Architecture** - ReVa provides two plugins to Ghidra:
   - **[RevaApplicationPlugin](src/main/java/reva/plugin/RevaApplicationPlugin.java)** - An [application-level plugin](https://github.com/NationalSecurityAgency/ghidra/blob/stable/Ghidra/Framework/Project/src/main/java/ghidra/framework/main/ApplicationLevelOnlyPlugin.java) that manages the MCP server at the Ghidra application level. This plugin:
     - Implements `ApplicationLevelOnlyPlugin` to persist across tool sessions
     - Starts and manages the MCP server for the entire Ghidra instance
     - Survives when individual analysis tools are closed and reopened
     - Provides the `RevaMcpService` to other plugins
     - Runs in the FrontEndTool (project window)
     - Allows access to the entire Ghidra project from one MCP client session

   - **[RevaPlugin](src/main/java/reva/plugin/RevaPlugin.java)** - A tool-level plugin that runs in each CodeBrowser tool. This plugin:
     - Extends `ProgramPlugin` for program-specific functionality
       - Things like current location, current program, etc.
     - Connects to the application-level MCP server via `RevaMcpService`
     - Handles program open/close events for its specific tool
     - Provides the UI components (RevaProvider)
     - Notifies the MCP server about program lifecycle in its tool

2. **[McpServerManager](src/main/java/reva/server/McpServerManager.java)** - Manages the Model Context Protocol server, including configuration, registration of resources and tools. The server lifecycle is tied to Ghidra's lifetime through the application plugin.

3. **[RevaProgramManager](src/main/java/reva/plugin/RevaProgramManager.java)** - Tracks open programs across all Ghidra tools and provides centralized program access.

4. **[ProgramLookupUtil](src/main/java/reva/util/ProgramLookupUtil.java)** - Validates program paths and provides helpful error messages. Always use `ProgramLookupUtil.getValidatedProgram(programPath)` for program resolution in tools.

5. **[RevaInternalServiceRegistry](src/main/java/reva/util/RevaInternalServiceRegistry.java)** - A simple service locator that allows components to find each other at runtime.

6. **[ConfigManager](src/main/java/reva/plugin/ConfigManager.java)** - Manages configuration settings for the extension with support for Ghidra ToolOptions (GUI) or file-based (headless) backends.

7. **[AddressUtil](src/main/java/reva/util/AddressUtil.java)** - Provides consistent address formatting for JSON output. Always use `AddressUtil.formatAddress(address)` to ensure addresses have the `0x` prefix.

8. **[DataTypeParserUtil](src/main/java/reva/util/DataTypeParserUtil.java)** - Parses datatype strings (e.g., `"char*"`, `"int[10]"`) into Ghidra DataType objects.

### MCP Server Components

The MCP server components are divided into two main categories:

1. **[Resources](src/main/java/reva/resources/ResourceProvider.java)** - Read-only data sources exposed by the MCP server. This will be expanded in the future, when more MCP clients support resources.
2. **[Tools](src/main/java/reva/tools/ToolProvider.java)** - Interactive operations that can be invoked by clients. These mirror what humans can do in Ghidra, such as searching for symbols, managing bookmarks, and more.

Each component follows a provider pattern where the provider is responsible for registering and managing one or more resources or tools.

### Operational Modes

ReVa supports three operational modes, all sharing the same core MCP server infrastructure:

1. **GUI Mode (Ghidra Plugin)** - The standard way to use ReVa when working interactively with Ghidra:
   - Server runs on `http://localhost:8080/mcp/message` (configurable)
   - Uses [`RevaApplicationPlugin`](src/main/java/reva/plugin/RevaApplicationPlugin.java) for lifecycle management
   - Configuration stored in Ghidra's ToolOptions (persists across sessions)
   - Ideal for interactive analysis with Claude Desktop, VSCode, or other MCP clients

2. **Headless Mode (PyGhidra Script)** - For automated analysis pipelines:
   - Started via [`RevaHeadlessLauncher`](src/main/java/reva/headless/RevaHeadlessLauncher.java)
   - Uses file-based configuration (no GUI required)
   - Integrates with Python scripts using PyGhidra
   - See [`scripts/reva_headless_server.py`](scripts/reva_headless_server.py) for usage

3. **Claude CLI Mode (Stdio Transport)** - For direct integration with Claude CLI:
   - Uses the `mcp-reva` Python command
   - Stdio bridge proxies MCP protocol to local HTTP server (random port)
   - Automatic temporary project creation and cleanup
   - Add to Claude CLI: `claude mcp add ReVa -- mcp-reva`

### Tool Provider Categories

ReVa provides 17 tool providers organized by purpose:

| Category | Providers | Description |
|----------|-----------|-------------|
| **Core Analysis** | [`DecompilerToolProvider`](src/main/java/reva/tools/decompiler/DecompilerToolProvider.java), [`FunctionToolProvider`](src/main/java/reva/tools/functions/FunctionToolProvider.java), [`StringToolProvider`](src/main/java/reva/tools/strings/StringToolProvider.java), [`SymbolToolProvider`](src/main/java/reva/tools/symbols/SymbolToolProvider.java), [`CrossReferencesToolProvider`](src/main/java/reva/tools/xrefs/CrossReferencesToolProvider.java), [`MemoryToolProvider`](src/main/java/reva/tools/memory/MemoryToolProvider.java) | Primary analysis operations |
| **Data & Types** | [`DataToolProvider`](src/main/java/reva/tools/data/DataToolProvider.java), [`DataTypeToolProvider`](src/main/java/reva/tools/datatypes/DataTypeToolProvider.java), [`StructureToolProvider`](src/main/java/reva/tools/structures/StructureToolProvider.java) | Data definition and type management |
| **Advanced Analysis** | [`CallGraphToolProvider`](src/main/java/reva/tools/callgraph/CallGraphToolProvider.java), [`DataFlowToolProvider`](src/main/java/reva/tools/dataflow/DataFlowToolProvider.java), [`ConstantSearchToolProvider`](src/main/java/reva/tools/constants/ConstantSearchToolProvider.java), [`VtableToolProvider`](src/main/java/reva/tools/vtable/VtableToolProvider.java), [`ImportExportToolProvider`](src/main/java/reva/tools/imports/ImportExportToolProvider.java) | Specialized analysis features |
| **Annotations** | [`CommentToolProvider`](src/main/java/reva/tools/comments/CommentToolProvider.java), [`BookmarkToolProvider`](src/main/java/reva/tools/bookmarks/BookmarkToolProvider.java) | Program annotations |
| **Project** | [`ProjectToolProvider`](src/main/java/reva/tools/project/ProjectToolProvider.java) | Program and project management |

## Plugin Architecture and Lifecycle

### Why an Application Plugin and a Tool Plugin?

ReVa aims to provide a multi-program environment to solve complex reverse engineering tasks. The MCP streamable HTTP architecture requires a persistent server for the lifetime of the session.
Both of these goals require some components to run for the entire Ghidra session (MCP server, project access), while others need to be tool-specific (current program, current selection).

1. **Application Plugin Benefits**:
   - The MCP server stays running even when you close all CodeBrowser windows
   - External clients (Claude, VSCode, etc.) maintain their connection
   - No interruption when switching between programs or tools
   - Single server instance handles all Ghidra tools

2. **Tool Plugin Benefits**:
   - Each CodeBrowser gets program-specific functionality
   - UI components are properly integrated with each tool
   - Program lifecycle events are handled per-tool
   - Multiple programs can be open simultaneously

### How They Work Together

1. **Startup Sequence**:
   - When Ghidra starts, `RevaApplicationPlugin` loads in the [FrontEndTool](https://github.com/NationalSecurityAgency/ghidra/blob/stable/Ghidra/Framework/Project/src/main/java/ghidra/framework/main/FrontEndTool.java)
   - It starts the MCP server and registers `RevaMcpService`
   - When you open a CodeBrowser, `RevaPlugin` loads and connects to the service
   - The tool plugin registers itself with the application plugin

2. **Communication Flow**:
   - External MCP clients connect to the server in `RevaApplicationPlugin`
   - The server uses `RevaProgramManager` to find programs across all Ghidra tools
   - Tool plugins notify the server about program open/close events
   - The server can access programs from any registered tool

3. **Shutdown Sequence**:
   - When a CodeBrowser closes, `RevaPlugin` unregisters from the server
   - The MCP server continues running for other tools
   - When Ghidra shuts down, `RevaApplicationPlugin` stops the server

## Lifecycle Management

ReVa is designed to handle the Ghidra lifecycle correctly:

1. **Application Lifecycle** - The [`RevaApplicationPlugin`](src/main/java/reva/plugin/RevaApplicationPlugin.java) manages the MCP server for the entire Ghidra session.
2. **Tool Lifecycle** - The [`RevaPlugin`](src/main/java/reva/plugin/RevaPlugin.java) manages tool-specific functionality and UI.
3. **Program Lifecycle** - Both plugins coordinate to handle program open/close events, with the application plugin maintaining the program registry.
4. **Server Lifecycle** - The MCP server starts with Ghidra and stops when Ghidra shuts down, surviving individual tool closures.

## Development Environment

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Java | 21+ | Required by Ghidra 12.0+ |
| Gradle | 8.x+ | Use `gradle` directly, NOT `./gradlew` |
| Ghidra | 12.0+ | Set `GHIDRA_INSTALL_DIR` environment variable |
| Python | 3.10+ | For CLI and headless mode |
| uv | Latest | Python package manager |

### Version Information

| Component | Version |
|-----------|---------|
| MCP SDK | v0.17.0 |
| Jackson | 2.20.x |
| Jetty | 11.0.26 |
| PyGhidra | 3.0.0+ |
| JUnit | 4 (NOT 5) |

### Build Commands

```bash
# Set Ghidra installation directory
export GHIDRA_INSTALL_DIR=/path/to/ghidra

# Build the extension
gradle

# Install directly to Ghidra
gradle install

# Clean lib directory if Jackson conflicts occur
rm lib/*.jar && gradle
```

### Python Setup

```bash
# Setup Python environment
uv sync

# Install CLI for development
uv pip install -e .

# Run CLI locally
uv run mcp-reva --verbose
```

## Adding New Resources

Resources provide read-only access to Ghidra data. To add a new resource:

1. Create a new class in the `reva.resources.impl` package that extends [`AbstractResourceProvider`](src/main/java/reva/resources/AbstractResourceProvider.java).
2. Implement the `register()` method to register your resource with the MCP server.
3. Add your resource provider to the `initializeResourceProviders()` method in [`McpServerManager`](src/main/java/reva/server/McpServerManager.java).

### Example Resource Implementation

For a concrete example, see the [`ProgramListResource`](src/main/java/reva/resources/impl/ProgramListResource.java) implementation.

```java
public class MyNewResource extends AbstractResourceProvider {
    private static final String RESOURCE_ID = "ghidra://my-resource";
    private static final String RESOURCE_NAME = "my-resource";
    private static final String RESOURCE_DESCRIPTION = "Description of my resource";
    private static final String RESOURCE_MIME_TYPE = "text/plain";

    public MyNewResource(McpSyncServer server) {
        super(server);
    }

    @Override
    public void register() {
        Resource resource = new Resource(
            RESOURCE_ID,
            RESOURCE_NAME,
            RESOURCE_DESCRIPTION,
            RESOURCE_MIME_TYPE,
            null  // No schema needed for simple resources
        );

        SyncResourceSpecification resourceSpec = new SyncResourceSpecification(
            resource,
            (exchange, request) -> {
                List<ResourceContents> resourceContents = new ArrayList<>();

                // Implement logic to gather data and create resource contents

                return new ReadResourceResult(resourceContents);
            }
        );

        server.addResource(resourceSpec);
        logInfo("Registered resource: " + RESOURCE_NAME);
    }

    @Override
    public void programOpened(Program program) {
        // Handle program opened event if needed
    }

    @Override
    public void programClosed(Program program) {
        // Handle program closed event if needed
    }
}
```

## Adding New Tools

Tools provide interactive operations that can be invoked by clients. To add a new tool:

1. Create a new class in the appropriate package under `reva.tools` that extends [`AbstractToolProvider`](src/main/java/reva/tools/AbstractToolProvider.java).
2. Implement the `registerTools()` method to register your tools with the MCP server.
3. Add your tool provider to the `initializeToolProviders()` method in [`McpServerManager`](src/main/java/reva/server/McpServerManager.java).

### Example Tool Implementation

For concrete examples, see the [`SymbolToolProvider`](src/main/java/reva/tools/symbols/SymbolToolProvider.java), [`StringToolProvider`](src/main/java/reva/tools/strings/StringToolProvider.java), [`BookmarkToolProvider`](src/main/java/reva/tools/bookmarks/BookmarkToolProvider.java), [`CommentToolProvider`](src/main/java/reva/tools/comments/CommentToolProvider.java), or other implementations in the `reva.tools` package.

```java
public class MyNewToolProvider extends AbstractToolProvider {
    public MyNewToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() throws McpError {
        registerMyTool();
        // Register additional tools as needed
    }

    private void registerMyTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path to the program"
        ));
        properties.put("parameter1", Map.of(
            "type", "string",
            "description", "Description of parameter 1"
        ));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "my-tool-name",
            "Description of what my tool does",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get the program - use helper method for consistent error handling
            Program program = getProgramFromArgs(args);

            // Get optional parameters with defaults
            boolean verbose = getOptionalBoolean(args, "verbose", false);
            int maxResults = getOptionalInt(args, "maxResults", 100);

            // Implement tool logic
            Address someAddress = program.getMinAddress();
            // ...

            // Return results - always use AddressUtil for address formatting
            Map<String, Object> resultData = new HashMap<>();
            resultData.put("success", true);
            resultData.put("programPath", program.getDomainFile().getPathname());
            resultData.put("address", AddressUtil.formatAddress(someAddress));

            return createJsonResult(resultData);
        });
    }
}
```

## Best Practices

### Resource and Tool Design

1. **Tool and Resource Design**
   - Try to make tools and resources mirror what a human can do in Ghidra.
   - Use clear and descriptive names for tools and resources.
   - Hint to the LLM about context the human would have, for example, return relevant listing view content when decompiling. A human would look at both. Return cross references when getting data, the human sees them together in the UI.
   - Use utility methods to reduce tool usage, like allowing both symbols and addresses as input in the same parameter. Try to make input standard to reduce tool calls.
     - If the LLM fails to use a tool correctly, try to adapt to the common mistake it makes.

2. **Error Handling**:
   - Always validate input parameters.
   - Return clear error messages when operations fail.
   - Use the `createErrorResult` method to create standardized error responses.
    - Include a hint for what to do next.

3. **Program Lifecycle**:
   - Be aware of the program lifecycle and handle program opened/closed events appropriately.
   - Avoid storing program-specific data in static fields unless explicitly designed to survive across program changes.
   - See how [`McpServerManager`](src/main/java/reva/server/McpServerManager.java) handles program lifecycle events.

4. **Resource Management**:
   - Clean up resources properly in the `cleanup()` method.
   - Unregister any listeners or observers when components are no longer needed.

### MCP Server Integration

1. **Schema Design**:
   - Design clear and consistent schemas for your tools.
   - Document parameters thoroughly in the schema description.
   - Make parameters optional when appropriate.
   - See the schema design in the tool providers like [`SymbolToolProvider`](src/main/java/reva/tools/symbols/SymbolToolProvider.java).

2. **Performance Considerations**:
   - Use pagination for large data sets.
   - Consider implementing tools to get counts before retrieving full data sets.
   - Use Ghidra's thread pool for long-running operations.
   - See how [`SymbolToolProvider`](src/main/java/reva/tools/symbols/SymbolToolProvider.java) implements pagination.

3. **Server Configuration**:
   - Use the `ConfigManager` to access and modify server configuration.
   - Allow users to enable/disable features via configuration.

## Testing

### Test Categories

| Category | Command | Location | Requirements |
|----------|---------|----------|--------------|
| Java Unit Tests | `gradle test` | `src/test/` | No Ghidra environment |
| Java Integration Tests | `gradle integrationTest` | `src/test.slow/` | GUI environment, fork=1 |
| Python Unit Tests | `uv run pytest -m unit` | `tests/` | Mocked PyGhidra |
| Python Integration Tests | `uv run pytest -m integration` | `tests/` | PyGhidra available |
| Python E2E Tests | `uv run pytest -m e2e` | `tests/` | Full CLI subprocess |

### Running Tests

```bash
# Java unit tests (fast, no Ghidra)
gradle test --info

# Java integration tests (require GUI)
gradle integrationTest --info

# Run specific Java test class
gradle integrationTest --tests "*DecompilerToolProviderIntegrationTest" --info

# Python tests
uv run pytest                    # All tests
uv run pytest -m unit            # Fast unit tests with mocks
uv run pytest -m integration     # Tests requiring PyGhidra
uv run pytest tests/test_cli.py  # Specific test file

# Complete test suite
gradle test && gradle integrationTest && uv run pytest
```

### Integration Test Guidelines

Integration tests must validate **actual Ghidra program state changes**, not just MCP responses:

```java
@Test
public void testRenameFunction() throws Exception {
    // Call the MCP tool
    CallToolResult result = client.callTool(
        new CallToolRequest("rename-function", Map.of(
            "programPath", programPath,
            "address", "0x01000000",
            "newName", "myFunction"
        ))
    );

    // Verify MCP response
    assertMcpResultNotError(result, "Tool should not error");

    // **CRITICAL**: Verify actual program state changed
    Function func = program.getFunctionManager().getFunctionAt(testAddr);
    assertEquals("myFunction", func.getName());
}
```

See [`src/test.slow/CLAUDE.md`](src/test.slow/CLAUDE.md) for the full integration test base class and patterns.

### Manual Testing

For quick manual testing of your tools:

1. Install the extension in Ghidra.
2. Connect to the MCP server using an MCP client (Claude Desktop, VSCode, etc.).
3. Use the tool list endpoint to discover available tools.
4. Test with different input parameters and edge cases.

## Debugging

1. Use `Msg.info()` and `Msg.error()` for logging.
2. Check the Ghidra console for log messages.
3. For MCP server issues, check the server logs.

## Additional Resources

- [Model Context Protocol Documentation](https://modelcontextprotocol.io/)
- [Ghidra API Documentation](https://ghidra.re/ghidra_docs/api/)
- [Ghidra on GitHub](https://github.com/NationalSecurityAgency/ghidra)
- [MCP Java SDK](https://modelcontextprotocol.io/sdk/java/mcp-server)
