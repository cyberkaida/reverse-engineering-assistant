# CLAUDE.md - Resources Package

This file provides guidance for Claude Code when working with the MCP resource provider system in the `reva.resources` package.

## Quick Reference

| Item | Value |
|------|-------|
| **Resource URI Prefix** | `ghidra://` |
| **MCP SDK Version** | v0.17.0 |
| **Jackson Version** | 2.20.x |
| **Current Providers** | 1 (ProgramListResource) |
| **Base Class** | `AbstractResourceProvider` |
| **Registration Location** | `McpServerManager.initializeResourceProviders()` |

## Package Overview

The `reva.resources` package implements the Model Context Protocol (MCP) resource provider system, exposing read-only Ghidra data through MCP resources. Unlike tool providers that execute actions, resource providers make data available for client consumption.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        MCP Client                                │
│            (requests resource via URI)                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                    Resource Request (ghidra://...)
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    McpSyncServer                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              SyncResourceSpecification                      ││
│  │          (resource definition + handler)                    ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                 AbstractResourceProvider                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ ProgramListResource │  │   (Future)    │  │   (Future)    │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Ghidra Programs                               │
│              (via RevaProgramManager)                            │
└─────────────────────────────────────────────────────────────────┘
```

## Core Classes

### ResourceProvider Interface

| Method | Purpose |
|--------|---------|
| `register()` | Register resources with MCP server |
| `programOpened(Program)` | Handle program open lifecycle event |
| `programClosed(Program)` | Handle program close lifecycle event |
| `cleanup()` | Clean up resources on shutdown |

### AbstractResourceProvider Base Class

Provides common functionality for all resource providers:

| Feature | Description |
|---------|-------------|
| `server` field | Protected `McpSyncServer` reference |
| `logError(String)` | Log error via Ghidra's `Msg` utility |
| `logError(String, Exception)` | Log error with exception |
| `logInfo(String)` | Log informational message |
| Default lifecycle methods | No-op implementations for program events |

## Resource Content Types

| Type | Class | Use Case |
|------|-------|----------|
| Text/JSON | `TextResourceContents` | Program metadata, structured data |
| Binary | `BlobResourceContents` | Raw binary data (rarely used) |

## Resource Provider Implementation

### Basic Structure

```java
public class MyResourceProvider extends AbstractResourceProvider {
    private static final String RESOURCE_ID = "ghidra://my-resource";
    private static final String RESOURCE_NAME = "my-resource";
    private static final String RESOURCE_DESCRIPTION = "Description of resource";
    private static final String RESOURCE_MIME_TYPE = "application/json";

    private static final ObjectMapper JSON = new ObjectMapper();

    public MyResourceProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void register() {
        Resource resource = new Resource(
            RESOURCE_ID,
            RESOURCE_NAME,
            RESOURCE_DESCRIPTION,
            RESOURCE_MIME_TYPE,
            null  // Optional JSON schema
        );

        SyncResourceSpecification resourceSpec = new SyncResourceSpecification(
            resource,
            this::handleResourceRequest
        );

        server.addResource(resourceSpec);
        logInfo("Registered resource: " + RESOURCE_NAME);
    }

    private ReadResourceResult handleResourceRequest(
            ServerExchange exchange, ReadResourceRequest request) {
        List<ResourceContents> contents = new ArrayList<>();
        // ... generate content
        return new ReadResourceResult(contents);
    }
}
```

### Registration in McpServerManager

```java
private void initializeResourceProviders() {
    resourceProviders.add(new ProgramListResource(server));
    // Add new providers here

    for (ResourceProvider provider : resourceProviders) {
        provider.register();
    }
}
```

## URI Addressing

### URI Structure

| Pattern | Example | Description |
|---------|---------|-------------|
| Base resource | `ghidra://programs` | Main resource listing |
| Sub-resource | `ghidra://programs/My%20Program.exe` | Specific item (URL encoded) |
| Hierarchical | `ghidra://functions/0x00401000` | Resource at address |

### Best Practices

1. **Consistent URI scheme**: Always use `ghidra://` prefix
2. **URL encoding**: Encode dynamic path components with `URLEncoder.encode(path, StandardCharsets.UTF_8)`
3. **Hierarchical organization**: Use `/` for logical hierarchies
4. **Meaningful names**: Use descriptive resource names

## Program State Integration

### Accessing Program Data

```java
// Get open programs
List<Program> programs = RevaProgramManager.getOpenPrograms();

// Access program properties
String path = program.getDomainFile().getPathname();
String language = program.getLanguage().getLanguageID().getIdAsString();
String compilerSpec = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
long size = program.getMemory().getSize();
```

### Thread Safety

- Program data may be modified while resources are accessed
- Use appropriate synchronization for mutable state
- Consider defensive copying for complex structures

## Error Handling

### Exception Handling Pattern

```java
private ReadResourceResult handleResourceRequest(
        ServerExchange exchange, ReadResourceRequest request) {
    List<ResourceContents> contents = new ArrayList<>();

    try {
        generateResourceContent(contents);
    } catch (JsonProcessingException e) {
        logError("JSON serialization failed", e);
        // Return partial results or empty list
    } catch (Exception e) {
        logError("Unexpected error generating resource content", e);
    }

    return new ReadResourceResult(contents);
}
```

### Error Strategy

| Scenario | Approach |
|----------|----------|
| Serialization error | Log error, return partial results |
| Program access error | Skip problematic program, continue |
| Complete failure | Return empty list, log error |

## Resource vs Tool Providers

| Aspect | Resource Providers | Tool Providers |
|--------|-------------------|----------------|
| **Purpose** | Expose read-only data | Execute actions/modifications |
| **MCP Operation** | Handle resource requests | Handle tool calls |
| **State Changes** | No program modification | May modify program state |
| **Return Type** | `ReadResourceResult` | Tool-specific result objects |
| **URI Scheme** | Hierarchical resource URIs | Tool names |
| **When to Use** | Program metadata, lists, read-only views | Analysis, modifications, computations |

## Existing Implementation: ProgramListResource

Located at `impl/ProgramListResource.java`:

| Property | Value |
|----------|-------|
| **Resource URI** | `ghidra://programs` |
| **Resource Name** | `open-programs` |
| **MIME Type** | `text/plain` |
| **Returns** | JSON array of program metadata |

**Output Fields:**
- `programPath` - Ghidra project pathname
- `language` - Architecture/processor ID
- `compilerSpec` - Compiler specification ID
- `sizeBytes` - Memory size in bytes

## Development Checklist

When implementing a new resource provider:

- [ ] Extend `AbstractResourceProvider`
- [ ] Define resource constants (ID, name, description, MIME type)
- [ ] Implement `register()` with `SyncResourceSpecification`
- [ ] Use URL encoding for dynamic URI components
- [ ] Add JSON serialization with error handling
- [ ] Include logging (info for registration, error for failures)
- [ ] Register in `McpServerManager.initializeResourceProviders()`
- [ ] Consider program lifecycle requirements
- [ ] Write unit tests for content generation

## Troubleshooting

### Resource Not Accessible

| Symptom | Cause | Solution |
|---------|-------|----------|
| Resource not found | Not registered | Check `initializeResourceProviders()` |
| Empty response | No open programs | Open a program in Ghidra |
| Malformed URI | Missing URL encoding | Use `URLEncoder.encode()` |

### Content Generation Errors

| Symptom | Cause | Solution |
|---------|-------|----------|
| JSON serialization fails | Invalid object structure | Check Jackson annotations |
| Null pointer exception | Program closed during access | Add null checks |
| Partial results | Some programs failed | Check logs for specific errors |

### Testing Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| Mock server NPE | Server not initialized | Use `mock(McpSyncServer.class)` |
| Registration verification fails | Wrong matcher | Use `any(SyncResourceSpecification.class)` |

## Related Documentation

- `/src/main/java/reva/server/CLAUDE.md` - Server architecture, provider registration
- `/src/main/java/reva/tools/CLAUDE.md` - Tool provider patterns (for comparison)
- `/src/main/java/reva/plugin/CLAUDE.md` - RevaProgramManager, program lifecycle
- `/src/main/java/reva/util/CLAUDE.md` - Utility classes for data access
