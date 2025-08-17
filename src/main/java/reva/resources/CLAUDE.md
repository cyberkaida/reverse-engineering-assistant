# Resources Package Guide

This document provides comprehensive guidance for working with the MCP resource provider system in ReVa's resources package.

## Package Overview

The `reva.resources` package implements the Model Context Protocol (MCP) resource provider system, which exposes read-only Ghidra data through MCP resources. Unlike tool providers that execute actions, resource providers make data available for client consumption.

### Key Concepts
- **Resources**: Read-only data accessible via URI
- **Resource Providers**: Components that register and manage resources
- **Resource Contents**: The actual data returned when a resource is accessed
- **URI Addressing**: Hierarchical naming scheme for resources

## Architecture Components

### ResourceProvider Interface
The core interface defining the resource provider contract:

```java
public interface ResourceProvider {
    void register();                    // Register resources with MCP server
    void programOpened(Program program); // Handle program lifecycle events
    void programClosed(Program program);
    void cleanup();                     // Clean up resources
}
```

### AbstractResourceProvider Base Class
Provides common functionality for all resource providers:

```java
public abstract class AbstractResourceProvider implements ResourceProvider {
    protected final McpSyncServer server;
    
    // Logging utilities
    protected void logError(String message);
    protected void logError(String message, Exception e);
    protected void logInfo(String message);
}
```

**Key Features:**
- MCP server reference for resource registration
- Consistent logging through Ghidra's `Msg` utility
- Default no-op implementations for lifecycle methods
- Error handling support

## Resource Provider Implementation Pattern

### 1. Basic Resource Provider Structure
```java
public class MyResourceProvider extends AbstractResourceProvider {
    private static final String RESOURCE_ID = "ghidra://my-resource";
    private static final String RESOURCE_NAME = "my-resource";
    private static final String RESOURCE_DESCRIPTION = "Description of resource";
    private static final String RESOURCE_MIME_TYPE = "text/plain";
    
    public MyResourceProvider(McpSyncServer server) {
        super(server);
    }
    
    @Override
    public void register() {
        // Create resource definition
        Resource resource = new Resource(
            RESOURCE_ID,
            RESOURCE_NAME, 
            RESOURCE_DESCRIPTION,
            RESOURCE_MIME_TYPE,
            null  // Optional JSON schema
        );
        
        // Create resource specification with content handler
        SyncResourceSpecification resourceSpec = new SyncResourceSpecification(
            resource,
            this::handleResourceRequest
        );
        
        server.addResource(resourceSpec);
        logInfo("Registered resource: " + RESOURCE_NAME);
    }
    
    private ReadResourceResult handleResourceRequest(ServerExchange exchange, ReadResourceRequest request) {
        // Generate resource content
        List<ResourceContents> contents = new ArrayList<>();
        // ... add content generation logic
        return new ReadResourceResult(contents);
    }
}
```

### 2. Resource Registration Lifecycle
Resource providers are automatically registered in `McpServerManager.initializeResourceProviders()`:

```java
private void initializeResourceProviders() {
    resourceProviders.add(new ProgramListResource(server));
    // Add new providers here
    
    // Register all resources with the server
    for (ResourceProvider provider : resourceProviders) {
        provider.register();
    }
}
```

### 3. Program Lifecycle Integration
Resource providers receive notifications when programs are opened/closed:

```java
@Override
public void programOpened(Program program) {
    // Optional: Update resource state when programs are opened
    // Default implementation does nothing
}

@Override
public void programClosed(Program program) {
    // Optional: Clean up program-specific resource state
    // Default implementation does nothing
}
```

## Resource Content Generation

### Content Types
Resources can return different types of content:

1. **TextResourceContents**: Plain text or JSON data
2. **BlobResourceContents**: Binary data (not commonly used)

### Example: Dynamic Content Generation
```java
private ReadResourceResult handleResourceRequest(ServerExchange exchange, ReadResourceRequest request) {
    List<ResourceContents> resourceContents = new ArrayList<>();
    
    // Get current Ghidra state
    List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
    
    for (Program program : openPrograms) {
        try {
            // Extract program metadata
            String programPath = program.getDomainFile().getPathname();
            String language = program.getLanguage().getLanguageID().getIdAsString();
            
            // Create structured data
            ProgramMetadata metadata = new ProgramMetadata(programPath, language);
            String jsonContent = JSON.writeValueAsString(metadata);
            
            // Create resource content with unique URI
            String encodedPath = URLEncoder.encode(programPath, StandardCharsets.UTF_8);
            resourceContents.add(
                new TextResourceContents(
                    RESOURCE_ID + "/" + encodedPath,
                    "application/json",
                    jsonContent
                )
            );
        } catch (JsonProcessingException e) {
            logError("Error serializing program metadata", e);
        }
    }
    
    return new ReadResourceResult(resourceContents);
}
```

## URI Handling and Resource Addressing

### URI Structure
Resources use hierarchical URI schemes:
- Base URI: `ghidra://resource-name`
- Sub-resources: `ghidra://resource-name/sub-item`
- Encoded paths: URL encoding for special characters

### Best Practices
1. **Consistent URI schemes**: Use `ghidra://` prefix for all resources
2. **URL encoding**: Always encode dynamic path components
3. **Hierarchical organization**: Use `/` to create logical hierarchies
4. **Meaningful names**: Use descriptive resource and sub-resource names

```java
// Good URI examples
"ghidra://programs"                           // Main programs resource
"ghidra://programs/My%20Program.exe"          // Specific program (URL encoded)
"ghidra://functions/0x00401000"              // Function at specific address
"ghidra://strings/ascii"                     // ASCII strings subset
```

## Program State Integration

### Accessing Program Data
Resource providers can access current Ghidra state through various APIs:

```java
// Get open programs
List<Program> programs = RevaProgramManager.getOpenPrograms();

// Access program properties
String path = program.getDomainFile().getPathname();
String language = program.getLanguage().getLanguageID().getIdAsString();
String compilerSpec = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
long size = program.getMemory().getSize();

// Access program content (functions, data, etc.)
FunctionManager functionManager = program.getFunctionManager();
DataManager dataManager = program.getDataTypeManager();
```

### Thread Safety
Resource providers must handle concurrent access safely:
- Program data may be modified while resources are being accessed
- Use appropriate synchronization when accessing mutable program state
- Consider defensive copying for complex data structures

## Error Handling for Resource Operations

### Exception Handling Patterns
```java
private ReadResourceResult handleResourceRequest(ServerExchange exchange, ReadResourceRequest request) {
    List<ResourceContents> contents = new ArrayList<>();
    
    try {
        // Resource generation logic
        generateResourceContent(contents);
    } catch (JsonProcessingException e) {
        logError("JSON serialization failed", e);
        // Return partial results or empty list
    } catch (Exception e) {
        logError("Unexpected error generating resource content", e);
        // Consider returning error content or empty list
    }
    
    return new ReadResourceResult(contents);
}
```

### Error Content Strategy
When errors occur, consider:
1. **Partial results**: Return successfully generated content
2. **Error metadata**: Include error information in resource content
3. **Empty results**: Return empty list for complete failures
4. **Logging**: Always log errors for debugging

```java
// Example: Including error information in resource content
catch (Exception e) {
    logError("Error processing program: " + programPath, e);
    
    // Add error information as resource content
    ErrorInfo errorInfo = new ErrorInfo("processing_error", e.getMessage());
    String errorJson = JSON.writeValueAsString(errorInfo);
    
    contents.add(new TextResourceContents(
        RESOURCE_ID + "/error/" + encodedPath,
        "application/json",
        errorJson
    ));
}
```

## Testing Considerations for Resources

### Unit Testing Strategy
Resource providers should be tested for:

1. **Resource registration**: Verify resources are registered correctly
2. **Content generation**: Test resource content creation logic
3. **Error handling**: Verify graceful error handling
4. **URI generation**: Test URI encoding and structure
5. **Program lifecycle**: Test behavior with program open/close events

### Test Structure Example
```java
public class MyResourceProviderTest {
    private McpSyncServer mockServer;
    private MyResourceProvider provider;
    
    @Before
    public void setUp() {
        mockServer = mock(McpSyncServer.class);
        provider = new MyResourceProvider(mockServer);
    }
    
    @Test
    public void testResourceRegistration() {
        provider.register();
        
        // Verify server.addResource() was called
        verify(mockServer).addResource(any(SyncResourceSpecification.class));
    }
    
    @Test
    public void testContentGeneration() {
        // Test resource content generation logic
        // Verify JSON serialization
        // Check URI encoding
    }
}
```

### Integration Testing
- Test with actual Ghidra programs
- Verify resource accessibility through MCP client
- Test concurrent access scenarios
- Validate resource content structure

## Comparison with Tool Providers

### Key Differences

| Aspect | Resource Providers | Tool Providers |
|--------|-------------------|----------------|
| **Purpose** | Expose read-only data | Execute actions/modifications |
| **MCP Operation** | Handle resource requests | Handle tool calls |
| **State Changes** | No program modification | May modify program state |
| **Return Type** | `ReadResourceResult` | Tool-specific result objects |
| **URI Scheme** | Hierarchical resource URIs | Tool names |
| **Lifecycle** | Passive data exposure | Active operation execution |

### Similarities
- Both extend abstract base classes (`AbstractResourceProvider`/`AbstractToolProvider`)
- Both registered automatically in `McpServerManager`
- Both receive program lifecycle notifications
- Both use consistent logging patterns
- Both handle JSON serialization

### When to Use Each
- **Resource Providers**: For exposing program metadata, lists, or read-only views
- **Tool Providers**: For performing analysis, modifications, or computations

## Example: ProgramListResource Analysis

The included `ProgramListResource` demonstrates best practices:

```java
public class ProgramListResource extends AbstractResourceProvider {
    // Constants for resource identity
    private static final String RESOURCE_ID = "ghidra://programs";
    private static final String RESOURCE_NAME = "open-programs";
    
    // JSON handling
    private static final ObjectMapper JSON = new ObjectMapper();
    
    @Override
    public void register() {
        // Create resource definition
        Resource resource = new Resource(RESOURCE_ID, RESOURCE_NAME, ...);
        
        // Lambda-based content handler
        SyncResourceSpecification resourceSpec = new SyncResourceSpecification(
            resource,
            (exchange, request) -> {
                // Generate content for each open program
                List<ResourceContents> resourceContents = new ArrayList<>();
                List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
                
                for (Program program : openPrograms) {
                    // Create program metadata and add to contents
                }
                
                return new ReadResourceResult(resourceContents);
            }
        );
        
        server.addResource(resourceSpec);
    }
}
```

**Key Features Demonstrated:**
- Static resource constants
- Lambda-based content generation
- Proper JSON serialization with error handling
- URL encoding for URI safety
- Structured data objects for JSON
- Comprehensive error logging

## Development Checklist

When implementing a new resource provider:

- [ ] Extend `AbstractResourceProvider`
- [ ] Define resource constants (ID, name, description, MIME type)
- [ ] Implement `register()` method with proper resource specification
- [ ] Create content generation logic with error handling
- [ ] Use URL encoding for dynamic URI components
- [ ] Add JSON serialization with proper exception handling
- [ ] Include comprehensive logging
- [ ] Register provider in `McpServerManager.initializeResourceProviders()`
- [ ] Consider program lifecycle requirements
- [ ] Write unit tests for content generation
- [ ] Write integration tests if needed
- [ ] Document resource URI scheme and content format