# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the project tools package in ReVa.

## Package Overview

The `reva.tools.project` package provides MCP tools for Ghidra project management operations. It handles program discovery, project file listing, and version control operations through Ghidra's project framework and version control system.

## Key Tools

- `get-current-program` - Get the currently active program with metadata
- `list-project-files` - List files and folders in the Ghidra project with optional recursion
- `list-open-programs` - List all programs currently open in Ghidra across all tools
- `checkin-program` - Check in (commit) a program to version control with commit message

## Critical Implementation Patterns

### Project Access Pattern

**Always use AppInfo.getActiveProject() for project access**:
```java
Project project = AppInfo.getActiveProject();
if (project == null) {
    return createErrorResult("No active project found");
}

// Access project data
DomainFolder rootFolder = project.getProjectData().getRootFolder();
DomainFolder folder = project.getProjectData().getFolder(folderPath);
```

### Program Discovery Through RevaProgramManager

**Use RevaProgramManager for consistent program access across tools**:
```java
// Get all open programs across all Ghidra tools
List<Program> openPrograms = RevaProgramManager.getOpenPrograms();

if (openPrograms.isEmpty()) {
    return createErrorResult("No programs are currently open in Ghidra");
}

// RevaProgramManager handles:
// - Multiple tool instances
// - Test environments without GUI
// - Cached program access
// - Direct program registration for testing
```

### DomainFile and DomainFolder Handling

**Use proper path handling for project navigation**:
```java
// Root folder access
if (folderPath.equals("/")) {
    folder = project.getProjectData().getRootFolder();
} else {
    folder = project.getProjectData().getFolder(folderPath);
}

if (folder == null) {
    return createErrorResult("Folder not found: " + folderPath);
}

// File enumeration
DomainFile[] files = folder.getFiles();
DomainFolder[] subfolders = folder.getFolders();
```

### Program Metadata Collection

**Standard pattern for program information gathering**:
```java
Map<String, Object> programInfo = new HashMap<>();
programInfo.put("programPath", program.getDomainFile().getPathname());
programInfo.put("language", program.getLanguage().getLanguageID().getIdAsString());
programInfo.put("compilerSpec", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
programInfo.put("creationDate", program.getCreationDate());
programInfo.put("sizeBytes", program.getMemory().getSize());
programInfo.put("symbolCount", program.getSymbolTable().getNumSymbols());
programInfo.put("functionCount", program.getFunctionManager().getFunctionCount());
programInfo.put("modificationDate", program.getDomainFile().getLastModifiedTime());
programInfo.put("isReadOnly", program.getDomainFile().isReadOnly());
```

### File Metadata Collection for Project Files

**Include comprehensive file information for project browsing**:
```java
Map<String, Object> fileInfo = new HashMap<>();
fileInfo.put("programPath", file.getPathname());
fileInfo.put("type", "file");
fileInfo.put("contentType", file.getContentType());
fileInfo.put("lastModified", file.getLastModifiedTime());
fileInfo.put("readOnly", file.isReadOnly());
fileInfo.put("versioned", file.isVersioned());
fileInfo.put("checkedOut", file.isCheckedOut());

// Add program-specific metadata when available
if (file.getContentType().equals("Program")) {
    try {
        if (file.getMetadata() != null) {
            Object languageObj = file.getMetadata().get("CREATED_WITH_LANGUAGE");
            if (languageObj != null) {
                fileInfo.put("programLanguage", languageObj);
            }
            Object md5Obj = file.getMetadata().get("Executable MD5");
            if (md5Obj != null) {
                fileInfo.put("executableMD5", md5Obj);
            }
        }
    } catch (Exception e) {
        // Ignore metadata errors - not critical for file listing
    }
}
```

## Version Control Operations

### Checkin Pattern with Dual Mode Support

**Handle both new files and existing versioned files**:
```java
DomainFile domainFile = program.getDomainFile();

if (domainFile.canAddToRepository()) {
    // New file - add to version control
    domainFile.addToVersionControl(message, !keepCheckedOut, TaskMonitor.DUMMY);
    
    Map<String, Object> result = new HashMap<>();
    result.put("success", true);
    result.put("action", "added_to_version_control");
    result.put("programPath", programPath);
    result.put("message", message);
    result.put("keepCheckedOut", keepCheckedOut);
    result.put("isVersioned", domainFile.isVersioned());
    result.put("isCheckedOut", domainFile.isCheckedOut());
    
    return createJsonResult(result);
}
else if (domainFile.canCheckin()) {
    // Existing versioned file - check in changes
    DefaultCheckinHandler checkinHandler = new DefaultCheckinHandler(
        message + "\n💜🐉✨ (ReVa)", keepCheckedOut, false);
    domainFile.checkin(checkinHandler, TaskMonitor.DUMMY);
    
    // Return similar result structure
}
```

### Version Control Status Validation

**Provide specific error messages for different version control states**:
```java
if (!domainFile.isVersioned()) {
    return createErrorResult("Program is not under version control: " + programPath);
}
else if (!domainFile.isCheckedOut()) {
    return createErrorResult("Program is not checked out and cannot be modified: " + programPath);
}
else if (!domainFile.modifiedSinceCheckout()) {
    return createErrorResult("Program has no changes since checkout: " + programPath);
}
else {
    return createErrorResult("Program cannot be checked in for an unknown reason: " + programPath);
}
```

### Version Control Exception Handling

**Handle all version control exceptions with specific error messages**:
```java
try {
    // Version control operation
} catch (IOException e) {
    return createErrorResult("IO error during checkin: " + e.getMessage());
} catch (VersionException e) {
    return createErrorResult("Version control error: " + e.getMessage());
} catch (CancelledException e) {
    return createErrorResult("Checkin operation was cancelled");
} catch (Exception e) {
    return createErrorResult("Unexpected error during checkin: " + e.getMessage());
}
```

## Recursive File Collection Pattern

### Non-Recursive Collection

**Standard pattern for single-folder file listing**:
```java
private void collectFilesInFolder(DomainFolder folder, List<Map<String, Object>> filesList, String pathPrefix) {
    // Add subfolders first
    for (DomainFolder subfolder : folder.getFolders()) {
        Map<String, Object> folderInfo = new HashMap<>();
        folderInfo.put("folderPath", pathPrefix + subfolder.getName());
        folderInfo.put("type", "folder");
        folderInfo.put("childCount", subfolder.getFiles().length + subfolder.getFolders().length);
        filesList.add(folderInfo);
    }

    // Add files
    for (DomainFile file : folder.getFiles()) {
        // Build file info map
        filesList.add(fileInfo);
    }
}
```

### Recursive Collection

**Pattern for recursive project tree traversal**:
```java
private void collectFilesRecursive(DomainFolder folder, List<Map<String, Object>> filesList, String pathPrefix) {
    // Collect files in current folder
    collectFilesInFolder(folder, filesList, pathPrefix);

    // Recursively collect files in subfolders
    for (DomainFolder subfolder : folder.getFolders()) {
        String newPrefix = pathPrefix + subfolder.getName() + "/";
        collectFilesRecursive(subfolder, filesList, newPrefix);
    }
}
```

## Response Formats for Project Data

### Multi-Item Response Pattern

**Use metadata + items pattern for list responses**:
```java
// Create metadata about the result
Map<String, Object> metadataInfo = new HashMap<>();
metadataInfo.put("folderPath", folderPath);
metadataInfo.put("folderName", folder.getName());
metadataInfo.put("isRecursive", recursive);
metadataInfo.put("itemCount", filesList.size());

// Create combined result with metadata first
List<Object> resultData = new ArrayList<>();
resultData.add(metadataInfo);
resultData.addAll(filesList);

return createMultiJsonResult(resultData);
```

### Program List Response Pattern

**Consistent program list formatting**:
```java
List<Map<String, Object>> programsData = new ArrayList<>();

for (Program program : openPrograms) {
    Map<String, Object> programInfo = new HashMap<>();
    // Standard program metadata fields
    programsData.add(programInfo);
}

Map<String, Object> metadataInfo = new HashMap<>();
metadataInfo.put("count", programsData.size());

List<Object> resultData = new ArrayList<>();
resultData.add(metadataInfo);
resultData.addAll(programsData);

return createMultiJsonResult(resultData);
```

## Error Handling Patterns

### Project Access Validation

**Always validate project access before operations**:
```java
Project project = AppInfo.getActiveProject();
if (project == null) {
    return createErrorResult("No active project found");
}
```

### Program Path Validation

**Use standard program validation from AbstractToolProvider**:
```java
// Get the validated program using the standard helper
Program program = getProgramFromArgs(request);
```

### Folder Path Validation

**Validate folder paths with helpful error messages**:
```java
DomainFolder folder;
if (folderPath.equals("/")) {
    folder = project.getProjectData().getRootFolder();
} else {
    folder = project.getProjectData().getFolder(folderPath);
}

if (folder == null) {
    return createErrorResult("Folder not found: " + folderPath);
}
```

## Ghidra Project API Usage Patterns

### Project Data Access

**Standard project data navigation**:
```java
Project project = AppInfo.getActiveProject();
DomainFolder rootFolder = project.getProjectData().getRootFolder();
DomainFolder targetFolder = project.getProjectData().getFolder(path);
```

### DomainFile Operations

**Key DomainFile methods for project tools**:
```java
// Basic file information
String pathname = file.getPathname();
String contentType = file.getContentType();
long lastModified = file.getLastModifiedTime();
boolean isReadOnly = file.isReadOnly();

// Version control status
boolean isVersioned = file.isVersioned();
boolean isCheckedOut = file.isCheckedOut();
boolean hasChanges = file.modifiedSinceCheckout();
boolean canAddToVCS = file.canAddToRepository();
boolean canCheckin = file.canCheckin();

// Metadata access (with error handling)
Map<String, Object> metadata = file.getMetadata();
```

### ToolManager Integration

**Access programs across multiple tools**:
```java
Project project = AppInfo.getActiveProject();
ToolManager toolManager = project.getToolManager();
PluginTool[] runningTools = toolManager.getRunningTools();

for (PluginTool tool : runningTools) {
    ProgramManager programManager = tool.getService(ProgramManager.class);
    if (programManager != null) {
        Program[] programs = programManager.getAllOpenPrograms();
        // Process programs
    }
}
```

## Testing Considerations

### Integration Test Focus Areas

- **Project file enumeration** - Test both recursive and non-recursive listing
- **Version control operations** - Test both new file addition and existing file checkin
- **Multiple program handling** - Test with multiple open programs across tools
- **Error conditions** - Test with missing projects, invalid paths, version control errors

### Test Environment Considerations

- **RevaProgramManager fallback** - Tests may use direct program registration
- **Project setup** - Tests need active project with sample files
- **Version control setup** - Tests need repository-backed project for checkin tests
- **Multiple tools** - Integration tests should verify cross-tool program discovery

### Mock Data Requirements

- **Project with multiple folders** - For file listing tests
- **Versioned and non-versioned files** - For version control operation tests
- **Programs with different metadata** - For program information tests
- **Empty and populated folders** - For edge case testing

## Important Notes

- **Project dependency**: All operations require an active Ghidra project
- **RevaProgramManager integration**: Use RevaProgramManager.getOpenPrograms() for program discovery
- **Version control support**: Handle both new files and existing versioned files
- **Metadata handling**: Include comprehensive file metadata for project browsing
- **Error specificity**: Provide specific error messages for different failure modes
- **Path consistency**: Use DomainFile.getPathname() for consistent path representation
- **Transaction safety**: Version control operations handle their own transactions
- **TaskMonitor usage**: Use TaskMonitor.DUMMY for simple operations