# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the project tools package in ReVa.

## Package Overview

The `reva.tools.project` package provides MCP tools for Ghidra project management operations. It handles program discovery, project file listing, and version control operations through Ghidra's project framework and version control system.

## Key Tools

- `get-current-program` - Get the currently active program with metadata (GUI mode only)
- `list-project-files` - List files and folders in the Ghidra project with optional recursion
- `list-open-programs` - List all programs currently open in Ghidra across all tools (GUI mode only)
- `checkin-program` - Check in (commit) a program to version control with commit message
- `analyze-program` - Run Ghidra auto-analysis as a **background job**, wait inline up to `waitSeconds`, then persist the result (see [Background Analysis Jobs](#background-analysis-jobs))
- `analysis-status` - Long-poll a running analysis job: tail its log, read the live function count, get the full result when terminal
- `analysis-cancel` - Request cancellation of a running analysis job (async; partial work is still persisted)
- `list-analyzers` - List analyzers applicable to a program (names feed `analyze-program`'s `enableAnalyzers` / `disableAnalyzers`)
- `change-processor` - Change the processor architecture (language/compiler spec) of an existing program
- `import-file` - Import a file into the project, optionally analyzing and adding to version control
- `capture-reva-debug-info` - Capture ReVa debug information

## Background Analysis Jobs

`analyze-program`, `analysis-status`, and `analysis-cancel` together implement a poll-driven
background analysis workflow. The synchronous `analyze-program` of old has been rewritten: it now
submits the analysis to a background worker (`reva.services.AnalysisJobManager` → `AnalysisJob` +
`AnalysisJobRunner`, fed an `AnalyzeRequest`), waits inline for a short window, and **persists** the
result when the job finishes. (The old synchronous tool never saved — a latent bug this fixes.)

**All Ghidra work runs off the request thread.** The worker (`AnalysisJobRunner`) opens the analysis
transaction, applies any per-call analyzer overrides, calls `startAnalysis`, marks the program
analyzed, and persists — all on a background thread, mirroring the proven off-Swing path of the
former synchronous tool and `checkin-program`. The MCP handler thread only long-polls the job and
serializes its state into JSON.

### Status lifecycle

Statuses: `running`, `persisting` (non-terminal), and the terminal set `completed`, `failed`,
`cancelled`, `timed_out`. The lifecycle is **not strictly linear** — `failed` is reached directly
from `running` (no analysis manager, or an exception inside the analysis transaction) and never
passes through `persisting`:

```
running ──► persisting ──► completed
   │             ├────────► cancelled    (cancel requested while running)
   │             └────────► timed_out    (timeout fired, no cancel requested)
   └──────────────────────► failed       (setup error / analysis-transaction exception)
```

`AnalysisJob.Status.isTerminal()` is the single source of truth the tools poll on. `persisting`
means analysis succeeded and the program is being saved/checked-in; partial work from a cancelled or
timed-out run is **still persisted** before the job goes terminal.

### The model-facing poll loop

The model starts the job (optionally with `waitSeconds:0` to return immediately), then loops
`analysis-status`, feeding the previous call's `logCursor` back as `sinceLogSeq`, until the status is
terminal — at which point `analysis-status` also returns the full `result`.

```jsonc
// 1. Start the job, don't block the request thread at all.
// → analyze-program { "programPath": "/big.exe", "waitSeconds": 0 }
{
  "success": true,
  "programPath": "/big.exe",
  "jobId": "analysis-3",
  "status": "running",
  "functionCount": 0,
  "log": [ { "seq": 1, "elapsedMs": 12, "message": "Starting full auto-analysis…" } ],
  "logCursor": 1,
  "truncated": false,
  "hint": "Analysis still running. Poll analysis-status with this jobId and sinceLogSeq=logCursor; or call analysis-cancel to stop."
}

// 2. Long-poll. Feed back logCursor as sinceLogSeq to get only new lines.
// → analysis-status { "jobId": "analysis-3", "sinceLogSeq": 1, "waitSeconds": 10 }
{
  "success": true,
  "jobId": "analysis-3",
  "programPath": "/big.exe",
  "status": "running",
  "functionCount": 482,
  "log": [ { "seq": 2, "elapsedMs": 3140, "message": "Analyzing… Function Start Search" } ],
  "logCursor": 2,
  "truncated": false
}

// 3. ...repeat with sinceLogSeq=2, then 3, ... until status is terminal.
// → analysis-status { "jobId": "analysis-3", "sinceLogSeq": 7, "waitSeconds": 10 }
{
  "success": true,
  "jobId": "analysis-3",
  "programPath": "/big.exe",
  "status": "completed",
  "functionCount": 1207,
  "log": [ { "seq": 8, "elapsedMs": 41230, "message": "Analysis COMPLETED (41218ms)" } ],
  "logCursor": 8,
  "truncated": false,
  "result": {
    "success": true,
    "programPath": "/big.exe",
    "analyzed": true,
    "wasFullAnalysis": true,
    "durationMs": 41218,
    "totalTaskTimeMs": 39870,
    "cancelled": false,
    "timedOut": false,
    "analyzersRun": [ { "name": "Function Start Search" } ],
    "persisted": "checkin",
    "saved": true
  }
}
```

`analysis-status` polling notes:

| Param           | Default | Meaning |
|-----------------|---------|---------|
| `jobId`         | —       | The job to poll. Provide **exactly one** of `jobId` or `programPath`. |
| `programPath`   | —       | Resolves to that program's **latest** job (`analysis-<N>`, greatest N). |
| `sinceLogSeq`   | `0`     | Cursor — return only entries with `seq > sinceLogSeq`. Feed back `logCursor`. |
| `waitSeconds`   | `10`    | Long-poll window; returns **the instant** the job terminates, else holds until it expires. |
| `maxLogEntries` | `50`    | Page size. When more entries remain, `truncated:true`. |

**Drain the log before trusting status alone.** When a response has `truncated:true`, call again with
`sinceLogSeq=logCursor` to fetch the remaining log lines — there are more than `maxLogEntries`
buffered. Status itself is always current regardless of truncation.

### Small-program fast path (backward compatible)

When `analyze-program` finishes within `waitSeconds` (default 10), the inline wait observes a terminal
status and returns the job's full result map in one call — with `status:"completed"` (or the
terminal status) added. **All prior fields are preserved** (`success`, `analyzed`, `wasFullAnalysis`,
`durationMs`, `analyzersRun`, `messages`, …), so existing callers keep working; the new
`jobId`, `status`, `persisted`, and `saved` fields are additive.

The result map produced by `AnalysisJobRunner` (returned either inline by `analyze-program` or under
`result` by `analysis-status`) contains:

| Field            | Notes |
|------------------|-------|
| `success`        | `true` unless the run was cancelled/timed-out. |
| `programPath`    | The analyzed program. |
| `analyzed`       | `GhidraProgramUtilities.isAnalyzed(program)` after the run. |
| `wasFullAnalysis`| `true` on a fresh program or with `forceFullAnalysis`; else incremental. |
| `durationMs`     | Wall-clock analysis time. |
| `totalTaskTimeMs`| Sum of per-analyzer task time. |
| `cancelled`      | `true` if the monitor was cancelled (cancel or timeout). |
| `timedOut`       | `true` only when the timeout fired and no cancel was requested. |
| `analyzersRun`   | `[{ "name": ... }]` of timed analyzer tasks. |
| `messages`       | Analyzer message-log lines (present only when non-empty). |
| `persisted`      | `checkin` \| `add_to_vc` \| `save` \| `skipped` \| `failed`. |
| `saved`          | Whether a local save occurred. |
| `persistError`   | Present only when checkin/add-to-VC failed after a successful local save. |

`persisted:"skipped"` covers **both** `persist:"none"` **and** "program had no changes since the
analysis" (`!program.isChanged()`). A persist failure is reported (`persisted:"failed"` +
`persistError`) but is **not** fatal — analysis success is independent of persistence.

### Persist semantics (`persist` param: `auto` | `save` | `none`)

Backed by `reva.util.ProgramPersistenceUtil` (the shared save-or-checkin helper, also used by
`checkin-program`):

| Mode            | Behavior |
|-----------------|----------|
| `auto` (default)| **Save locally, then checkin** if the file is under version control (add-to-VC for a not-yet-versioned file, checkin for an existing versioned file). |
| `save`          | Local save only — never touches version control. |
| `none`          | Don't persist at all (`persisted:"skipped"`). Use for a read-only analysis. |

The background persist always runs with `keepCheckedOut=true`, so it won't release the program's
checkout out from under an interactive session.

### Single-flight: one analysis per program

Only one analysis runs per program at a time. `analyze-program` checks
`AnalysisJobManager.runningJobForProgram(programPath)`: if a job is in flight it **reuses** that job
instead of starting a second one. Caveat for the model: the reuse path does **not** rebuild the
`AnalyzeRequest`, so the second call's `enableAnalyzers` / `disableAnalyzers` / `persist` /
`forceFullAnalysis` are **silently ignored** — overrides apply only to the call that *starts* the
job. (Analyzer-name *validation* still runs on every call and can still reject bad names.) To change
overrides, cancel the running job and start a fresh one.

### `waitSeconds` vs. the client tool-call timeout

The inline wait (in both `analyze-program` and `analysis-status`) holds the MCP request open for up
to `waitSeconds`. **Keep `waitSeconds` safely below the MCP client's tool-call timeout.** A value
above the client timeout drops the call — but the background job keeps running and stays pollable, so
this degrades to "the model has to re-poll" rather than losing work. Long analyses are *designed* to
fall through the inline wait into the pollable job; this is the normal path, not an error.

### `analysis-cancel`

`analysis-cancel` requires `jobId`. It sets the job's cancel flag and cancels the attached monitor
so the in-flight analysis unwinds. Cancellation is **asynchronous**: the tool returns immediately
(`alreadyTerminal:false`, "Cancellation requested"); poll `analysis-status` until the job reaches
`cancelled` to confirm. Partial analysis is still persisted as the job unwinds. Cancelling an
already-finished job is a no-op (`alreadyTerminal:true`).

### Supporting classes (`reva.services.*`)

- **`AnalysisJobManager`** — creates jobs (`analysis-<N>` ids), submits them to the worker pool, tracks them, enforces single-flight (`runningJobForProgram`), and looks them up (`get`, `all`). Caps retained jobs and cancels jobs on program-close / shutdown.
- **`AnalysisJob`** — in-memory job state: status, an append-only log buffer with a monotonic per-job `seq` counter (`logSince(sinceSeq, max)` returns a `LogPage` with `nextCursor` + `truncated`), live `functionCount`, and the result/error payloads. Thread-safe.
- **`AnalysisJobRunner`** — the `Runnable` that does all the Ghidra work on the worker thread (overrides → transaction → `startAnalysis` → persist → terminal status). Its `JobLogTaskMonitor` mirrors analyzer `setMessage` output into the job log (deduped) and refreshes the live function count.
- **`AnalyzeRequest`** — the immutable parameter bundle (program, enable/disable analyzers, `forceFullAnalysis`, `timeoutSeconds`, `persistMode`).

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
metadataInfo.put("items", filesList);
return createJsonResult(metadataInfo);
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

Map<String, Object> result = new HashMap<>();
result.put("count", programsData.size());
result.put("programs", programsData);
return createJsonResult(result);
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
- **Background analysis**: `analyze-program` runs auto-analysis on a worker thread (`reva.services.*`) and persists the result; the request thread only long-polls. See [Background Analysis Jobs](#background-analysis-jobs).
- **Persistence**: `analyze-program` and `checkin-program` share `reva.util.ProgramPersistenceUtil` for save-then-checkin semantics.