/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.tools.project;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.Analyzer;
import ghidra.framework.model.DomainObject;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import java.util.LinkedHashMap;
import java.util.concurrent.TimeUnit;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.Loader;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.plugins.importer.batch.BatchGroup;
import ghidra.plugins.importer.batch.BatchGroup.BatchLoadConfig;
import ghidra.plugins.importer.batch.BatchGroupLoadSpec;
import ghidra.plugins.importer.batch.BatchInfo;
import ghidra.app.util.bin.ByteProvider;
import ghidra.framework.store.local.LocalFileSystem;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.debug.DebugCaptureService;
import reva.plugin.RevaProgramManager;
import reva.plugin.ConfigManager;
import reva.services.AnalysisJob;
import reva.services.AnalysisJobManager;
import reva.services.AnalyzeRequest;
import reva.services.JobLog;
import reva.tools.AbstractToolProvider;
import reva.util.ProgramPersistenceUtil;
import reva.util.ProgramPersistenceUtil.PersistMode;
import reva.util.SchemaUtil;
import reva.util.RevaInternalServiceRegistry;

/**
 * Tool provider for project-related operations.
 * Provides tools to get the current program, list project files, and perform version control operations.
 */
public class ProjectToolProvider extends AbstractToolProvider {

    private final boolean headlessMode;

    /**
     * Constructor
     * @param server The MCP server
     * @param headlessMode True if running in headless mode (no GUI context)
     */
    public ProjectToolProvider(McpSyncServer server, boolean headlessMode) {
        super(server);
        this.headlessMode = headlessMode;
    }

    @Override
    public void registerTools() {
        // GUI-only tools: require ToolManager which isn't available in headless mode
        if (!headlessMode) {
            registerGetCurrentProgramTool();
            registerListOpenProgramsTool();
        }
        registerListProjectFilesTool();
        registerCheckinProgramTool();
        registerAnalyzeProgramTool();
        registerAnalysisStatusTool();
        registerAnalysisCancelTool();
        registerListAnalyzersTool();
        registerChangeProcessorTool();
        registerImportFileTool();
        registerCaptureDebugInfoTool();
    }

    /**
     * Register a tool to get the currently active program
     */
    private void registerGetCurrentProgramTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        // This tool doesn't require any parameters
        List<String> required = new ArrayList<>();

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-current-program")
            .title("Get Current Program")
            .description("Get the currently active program in Ghidra")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get all open programs
            List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
            if (openPrograms.isEmpty()) {
                return createErrorResult("No programs are currently open in Ghidra");
            }

            // For now, just return the first program (assuming it's the active one)
            Program program = openPrograms.get(0);

            // Create result data
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

            return createJsonResult(programInfo);
        });
    }

    /**
     * Register a tool to list files and folders in the Ghidra project
     */
    private void registerListProjectFilesTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("folderPath", SchemaUtil.stringProperty(
            "Path to the folder to list contents of. Use '/' for the root folder."
        ));
        properties.put("recursive", SchemaUtil.booleanPropertyWithDefault(
            "Whether to list files recursively", false
        ));

        List<String> required = List.of("folderPath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-project-files")
            .title("List Project Files")
            .description("List files and folders in the Ghidra project")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get the folder path from the request
            String folderPath;
            try {
                folderPath = getString(request, "folderPath");
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            }

            // Get the recursive flag
            boolean recursive = getOptionalBoolean(request, "recursive", false);

            // Get the active project
            Project project = AppInfo.getActiveProject();
            if (project == null) {
                return createErrorResult("No active project found");
            }

            // Get the folder from the path
            DomainFolder folder;
            if (folderPath.equals("/")) {
                folder = project.getProjectData().getRootFolder();
            } else {
                folder = project.getProjectData().getFolder(folderPath);
            }

            if (folder == null) {
                return createErrorResult("Folder not found: " + folderPath);
            }

            // Get files and folders in the specified path
            List<Map<String, Object>> filesList = new ArrayList<>();

            // Add metadata about the current folder
            Map<String, Object> metadataInfo = new HashMap<>();
            metadataInfo.put("folderPath", folderPath);
            metadataInfo.put("folderName", folder.getName());
            metadataInfo.put("isRecursive", recursive);

            // Get the files and folders
            if (recursive) {
                collectFilesRecursive(folder, filesList, "");
            } else {
                collectFilesInFolder(folder, filesList, "");
            }

            metadataInfo.put("itemCount", filesList.size());
            metadataInfo.put("items", filesList);
            return createJsonResult(metadataInfo);
        });
    }

    /**
     * Register a tool to list all open programs across all Ghidra tools
     */
    private void registerListOpenProgramsTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        // This tool doesn't require any parameters
        List<String> required = new ArrayList<>();

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-open-programs")
            .title("List Open Programs")
            .description("List all programs currently open in Ghidra across all tools")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get all open programs from all tools
            List<Program> openPrograms = RevaProgramManager.getOpenPrograms();

            if (openPrograms.isEmpty()) {
                return createErrorResult("No programs are currently open in Ghidra");
            }

            // Create program info for each program
            List<Map<String, Object>> programsData = new ArrayList<>();
            for (Program program : openPrograms) {
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
                programsData.add(programInfo);
            }

            Map<String, Object> result = new HashMap<>();
            result.put("count", programsData.size());
            result.put("programs", programsData);
            return createJsonResult(result);
        });
    }

    /**
     * Register a tool to checkin (commit) a program to version control
     */
    private void registerCheckinProgramTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty(
            "Path to the program to checkin (e.g., '/Hatchery.exe')"
        ));
        properties.put("message", SchemaUtil.stringProperty(
            "Commit message for the checkin"
        ));
        properties.put("keepCheckedOut", SchemaUtil.booleanPropertyWithDefault(
            "Whether to keep the program checked out after checkin", false
        ));

        List<String> required = List.of("programPath", "message");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("checkin-program")
            .title("Checkin Program")
            .description("Checkin (commit) a program to version control with a commit message")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get parameters
            String programPath;
            String message;
            try {
                programPath = getString(request, "programPath");
                message = getString(request, "message");
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            }

            boolean keepCheckedOut = getOptionalBoolean(request, "keepCheckedOut", false);

            // Get the program
            Program program;
            try {
                program = getProgramFromArgs(request);
            } catch (Exception e) {
                return createErrorResult(e.getMessage());
            }

            DomainFile domainFile = program.getDomainFile();

            try {
                // Pre-validation: reject versioned files that cannot be persisted via
                // checkin/addToVC so the user gets the specific error rather than a silent
                // local-only save. ProgramPersistenceUtil.selectAction would otherwise treat
                // these as SAVE. These branches must run BEFORE persist().
                if (!domainFile.canAddToRepository() && !domainFile.canCheckin()
                        && domainFile.isVersioned()) {
                    if (!domainFile.isCheckedOut()) {
                        return createErrorResult("Program is not checked out and cannot be modified: " + programPath);
                    }
                    else if (!domainFile.modifiedSinceCheckout()) {
                        return createErrorResult("Program has no changes since checkout: " + programPath);
                    }
                    else {
                        return createErrorResult("Program cannot be checked in for an unknown reason: " + programPath);
                    }
                }

                // Save locally, then checkin/addToVC when the file is under version control.
                // persist() saves while the program is still open (the program object held here
                // is the cache's consumer; releasing it before save would close it). checkin/
                // addToVersionControl tolerate an open program (Ghidra forces keepCheckedOut=true
                // when the file is in use), so the cache release happens afterward as pure
                // cache hygiene.
                ProgramPersistenceUtil.PersistResult pr = ProgramPersistenceUtil.persist(
                    program, ProgramPersistenceUtil.PersistMode.AUTO, message, keepCheckedOut,
                    TaskMonitor.DUMMY);

                // Release program from cache after version control operations.
                boolean wasCached = RevaProgramManager.releaseProgramFromCache(program);
                if (wasCached) {
                    Msg.debug(this, "Released program from cache after version control: " + programPath);
                }

                // A checkin/addToVC failure after a successful save surfaces as an error,
                // matching the prior "Checkin failed: ..." behavior. Skip the reopen, as the
                // prior flow also errored out before reopening.
                if (pr.error != null) {
                    return createErrorResult("Checkin failed: " + pr.error);
                }

                // Re-open program to cache if it was cached and we're keeping it checked out.
                boolean didVersionControl = pr.action == ProgramPersistenceUtil.PersistAction.CHECKIN
                    || pr.action == ProgramPersistenceUtil.PersistAction.ADD_TO_VC;
                if (didVersionControl && wasCached && keepCheckedOut) {
                    Program reopenedProgram = RevaProgramManager.reopenProgramToCache(programPath);
                    if (reopenedProgram != null) {
                        Msg.debug(this, "Re-opened program to cache after version control: " + programPath);
                    }
                }

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("programPath", programPath);
                result.put("message", message);
                if (pr.action == ProgramPersistenceUtil.PersistAction.ADD_TO_VC) {
                    result.put("action", "added_to_version_control");
                    result.put("keepCheckedOut", keepCheckedOut);
                    result.put("isVersioned", domainFile.isVersioned());
                    result.put("isCheckedOut", domainFile.isCheckedOut());
                }
                else if (pr.action == ProgramPersistenceUtil.PersistAction.CHECKIN) {
                    result.put("action", "checked_in");
                    result.put("keepCheckedOut", keepCheckedOut);
                    result.put("isVersioned", domainFile.isVersioned());
                    result.put("isCheckedOut", domainFile.isCheckedOut());
                }
                else {
                    // SAVE or SKIP (read-only): treated as a local save, matching the prior
                    // "not under version control" / read-only handling.
                    result.put("action", "saved");
                    result.put("isVersioned", false);
                    result.put("info", "Program is not under version control - changes were saved instead");
                }

                return createJsonResult(result);

            } catch (Exception e) {
                return createErrorResult("Checkin failed: " + e.getMessage());
            }
        });
    }

    /**
     * Recursively collect all program paths from a folder and its subfolders
     * @param folder The folder to collect from
     * @param programPaths List to accumulate program paths
     */
    private void collectAllProgramPaths(DomainFolder folder, List<String> programPaths) {
        // Collect programs in this folder
        for (DomainFile file : folder.getFiles()) {
            if (file.getContentType().equals("Program")) {
                programPaths.add(file.getPathname());
            }
        }

        // Recursively collect from subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            collectAllProgramPaths(subfolder, programPaths);
        }
    }

    /**
     * Run a full auto-analysis on a freshly-imported program. Mirrors analyze-program's
     * full-analysis flow so analyzeAfterImport produces the same result as an explicit
     * analyze-program call with forceFullAnalysis=true on a fresh program.
     *
     * Without this (just calling startAnalysis on a fresh program), only addresses
     * already on the analyzer's queue get analyzed -- typically just the entry point
     * and import thunks -- so non-entry functions named in the symbol table are
     * never created.
     *
     * @return true if analysis completed; false if the user/timeout cancelled the
     *         monitor mid-run. Distinct from environmental "no AutoAnalysisManager
     *         available" — that throws IllegalStateException so callers can label
     *         it as an internal failure rather than mis-reporting it as a timeout.
     * @throws IllegalStateException if Ghidra has no AutoAnalysisManager for this
     *         program (an unexpected internal state).
     */
    private boolean runFullAnalysisAfterImport(Program program, TaskMonitor monitor) {
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        if (mgr == null) {
            throw new IllegalStateException(
                "No AutoAnalysisManager available for " + program.getDomainFile().getPathname() +
                ". Ghidra is in an unexpected state — analysis cannot proceed.");
        }
        mgr.initializeOptions();
        int tx = program.startTransaction("ReVa: Auto Analysis (post-import)");
        try {
            if (!GhidraProgramUtilities.isAnalyzed(program)) {
                mgr.reAnalyzeAll(null);
            }
            mgr.startAnalysis(monitor);
            boolean cancelled = monitor.isCancelled();
            if (!cancelled) {
                GhidraProgramUtilities.markProgramAnalyzed(program);
            }
            program.endTransaction(tx, true);
            return !cancelled;
        } catch (Exception e) {
            program.endTransaction(tx, false);
            throw e;
        }
    }

    /**
     * Collect imported files, optionally analyze them, and add them to version control
     * @param destFolder The destination folder where files were imported
     * @param importedBaseName The base name of the imported file/directory
     * @param analyzeAfterImport Whether to run auto-analysis on imported programs
     * @param analysisTimeoutSeconds Timeout in seconds for analysis operations
     * @param versionedFiles List to track successfully versioned files
     * @param analyzedFiles List to track successfully analyzed files
     * @param errors List to track errors
     * @param monitor Task monitor for cancellation and timeout checking
     */
    private void collectImportedFiles(DomainFolder destFolder, String importedBaseName,
                                     boolean analyzeAfterImport, int analysisTimeoutSeconds,
                                     List<String> versionedFiles, List<String> analyzedFiles,
                                     List<String> errors, TaskMonitor monitor) {
        try {
            // Find newly imported files in the destination folder
            for (DomainFile file : destFolder.getFiles()) {
                boolean wasAnalyzed = false;

                // Analyze if requested and this is a Program file
                if (file.getContentType().equals("Program") && analyzeAfterImport) {
                    try {
                        // Open program with temporary consumer
                        Object consumer = new Object();
                        DomainObject domainObject = file.getDomainObject(consumer, false, false, monitor);

                        if (domainObject instanceof Program) {
                            Program program = (Program) domainObject;
                            try {
                                TaskMonitor analysisMonitor =
                                    TimeoutTaskMonitor.timeoutIn(analysisTimeoutSeconds, TimeUnit.SECONDS);
                                try {
                                    boolean completed = runFullAnalysisAfterImport(program, analysisMonitor);
                                    if (!completed) {
                                        errors.add("Analysis timed out for " + file.getPathname() +
                                            " after " + analysisTimeoutSeconds + " seconds");
                                    } else {
                                        program.save("Auto-analysis complete", monitor);
                                        analyzedFiles.add(file.getPathname());
                                        wasAnalyzed = true;
                                    }
                                } catch (IllegalStateException e) {
                                    // Distinct from a timeout: AutoAnalysisManager unavailable
                                    // for this program. Report verbatim so the caller doesn't
                                    // see this as "analysis timed out".
                                    errors.add("Analysis setup failed for " + file.getPathname() +
                                        ": " + e.getMessage());
                                }
                            } finally {
                                // Release program
                                program.release(consumer);
                            }
                        }
                    } catch (Exception e) {
                        errors.add("Analysis failed for " + file.getPathname() + ": " + e.getMessage());
                    }
                }

                // Add to version control after analysis (or immediately if no analysis)
                if (file.canAddToRepository()) {
                    try {
                        // Use different commit message based on whether analysis was performed
                        String commitMessage = wasAnalyzed
                            ? "Initial import via ReVa (analyzed)"
                            : "Initial import via ReVa";
                        file.addToVersionControl(commitMessage, false, monitor);
                        versionedFiles.add(file.getPathname());
                    } catch (Exception e) {
                        errors.add("Failed to add " + file.getPathname() + " to version control: " + e.getMessage());
                    }
                }
            }

            // Recursively process subfolders
            for (DomainFolder subfolder : destFolder.getFolders()) {
                collectImportedFiles(subfolder, importedBaseName, analyzeAfterImport, analysisTimeoutSeconds,
                    versionedFiles, analyzedFiles, errors, monitor);
            }
        } catch (Exception e) {
            errors.add("Error collecting imported files: " + e.getMessage());
        }
    }

    /**
     * Collect files and subfolders from a folder
     * @param folder The folder to collect from
     * @param filesList The list to add files to
     * @param pathPrefix The path prefix for subfolder names
     */
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

            filesList.add(fileInfo);
        }
    }

    /**
     * Recursively collect files and subfolders from a folder
     * @param folder The folder to collect from
     * @param filesList The list to add files to
     * @param pathPrefix The path prefix for subfolder names
     */
    private void collectFilesRecursive(DomainFolder folder, List<Map<String, Object>> filesList, String pathPrefix) {
        // Collect files in current folder
        collectFilesInFolder(folder, filesList, pathPrefix);

        // Recursively collect files in subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            String newPrefix = pathPrefix + subfolder.getName() + "/";
            collectFilesRecursive(subfolder, filesList, newPrefix);
        }
    }

    /**
     * Register a tool to analyze a program with Ghidra's auto-analysis.
     * Blocks until analysis completes (or times out), wraps the work in a transaction,
     * marks the program as analyzed, and reports progress via MCP when the client supplies
     * a progressToken. Supports per-call analyzer overrides that do not persist.
     */
    private void registerAnalyzeProgramTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty(
            "Path to the program to analyze (e.g., '/Hatchery.exe')"
        ));

        Map<String, Object> enableProp = new HashMap<>();
        enableProp.put("type", "array");
        enableProp.put("items", Map.of("type", "string"));
        enableProp.put("description",
            "Names of analyzers to enable for this run only (does not persist). "
            + "Each name must be a top-level analyzer enable flag (no dots in the name) -- "
            + "use list-analyzers to discover valid names.");
        properties.put("enableAnalyzers", enableProp);

        Map<String, Object> disableProp = new HashMap<>();
        disableProp.put("type", "array");
        disableProp.put("items", Map.of("type", "string"));
        disableProp.put("description",
            "Names of analyzers to disable for this run only (does not persist). "
            + "Each name must be a top-level analyzer enable flag (no dots in the name) -- "
            + "use list-analyzers to discover valid names.");
        properties.put("disableAnalyzers", disableProp);

        Map<String, Object> forceFullProp = new HashMap<>();
        forceFullProp.put("type", "boolean");
        forceFullProp.put("description",
            "Force a full re-analysis even if the program is already marked analyzed (default: false). "
            + "When false, the first call on a fresh program runs full analysis and subsequent calls are incremental.");
        forceFullProp.put("default", false);
        properties.put("forceFullAnalysis", forceFullProp);

        Map<String, Object> timeoutProp = new HashMap<>();
        timeoutProp.put("type", "integer");
        timeoutProp.put("description",
            "Maximum analysis time in seconds. Defaults to the configured analysis timeout. "
            + "Pass -1 to disable the timeout entirely (analysis runs until done).");
        properties.put("timeoutSeconds", timeoutProp);

        Map<String, Object> waitProp = new HashMap<>();
        waitProp.put("type", "integer");
        waitProp.put("minimum", 0);
        waitProp.put("default", 10);
        waitProp.put("description",
            "Seconds to wait inline for analysis to finish before returning a job handle to poll. "
            + "Small programs finish within this window and return the full result in one call; long "
            + "analyses return {status:running, jobId} to poll with analysis-status. Keep this safely "
            + "below your MCP client's tool-call timeout — the inline wait holds the request open, so a "
            + "value above the client timeout would drop the call (the job still runs and stays pollable).");
        properties.put("waitSeconds", waitProp);

        Map<String, Object> persistProp = new HashMap<>();
        persistProp.put("type", "string");
        persistProp.put("enum", List.of("auto", "save", "none"));
        persistProp.put("default", "auto");
        persistProp.put("description",
            "How to persist the analysis when it finishes: auto = save locally then checkin if the "
            + "file is under version control; save = local save only; none = don't persist (read-only).");
        properties.put("persist", persistProp);

        List<String> required = List.of("programPath");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("analyze-program")
            .title("Analyze Program")
            .description(
                "Run Ghidra's auto-analysis on a program as a background job, then persist the result. "
                + "Waits inline up to waitSeconds for completion: small programs finish in that window and "
                + "return the full result (success, analyzersRun, durationMs, persisted, saved, ...) in one "
                + "call with status=completed. Longer analyses return {status:running, jobId, log} so you "
                + "can poll analysis-status with the jobId (or stop it with analysis-cancel). Only one "
                + "analysis runs per program at a time — calling again while one is in flight reuses the "
                + "running job. Supports per-call analyzer overrides via enableAnalyzers / disableAnalyzers "
                + "(use list-analyzers for valid names) and a persist mode (auto/save/none). After "
                + "import-file, call this tool to populate functions, strings, and references.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            String programPath = program.getDomainFile().getPathname();

            List<String> enableAnalyzers =
                getOptionalStringList(request.arguments(), "enableAnalyzers", List.of());
            List<String> disableAnalyzers =
                getOptionalStringList(request.arguments(), "disableAnalyzers", List.of());
            boolean forceFullAnalysis = getOptionalBoolean(request, "forceFullAnalysis", false);

            ConfigManager configManager =
                RevaInternalServiceRegistry.getService(ConfigManager.class);
            int defaultTimeout = configManager != null ? configManager.getAnalysisTimeoutSeconds() : 600;
            int timeoutSeconds = getOptionalInt(request, "timeoutSeconds", defaultTimeout);

            if (timeoutSeconds == 0 || (timeoutSeconds < 0 && timeoutSeconds != -1)) {
                return createErrorResult(
                    "timeoutSeconds must be a positive integer or -1 (no timeout); got " + timeoutSeconds);
            }

            int waitSeconds = getOptionalInt(request, "waitSeconds", 10);
            if (waitSeconds < 0) {
                return createErrorResult("waitSeconds must be >= 0; got " + waitSeconds);
            }

            // Map the persist mode string to the runner's PersistMode.
            String persistArg = getOptionalString(request, "persist", "auto");
            PersistMode persistMode;
            switch (persistArg.toLowerCase()) {
                case "auto":
                    persistMode = PersistMode.AUTO;
                    break;
                case "save":
                    persistMode = PersistMode.SAVE;
                    break;
                case "none":
                    persistMode = PersistMode.NONE;
                    break;
                default:
                    return createErrorResult(
                        "persist must be one of [auto, save, none]; got '" + persistArg + "'");
            }

            // Get the analysis manager early so its analyzers register their options on the
            // program before we validate user-supplied override names. Without this, a fresh
            // program has no entries in ANALYSIS_PROPERTIES and every override would be
            // rejected as "unknown analyzer". (Validation runs synchronously, before submit,
            // so bad input still errors immediately.)
            AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(program);
            if (aam == null) {
                return createErrorResult("Could not get analysis manager for program: " + programPath);
            }
            aam.initializeOptions();

            Options analysisOpts = program.getOptions(Program.ANALYSIS_PROPERTIES);

            // Validate override names: each must name a top-level boolean analyzer enable flag.
            for (String name : enableAnalyzers) {
                String err = validateAnalyzerOverride(analysisOpts, name);
                if (err != null) {
                    return createErrorResult(err);
                }
            }
            for (String name : disableAnalyzers) {
                String err = validateAnalyzerOverride(analysisOpts, name);
                if (err != null) {
                    return createErrorResult(err);
                }
            }

            AnalysisJobManager mgr = RevaInternalServiceRegistry.getService(AnalysisJobManager.class);
            if (mgr == null) {
                return createErrorResult("background analysis service unavailable");
            }

            // Single-flight: atomically reuse an in-flight job for this program, or start a new
            // one. startOrAttach holds the manager lock across find+create+submit so two
            // concurrent calls for the same program can't both launch an analysis.
            AnalysisJob job = mgr.startOrAttach(programPath, new AnalyzeRequest(
                program, enableAnalyzers, disableAnalyzers, forceFullAnalysis,
                timeoutSeconds, persistMode));

            Object progressToken = request.progressToken();
            boolean emitProgress = progressToken != null && exchange != null;

            // Inline long-poll: wait up to waitSeconds for the job to reach a terminal state,
            // emitting best-effort progress notifications when the client opted in.
            awaitWithProgress(exchange, request, waitSeconds,
                () -> job.getStatus().isTerminal(),
                () -> {
                    String latest = job.getLatestLogMessage();
                    return latest != null ? latest : job.getStatus().name().toLowerCase();
                });

            if (job.getStatus().isTerminal()) {
                // Start from the job's result map (which carries success/analyzed/wasFullAnalysis/
                // durationMs/analyzersRun/messages/persisted/saved/... for backward compatibility).
                Map<String, Object> result = job.getResult();
                if (result == null) {
                    // Only happens on FAILED before a result map was set.
                    result = new HashMap<>();
                    result.put("success", false);
                    result.put("programPath", programPath);
                    if (job.getError() != null) {
                        result.put("error", job.getError());
                    }
                } else {
                    result = new HashMap<>(result);
                }
                result.put("jobId", job.getJobId());
                result.put("status", job.getStatus().name().toLowerCase());

                if (emitProgress) {
                    try {
                        exchange.progressNotification(new McpSchema.ProgressNotification(
                            progressToken, 1.0, 1.0,
                            "Analysis " + job.getStatus().name().toLowerCase()));
                    } catch (Exception ignore) {
                        // best-effort
                    }
                }

                return createJsonResult(result);
            }

            // Still running after the inline wait: return a job handle to poll.
            JobLog.LogPage page = job.logSince(0, 50);
            List<Map<String, Object>> log = new ArrayList<>();
            for (JobLog.LogEntry entry : page.entries) {
                Map<String, Object> e = new LinkedHashMap<>();
                e.put("seq", entry.seq);
                e.put("elapsedMs", entry.elapsedMs);
                e.put("message", entry.message);
                log.add(e);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", true);
            result.put("programPath", programPath);
            result.put("jobId", job.getJobId());
            result.put("status", "running");
            result.put("functionCount", job.getFunctionCount());
            result.put("log", log);
            result.put("logCursor", page.nextCursor);
            result.put("truncated", page.truncated);
            result.put("hint",
                "Analysis still running. Poll analysis-status with this jobId and "
                + "sinceLogSeq=logCursor; or call analysis-cancel to stop.");

            return createJsonResult(result);
        });
    }

    /**
     * Register the analysis-status tool: a log-tailing long-poll the model loops on to monitor a
     * background analysis job until it terminates.
     */
    private void registerAnalysisStatusTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("jobId", SchemaUtil.stringProperty(
            "The analysis job to poll (e.g., 'analysis-3'), as returned by analyze-program. "
            + "Provide exactly one of jobId or programPath."));
        properties.put("programPath", SchemaUtil.stringProperty(
            "Alternative to jobId: the program path (e.g., '/Hatchery.exe') whose LATEST analysis "
            + "job should be polled. Provide exactly one of jobId or programPath."));

        Map<String, Object> sinceProp = new HashMap<>();
        sinceProp.put("type", "integer");
        sinceProp.put("minimum", 0);
        sinceProp.put("default", 0);
        sinceProp.put("description",
            "Return only log entries with seq greater than this cursor. Feed back the previous "
            + "call's logCursor here to get just the new lines.");
        properties.put("sinceLogSeq", sinceProp);

        Map<String, Object> waitProp = new HashMap<>();
        waitProp.put("type", "integer");
        waitProp.put("minimum", 0);
        waitProp.put("default", 10);
        waitProp.put("description",
            "Seconds to long-poll: the call holds open up to this long waiting for progress, then "
            + "returns. It returns the instant the job terminates. Keep this safely below your MCP "
            + "client's tool-call timeout — the inline wait holds the request open, so a value above "
            + "the client timeout would drop the call (the job still runs and stays pollable).");
        properties.put("waitSeconds", waitProp);

        Map<String, Object> maxLogProp = new HashMap<>();
        maxLogProp.put("type", "integer");
        maxLogProp.put("minimum", 1);
        maxLogProp.put("default", 50);
        maxLogProp.put("description",
            "Maximum number of log entries to return per call. When more are available, truncated "
            + "is true and you should call again with sinceLogSeq=logCursor to drain them.");
        properties.put("maxLogEntries", maxLogProp);

        List<String> required = List.of();

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("analysis-status")
            .title("Analysis Status")
            .description(
                "Poll a background analysis job started by analyze-program. Call repeatedly, feeding "
                + "back logCursor as sinceLogSeq, until status is terminal "
                + "(completed/failed/cancelled/timed_out). Each call returns the new log lines since "
                + "the cursor and the live function count, and long-polls up to waitSeconds for "
                + "progress — returning immediately when the job finishes. When terminal, the response "
                + "also carries the full result (persisted, saved, durationMs, ...). Identify the job "
                + "by jobId (preferred) or by programPath (resolves to that program's latest job).")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            AnalysisJobManager mgr = RevaInternalServiceRegistry.getService(AnalysisJobManager.class);
            if (mgr == null) {
                return createErrorResult("background analysis service unavailable");
            }

            String jobId = getOptionalString(request, "jobId", null);
            String programPath = getOptionalString(request, "programPath", null);
            boolean hasJobId = jobId != null && !jobId.isBlank();
            boolean hasProgramPath = programPath != null && !programPath.isBlank();

            if (hasJobId && hasProgramPath) {
                return createErrorResult("Provide exactly one of jobId or programPath, not both");
            }
            if (!hasJobId && !hasProgramPath) {
                return createErrorResult("provide jobId or programPath");
            }

            AnalysisJob job;
            if (hasJobId) {
                job = mgr.get(jobId);
                if (job == null) {
                    List<String> ids = new ArrayList<>();
                    for (AnalysisJob j : mgr.all()) {
                        ids.add(j.getJobId());
                    }
                    return createErrorResult("No job " + jobId + ". Active jobs: " + ids);
                }
            } else {
                job = latestJobForProgram(mgr, programPath);
                if (job == null) {
                    return createErrorResult("No analysis job found for programPath: " + programPath);
                }
            }

            long sinceLogSeq = getOptionalInt(request, "sinceLogSeq", 0);
            if (sinceLogSeq < 0) {
                return createErrorResult("sinceLogSeq must be >= 0; got " + sinceLogSeq);
            }
            int waitSeconds = getOptionalInt(request, "waitSeconds", 10);
            if (waitSeconds < 0) {
                return createErrorResult("waitSeconds must be >= 0; got " + waitSeconds);
            }
            int maxLogEntries = getOptionalInt(request, "maxLogEntries", 50);
            if (maxLogEntries < 1) {
                return createErrorResult("maxLogEntries must be >= 1; got " + maxLogEntries);
            }

            // Long-poll with progress: return the instant the job terminates, else hold until the
            // window expires. Emits MCP progress notifications on each tick when the client
            // supplied a progressToken — this both drives the progress UI and resets the client's
            // idle/tool-call timeout, preventing spurious "operation timed out" errors on long
            // waitSeconds values.
            awaitWithProgress(exchange, request, waitSeconds,
                () -> job.getStatus().isTerminal(),
                () -> {
                    String latest = job.getLatestLogMessage();
                    return latest != null ? latest : job.getStatus().name().toLowerCase();
                });

            // Emit a final progress notification when the job has reached a terminal state,
            // consistent with analyze-program's behavior.
            Object progressToken = request.progressToken();
            if (progressToken != null && exchange != null && job.getStatus().isTerminal()) {
                try {
                    exchange.progressNotification(new McpSchema.ProgressNotification(
                        progressToken, 1.0, 1.0,
                        "Analysis " + job.getStatus().name().toLowerCase()));
                } catch (Exception ignore) {
                    // best-effort
                }
            }

            JobLog.LogPage page = job.logSince(sinceLogSeq, maxLogEntries);
            List<Map<String, Object>> log = new ArrayList<>();
            for (JobLog.LogEntry entry : page.entries) {
                Map<String, Object> e = new LinkedHashMap<>();
                e.put("seq", entry.seq);
                e.put("elapsedMs", entry.elapsedMs);
                e.put("message", entry.message);
                log.add(e);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", true);
            result.put("jobId", job.getJobId());
            result.put("programPath", job.getProgramPath());
            result.put("status", job.getStatus().name().toLowerCase());
            result.put("functionCount", job.getFunctionCount());
            result.put("log", log);
            result.put("logCursor", page.nextCursor);
            result.put("truncated", page.truncated);

            if (job.getStatus().isTerminal()) {
                Map<String, Object> jobResult = job.getResult();
                if (jobResult != null) {
                    result.put("result", jobResult);
                } else if (job.getError() != null) {
                    result.put("error", job.getError());
                }
            }

            return createJsonResult(result);
        });
    }

    private void registerAnalysisCancelTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("jobId", SchemaUtil.stringProperty(
            "The analysis job to cancel (e.g. 'analysis-3')."));

        List<String> required = List.of("jobId");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("analysis-cancel")
            .title("Analysis Cancel")
            .description(
                "Request cancellation of a running background analysis job started by analyze-program. "
                + "Cancellation is asynchronous: this returns immediately after requesting it; poll "
                + "analysis-status until the job reaches a terminal state (cancelled) to confirm. "
                + "Partial analysis work is still persisted when the job unwinds. If the job has already "
                + "finished, this is a no-op and reports alreadyTerminal:true.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            AnalysisJobManager mgr = RevaInternalServiceRegistry.getService(AnalysisJobManager.class);
            if (mgr == null) {
                return createErrorResult("background analysis service unavailable");
            }

            String jobId = getString(request, "jobId");

            AnalysisJob job = mgr.get(jobId);
            if (job == null) {
                List<String> ids = new ArrayList<>();
                for (AnalysisJob j : mgr.all()) {
                    ids.add(j.getJobId());
                }
                return createErrorResult("No job " + jobId + ". Active jobs: " + ids);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", true);
            result.put("jobId", job.getJobId());

            if (job.getStatus().isTerminal()) {
                result.put("status", job.getStatus().name().toLowerCase());
                result.put("alreadyTerminal", true);
                result.put("message", "Job already finished; nothing to cancel.");
                return createJsonResult(result);
            }

            job.requestCancel();
            result.put("status", job.getStatus().name().toLowerCase());
            result.put("alreadyTerminal", false);
            result.put("message", "Cancellation requested. Poll analysis-status until the job reaches "
                + "a terminal state (cancelled); partial analysis is still persisted.");
            return createJsonResult(result);
        });
    }

    /**
     * Find the latest analysis job for the given program path. Job ids are {@code "analysis-<N>"}
     * with monotonically increasing N; the latest job is the one with the greatest N.
     *
     * @param mgr the analysis job manager
     * @param programPath the program path to match
     * @return the most recent job for that path, or null if none exists
     */
    private AnalysisJob latestJobForProgram(AnalysisJobManager mgr, String programPath) {
        AnalysisJob latest = null;
        long latestN = Long.MIN_VALUE;
        for (AnalysisJob job : mgr.all()) {
            if (!job.getProgramPath().equals(programPath)) {
                continue;
            }
            long n = jobIdSuffix(job.getJobId());
            if (latest == null || n > latestN) {
                latest = job;
                latestN = n;
            }
        }
        return latest;
    }

    /**
     * Parse the numeric suffix of an {@code "analysis-<N>"} job id. Returns {@link Long#MIN_VALUE}
     * for ids that don't end in a parseable number, so malformed ids never win the "latest" race.
     */
    private long jobIdSuffix(String jobId) {
        int dash = jobId.lastIndexOf('-');
        if (dash < 0 || dash == jobId.length() - 1) {
            return Long.MIN_VALUE;
        }
        try {
            return Long.parseLong(jobId.substring(dash + 1));
        } catch (NumberFormatException e) {
            return Long.MIN_VALUE;
        }
    }

    /**
     * Validate that the given analyzer-override name is a top-level analyzer enable flag
     * (a boolean entry in the program's analysis options, with no dot separators).
     * @return null if valid, otherwise a user-facing error message
     */
    private String validateAnalyzerOverride(Options analysisOpts, String name) {
        if (name == null || name.isBlank()) {
            return "Analyzer override name must be non-empty";
        }
        if (name.contains(".")) {
            return "Analyzer override '" + name
                + "' looks like a sub-option (contains '.'). Pass the top-level analyzer name only "
                + "(use list-analyzers to discover valid names).";
        }
        if (!analysisOpts.contains(name)) {
            return "Unknown analyzer '" + name
                + "'. Use list-analyzers to see analyzers applicable to this program.";
        }
        OptionType type = analysisOpts.getType(name);
        if (type != OptionType.BOOLEAN_TYPE) {
            return "Analyzer override '" + name + "' is not a boolean enable flag (type=" + type
                + "). Pass the top-level analyzer name only.";
        }
        return null;
    }

    /**
     * Register a read-only tool that lists analyzers applicable to a program along with
     * their current enable state, default state, type, priority, and any registered
     * sub-options. LLMs use this to discover valid names for analyze-program's
     * enableAnalyzers / disableAnalyzers parameters.
     */
    private void registerListAnalyzersTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty(
            "Path to the program whose analyzers to list (e.g., '/Hatchery.exe')."));

        List<String> required = List.of("programPath");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-analyzers")
            .title("List Analyzers")
            .description(
                "List the auto-analyzers that apply to the given program, including each "
                + "analyzer's name, description, type, priority, default and current enabled state, "
                + "and any registered sub-options. Use the returned 'name' field as input to "
                + "analyze-program's enableAnalyzers / disableAnalyzers parameters.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            String programPath = program.getDomainFile().getPathname();

            Options analysisOpts = program.getOptions(Program.ANALYSIS_PROPERTIES);

            List<Map<String, Object>> analyzers = new ArrayList<>();
            for (Analyzer analyzer : ClassSearcher.getInstances(Analyzer.class)) {
                if (analyzer.isPrototype()) {
                    continue;
                }
                if (!analyzer.canAnalyze(program)) {
                    continue;
                }

                String name = analyzer.getName();
                boolean defaultEnabled = analyzer.getDefaultEnablement(program);
                boolean currentlyEnabled;
                if (analysisOpts.contains(name)
                        && analysisOpts.getType(name) == OptionType.BOOLEAN_TYPE) {
                    currentlyEnabled = analysisOpts.getBoolean(name, defaultEnabled);
                } else {
                    currentlyEnabled = defaultEnabled;
                }

                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("name", name);
                entry.put("description", analyzer.getDescription());
                entry.put("type", analyzer.getAnalysisType().toString());
                entry.put("priority", analyzer.getPriority().priority());
                entry.put("defaultEnabled", defaultEnabled);
                entry.put("currentlyEnabled", currentlyEnabled);
                entry.put("supportsOneTimeAnalysis", analyzer.supportsOneTimeAnalysis());

                List<Map<String, Object>> subOptions = collectAnalyzerSubOptions(analysisOpts, name);
                if (!subOptions.isEmpty()) {
                    entry.put("subOptions", subOptions);
                }

                analyzers.add(entry);
            }

            // Stable order: by priority then name
            analyzers.sort((a, b) -> {
                int pa = (Integer) a.get("priority");
                int pb = (Integer) b.get("priority");
                if (pa != pb) {
                    return Integer.compare(pa, pb);
                }
                return ((String) a.get("name")).compareTo((String) b.get("name"));
            });

            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("programPath", programPath);
            result.put("count", analyzers.size());
            result.put("analyzers", analyzers);
            return createJsonResult(result);
        });
    }

    /**
     * Read the registered sub-options for an analyzer (the keys nested under the analyzer's
     * namespace in {@link Program#ANALYSIS_PROPERTIES}). Uses type-aware reads so non-boolean
     * sub-options surface correctly; falls back to {@code getValueAsString} for unknown types.
     */
    private List<Map<String, Object>> collectAnalyzerSubOptions(Options analysisOpts,
            String analyzerName) {
        List<Map<String, Object>> subOptions = new ArrayList<>();
        Options subOpts;
        try {
            subOpts = analysisOpts.getOptions(analyzerName);
        } catch (Exception e) {
            return subOptions;
        }
        if (subOpts == null) {
            return subOptions;
        }
        for (String optName : subOpts.getOptionNames()) {
            OptionType type;
            try {
                type = subOpts.getType(optName);
            } catch (Exception e) {
                continue;
            }
            Object value;
            try {
                switch (type) {
                    case BOOLEAN_TYPE -> value = subOpts.getBoolean(optName, false);
                    case INT_TYPE -> value = subOpts.getInt(optName, 0);
                    case LONG_TYPE -> value = subOpts.getLong(optName, 0L);
                    case DOUBLE_TYPE -> value = subOpts.getDouble(optName, 0.0);
                    case FLOAT_TYPE -> value = subOpts.getFloat(optName, 0.0f);
                    case STRING_TYPE -> value = subOpts.getString(optName, null);
                    default -> value = subOpts.getValueAsString(optName);
                }
            } catch (Exception e) {
                value = null;
            }

            String description;
            try {
                description = subOpts.getDescription(optName);
            } catch (Exception e) {
                description = null;
            }

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", optName);
            entry.put("type", type.name());
            entry.put("value", value);
            if (description != null && !description.isBlank()) {
                entry.put("description", description);
            }
            subOptions.add(entry);
        }
        return subOptions;
    }

    /**
     * Register a tool to change the processor architecture of an existing program
     */
    private void registerChangeProcessorTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty(
            "Path to the program to modify (e.g., '/Hatchery.exe')"
        ));
        properties.put("languageId", SchemaUtil.stringProperty(
            "Language ID for the new processor (e.g., 'x86:LE:64:default')"
        ));
        properties.put("compilerSpecId", SchemaUtil.stringProperty(
            "Compiler spec ID (optional, defaults to the language's default)"
        ));

        List<String> required = List.of("programPath", "languageId");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("change-processor")
            .title("Change Processor")
            .description("Change the processor architecture of an existing program")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get parameters
            String languageId;
            try {
                languageId = getString(request, "languageId");
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            }

            String compilerSpecId = getOptionalString(request, "compilerSpecId", null);

            // Get the program
            Program program;
            try {
                program = getProgramFromArgs(request);
            } catch (Exception e) {
                return createErrorResult(e.getMessage());
            }

            String programPath = program.getDomainFile().getPathname();

            try {
                // Get the language service
                LanguageService languageService = DefaultLanguageService.getLanguageService();

                // Parse the language ID
                LanguageID langId = new LanguageID(languageId);
                Language language = languageService.getLanguage(langId);

                // Get compiler spec
                CompilerSpec compilerSpec;
                if (compilerSpecId != null && !compilerSpecId.trim().isEmpty()) {
                    CompilerSpecID specId = new CompilerSpecID(compilerSpecId);
                    compilerSpec = language.getCompilerSpecByID(specId);
                } else {
                    compilerSpec = language.getDefaultCompilerSpec();
                }

                // Create language compiler spec pair
                LanguageCompilerSpecPair lcsPair = new LanguageCompilerSpecPair(langId, compilerSpec.getCompilerSpecID());

                // Capture old language before changing
                String oldLanguageId = program.getLanguage().getLanguageID().getIdAsString();

                // Change the processor
                int transactionID = program.startTransaction("Change processor architecture");
                try {
                    program.setLanguage(lcsPair.getLanguage(), lcsPair.getCompilerSpecID(), false, TaskMonitor.DUMMY);
                    program.endTransaction(transactionID, true);
                } catch (Exception e) {
                    program.endTransaction(transactionID, false);
                    throw e;
                }

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("programPath", programPath);
                result.put("oldLanguage", oldLanguageId);
                result.put("newLanguage", languageId);
                result.put("newCompilerSpec", compilerSpec.getCompilerSpecID().getIdAsString());
                result.put("message", "Processor architecture changed successfully");

                return createJsonResult(result);

            } catch (LanguageNotFoundException e) {
                return createErrorResult("Language not found: " + languageId);
            } catch (Exception e) {
                return createErrorResult("Failed to change processor architecture: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to import files into the Ghidra project
     */
    private void registerImportFileTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();

        // path parameter (required)
        // Note: The MCP client and Ghidra may have different working directories,
        // so absolute paths are recommended for reliable file resolution
        Map<String, Object> pathProperty = new HashMap<>();
        pathProperty.put("type", "string");
        pathProperty.put("description", "Absolute file system path to import (file, directory, or archive). Use absolute paths to ensure proper file resolution as the MCP client and Ghidra may have different working directories.");
        properties.put("path", pathProperty);

        // destinationFolder parameter (optional)
        Map<String, Object> destFolderProperty = new HashMap<>();
        destFolderProperty.put("type", "string");
        destFolderProperty.put("description", "Project folder path for imported files (default: root folder)");
        properties.put("destinationFolder", destFolderProperty);

        // recursive parameter (optional)
        Map<String, Object> recursiveProperty = new HashMap<>();
        recursiveProperty.put("type", "boolean");
        recursiveProperty.put("description", "Whether to recursively import from containers/archives (default: true)");
        properties.put("recursive", recursiveProperty);

        // maxDepth parameter (optional) - controlled by 'Import Max Depth' config setting
        Map<String, Object> maxDepthProperty = new HashMap<>();
        maxDepthProperty.put("type", "integer");
        maxDepthProperty.put("description", "Maximum container depth to recurse into (default: 10)");
        properties.put("maxDepth", maxDepthProperty);

        // analyzeAfterImport parameter (optional)
        Map<String, Object> analyzeProperty = new HashMap<>();
        analyzeProperty.put("type", "boolean");
        analyzeProperty.put("description",
            "Run auto-analysis on each imported program before returning (default: false). "
            + "Prefer leaving this off for LLM-driven workflows and calling analyze-program "
            + "explicitly so progress is reported and analyzer choices are visible.");
        properties.put("analyzeAfterImport", analyzeProperty);

        // stripLeadingPath parameter (optional)
        Map<String, Object> stripLeadingProperty = new HashMap<>();
        stripLeadingProperty.put("type", "boolean");
        stripLeadingProperty.put("description", "Omit the source file's leading path from imported file locations (default: true)");
        properties.put("stripLeadingPath", stripLeadingProperty);

        // stripAllContainerPath parameter (optional)
        Map<String, Object> stripContainerProperty = new HashMap<>();
        stripContainerProperty.put("type", "boolean");
        stripContainerProperty.put("description", "Completely flatten container paths in imported file locations (default: false)");
        properties.put("stripAllContainerPath", stripContainerProperty);

        // mirrorFs parameter (optional)
        Map<String, Object> mirrorFsProperty = new HashMap<>();
        mirrorFsProperty.put("type", "boolean");
        mirrorFsProperty.put("description", "Mirror the filesystem layout when importing (default: false)");
        properties.put("mirrorFs", mirrorFsProperty);

        // enableVersionControl parameter (optional)
        Map<String, Object> versionControlProperty = new HashMap<>();
        versionControlProperty.put("type", "boolean");
        versionControlProperty.put("description", "Automatically add imported files to version control (default: true)");
        properties.put("enableVersionControl", versionControlProperty);

        List<String> required = List.of("path");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("import-file")
            .title("Import File")
            .description(
                "Import files, directories, or archives into the Ghidra project using batch import. "
                + "By default this does NOT run auto-analysis; the response flags imported programs "
                + "with analyzed=false and analysisRecommended=true so callers know to follow up with "
                + "the analyze-program tool. Set analyzeAfterImport=true to bundle analysis into "
                + "the import call (slower, no per-analyzer progress).")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            try {
                // Get required parameter
                String path = getString(request, "path");

                // Get configuration for defaults
                ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
                boolean defaultAnalyze = configManager != null ? configManager.isWaitForAnalysisOnImport() : true;
                int defaultMaxDepth = configManager != null ? configManager.getImportMaxDepth() : 10;

                // Get optional parameters with defaults
                String destinationFolder = getOptionalString(request, "destinationFolder", "/");
                boolean recursive = getOptionalBoolean(request, "recursive", true);
                int maxDepth = getOptionalInt(request, "maxDepth", defaultMaxDepth);
                boolean analyzeAfterImport = getOptionalBoolean(request, "analyzeAfterImport", defaultAnalyze);
                boolean enableVersionControl = getOptionalBoolean(request, "enableVersionControl", true);
                boolean stripLeadingPath = getOptionalBoolean(request, "stripLeadingPath", true);
                boolean stripAllContainerPath = getOptionalBoolean(request, "stripAllContainerPath", false);
                boolean mirrorFs = getOptionalBoolean(request, "mirrorFs", false);

                // Validate file exists
                File file = new File(path);
                if (!file.exists()) {
                    return createErrorResult("File or directory does not exist: " + path);
                }

                // Get the active project
                Project project = AppInfo.getActiveProject();
                if (project == null) {
                    return createErrorResult("No active project found");
                }

                // Get destination folder
                DomainFolder destFolder;
                if (destinationFolder.equals("/")) {
                    destFolder = project.getProjectData().getRootFolder();
                } else {
                    destFolder = project.getProjectData().getFolder(destinationFolder);
                    if (destFolder == null) {
                        return createErrorResult("Destination folder not found: " + destinationFolder);
                    }
                }

                // Create BatchInfo with specified max depth
                BatchInfo batchInfo = new BatchInfo(recursive ? maxDepth : 1);

                // Convert file to FSRL and add to batch
                FSRL fsrl = FileSystemService.getInstance().getLocalFSRL(file);
                boolean hasImportableFiles = batchInfo.addFile(fsrl, TaskMonitor.DUMMY);

                if (!hasImportableFiles) {
                    return createErrorResult("No importable files found in: " + path);
                }

                // Check if any files were actually discovered
                if (batchInfo.getTotalCount() == 0) {
                    return createErrorResult("No supported file formats found in: " + path);
                }

                // Use configuration for timeouts
                int importTimeoutSeconds = configManager != null ?
                    configManager.getImportTimeoutSeconds() : 120; // Dedicated import timeout or 2 min default
                int analysisTimeoutSeconds = configManager != null ?
                    configManager.getImportAnalysisTimeoutSeconds() : 600; // Default 10 minutes

                // Create timeout-protected monitor for import operations
                TaskMonitor importMonitor = TimeoutTaskMonitor.timeoutIn(importTimeoutSeconds, TimeUnit.SECONDS);

                // Track imported files with accurate DomainFile references
                List<DomainFile> importedDomainFiles = new ArrayList<>();
                List<String> importedProgramPaths = new ArrayList<>();
                List<Map<String, Object>> detailedErrors = new ArrayList<>();

                // Progress tracking
                int totalFiles = batchInfo.getTotalCount();
                int processedFiles = 0;
                String progressToken = "import-" + System.currentTimeMillis();

                // Send initial progress notification
                if (exchange != null) {
                    exchange.progressNotification(new McpSchema.ProgressNotification(
                        progressToken, 0.0, (double) totalFiles,
                        "Starting import of " + totalFiles + " file(s) from " + path + "..."));
                }

                // Custom import loop - replaces ImportBatchTask to capture actual imported files
                int enabledGroups = 0;
                int skippedGroups = 0;
                importLoop:
                for (BatchGroup group : batchInfo.getGroups()) {
                    // Check for cancellation at the start of each group
                    if (importMonitor.isCancelled()) {
                        break importLoop;
                    }

                    // Check if group is enabled (has valid load spec selected)
                    if (!group.isEnabled()) {
                        skippedGroups++;
                        Msg.debug(this, "Skipping disabled batch group: " + group.getCriteria());
                        continue;
                    }
                    enabledGroups++;

                    BatchGroupLoadSpec selectedBatchGroupLoadSpec = group.getSelectedBatchGroupLoadSpec();
                    if (selectedBatchGroupLoadSpec == null) {
                        detailedErrors.add(Map.of(
                            "stage", "discovery",
                            "error", "Enabled group has no selected load spec",
                            "errorType", "ConfigurationError",
                            "details", group.getCriteria().toString()
                        ));
                        continue;
                    }

                    for (BatchLoadConfig config : group.getBatchLoadConfig()) {
                        if (importMonitor.isCancelled()) {
                            break importLoop;
                        }

                        try (ByteProvider byteProvider = FileSystemService.getInstance()
                                .getByteProvider(config.getFSRL(), true, importMonitor)) {

                            LoadSpec loadSpec = config.getLoadSpec(selectedBatchGroupLoadSpec);
                            if (loadSpec == null) {
                                detailedErrors.add(Map.of(
                                    "stage", "import",
                                    "sourceFSRL", config.getFSRL().toString(),
                                    "preferredName", config.getPreferredFileName(),
                                    "error", "No load spec matches selected batch group load spec",
                                    "errorType", "LoadSpecError"
                                ));
                                processedFiles++;
                                continue;
                            }

                            // Compute destination path using Ghidra's path handling logic
                            // Handle null UASI by falling back to the config's FSRL
                            FSRL uasiFsrl = (config.getUasi() != null) ? config.getUasi().getFSRL() : config.getFSRL();
                            String pathStr = fsrlToPath(config.getFSRL(),
                                uasiFsrl, stripLeadingPath, stripAllContainerPath);

                            // Sanitize the filename to replace invalid characters with underscores
                            String sanitizedPath = fixupProjectFilename(pathStr);

                            // Create settings record for Ghidra 12.0+ API
                            MessageLog log = new MessageLog();
                            Loader.ImporterSettings settings = new Loader.ImporterSettings(
                                byteProvider,
                                sanitizedPath,
                                project,
                                destFolder.getPathname(),
                                mirrorFs,
                                loadSpec,
                                loadSpec.getLoader().getDefaultOptions(byteProvider, loadSpec, null, false, mirrorFs),
                                this,
                                log,
                                importMonitor
                            );

                            // Load and save - capture each DomainFile
                            try (LoadResults<?> loadResults = loadSpec.getLoader().load(settings)) {
                                if (loadResults == null) {
                                    detailedErrors.add(Map.of(
                                        "stage", "import",
                                        "sourceFSRL", config.getFSRL().toString(),
                                        "preferredName", config.getPreferredFileName(),
                                        "error", "Loader returned null results",
                                        "errorType", "LoaderError"
                                    ));
                                    processedFiles++;
                                    continue;
                                }

                                // CRITICAL: Save each loaded object and capture DomainFile
                                for (Loaded<?> loaded : loadResults) {
                                    DomainFile savedFile = loaded.save(importMonitor);
                                    importedDomainFiles.add(savedFile);
                                    importedProgramPaths.add(savedFile.getPathname());
                                    Msg.info(this, "Imported: " + config.getFSRL() + " -> " + savedFile.getPathname());
                                }

                                // Track progress per source file and send notification
                                processedFiles++;
                                if (exchange != null) {
                                    // Progress tracks source files, but message shows total imported files
                                    String progressMsg = String.format("Processed %d/%d sources (%d files imported): %s",
                                        processedFiles, totalFiles, importedDomainFiles.size(), config.getPreferredFileName());
                                    exchange.progressNotification(new McpSchema.ProgressNotification(
                                        progressToken, (double) processedFiles, (double) totalFiles, progressMsg));
                                }

                                if (log.hasMessages()) {
                                    Msg.info(this, "Import log for " + config.getFSRL() + ": " + log.toString());
                                }
                            }
                        } catch (Exception e) {
                            detailedErrors.add(Map.of(
                                "stage", "import",
                                "sourceFSRL", config.getFSRL().toString(),
                                "preferredName", config.getPreferredFileName(),
                                "error", Objects.requireNonNullElse(e.getMessage(), e.toString()),
                                "errorType", e.getClass().getSimpleName()
                            ));
                            processedFiles++;
                            Msg.error(this, "Import failed for " + config.getFSRL(), e);
                        }
                    }
                }

                // Check for timeout
                if (importMonitor.isCancelled() && importedDomainFiles.isEmpty()) {
                    return createErrorResult("Import timed out after " + importTimeoutSeconds + " seconds. " +
                        "Try importing fewer files or increase timeout in ReVa configuration.");
                }

                // Report if no groups were enabled for import
                if (enabledGroups == 0 && importedDomainFiles.isEmpty()) {
                    detailedErrors.add(Map.of(
                        "stage", "discovery",
                        "error", "No enabled batch groups found",
                        "errorType", "NoImportableFiles",
                        "filesDiscovered", batchInfo.getTotalCount(),
                        "groupsCreated", batchInfo.getGroups().size(),
                        "skippedGroups", skippedGroups
                    ));
                }

                // Track version control and analysis results
                List<String> versionedFiles = new ArrayList<>();
                List<String> analyzedFiles = new ArrayList<>();

                // Process imported files: analyze if requested, then add to version control
                // Use the tracked importedDomainFiles list for accurate processing
                if ((enableVersionControl || analyzeAfterImport) && !importedDomainFiles.isEmpty()) {
                    int totalFilesToProcess = importedDomainFiles.size();

                    for (int fileIndex = 0; fileIndex < totalFilesToProcess; fileIndex++) {
                        DomainFile domainFile = importedDomainFiles.get(fileIndex);

                        // Create per-file timeout to ensure each file gets equal treatment
                        TaskMonitor postMonitor = TimeoutTaskMonitor.timeoutIn(analysisTimeoutSeconds, TimeUnit.SECONDS);

                        if (postMonitor.isCancelled()) {
                            // Record timeout error and skipped files
                            detailedErrors.add(Map.of(
                                "stage", "postProcessing",
                                "error", "Post-processing timed out",
                                "errorType", "TimeoutError"
                            ));

                            // Record individual timeout/skip error for each remaining file
                            for (int j = fileIndex; j < totalFilesToProcess; j++) {
                                DomainFile remainingFile = importedDomainFiles.get(j);
                                detailedErrors.add(Map.of(
                                    "stage", "postProcessing",
                                    "programPath", remainingFile.getPathname(),
                                    "error", "Post-processing skipped due to prior timeout",
                                    "errorType", "TimeoutError"
                                ));
                            }
                            break;
                        }

                        try {
                            // Run analysis if requested
                            if (analyzeAfterImport && domainFile.getContentType().equals("Program")) {
                                DomainObject domainObject = null;
                                try {
                                    // IMPORTANT: okToRecover (3rd param) must be TRUE. If false, getDomainObject()
                                    // returns null for programs that aren't already open, silently skipping analysis.
                                    domainObject = domainFile.getDomainObject(this, false, true, postMonitor);
                                    if (domainObject instanceof Program program) {
                                        TaskMonitor analysisMonitor =
                                            TimeoutTaskMonitor.timeoutIn(analysisTimeoutSeconds, TimeUnit.SECONDS);
                                        try {
                                            boolean completed =
                                                runFullAnalysisAfterImport(program, analysisMonitor);
                                            if (completed) {
                                                program.save("Analysis completed via ReVa import", postMonitor);
                                                analyzedFiles.add(domainFile.getPathname());
                                            } else {
                                                detailedErrors.add(Map.of(
                                                    "stage", "analysis",
                                                    "programPath", domainFile.getPathname(),
                                                    "error", "Analysis timed out",
                                                    "errorType", "TimeoutError"
                                                ));
                                            }
                                        } catch (IllegalStateException e) {
                                            // AutoAnalysisManager unavailable; distinct from timeout.
                                            detailedErrors.add(Map.of(
                                                "stage", "analysis",
                                                "programPath", domainFile.getPathname(),
                                                "error", e.getMessage(),
                                                "errorType", "AnalysisSetupError"
                                            ));
                                        }
                                    }
                                } finally {
                                    // Always release the domain object to prevent resource leaks
                                    if (domainObject != null) {
                                        domainObject.release(this);
                                    }
                                }
                            }

                            // Add to version control if requested
                            if (enableVersionControl) {
                                if (domainFile.canAddToRepository()) {
                                    String vcMessage = analyzeAfterImport && analyzedFiles.contains(domainFile.getPathname())
                                        ? "Initial import via ReVa (analyzed)"
                                        : "Initial import via ReVa";
                                    // Second parameter false = check in immediately (don't keep checked out)
                                    domainFile.addToVersionControl(vcMessage, false, postMonitor);
                                    versionedFiles.add(domainFile.getPathname());
                                }
                            }
                        } catch (Exception e) {
                            detailedErrors.add(Map.of(
                                "stage", "postProcessing",
                                "programPath", domainFile.getPathname(),
                                "error", Objects.requireNonNullElse(e.getMessage(), e.toString()),
                                "errorType", e.getClass().getSimpleName()
                            ));
                        }
                    }
                }

                // Create result data (omit echo-back of input config to keep response concise)
                Map<String, Object> result = new HashMap<>();
                result.put("success", !importedDomainFiles.isEmpty());
                result.put("importedFrom", path);
                result.put("destinationFolder", destinationFolder);
                result.put("filesDiscovered", batchInfo.getTotalCount());
                result.put("filesImported", importedDomainFiles.size());
                result.put("importedPrograms", importedProgramPaths);

                if (enableVersionControl && !versionedFiles.isEmpty()) {
                    result.put("filesAddedToVersionControl", versionedFiles.size());
                    result.put("versionedPrograms", versionedFiles);
                }

                if (analyzeAfterImport && !analyzedFiles.isEmpty()) {
                    result.put("filesAnalyzed", analyzedFiles.size());
                    result.put("analyzedPrograms", analyzedFiles);
                }

                // Per-program detail with analysis hints so LLMs know what to do next.
                if (!importedProgramPaths.isEmpty()) {
                    List<Map<String, Object>> programs = new ArrayList<>();
                    for (String importedPath : importedProgramPaths) {
                        Map<String, Object> entry = new LinkedHashMap<>();
                        entry.put("programPath", importedPath);
                        boolean wasAnalyzed = analyzedFiles.contains(importedPath);
                        entry.put("analyzed", wasAnalyzed);
                        if (!wasAnalyzed) {
                            entry.put("analysisRecommended", true);
                            entry.put("nextSteps",
                                "Call analyze-program with programPath '" + importedPath
                                + "' to populate functions, strings, and references.");
                        }
                        programs.add(entry);
                    }
                    result.put("programs", programs);
                }

                // Include detailed error information
                if (!detailedErrors.isEmpty()) {
                    result.put("errors", detailedErrors);
                    result.put("errorCount", detailedErrors.size());

                    // Build error summary by stage
                    Map<String, Long> errorsByStage = new HashMap<>();
                    for (Map<String, Object> error : detailedErrors) {
                        String stage = (String) error.getOrDefault("stage", "unknown");
                        errorsByStage.merge(stage, 1L, Long::sum);
                    }
                    StringBuilder summary = new StringBuilder();
                    summary.append(detailedErrors.size()).append(" error(s): ");
                    boolean first = true;
                    for (Map.Entry<String, Long> entry : errorsByStage.entrySet()) {
                        if (!first) summary.append(", ");
                        summary.append(entry.getValue()).append(" during ").append(entry.getKey());
                        first = false;
                    }
                    result.put("errorSummary", summary.toString());
                }

                // Build completion message
                String message = "Import completed. " + importedDomainFiles.size() + " of " +
                    batchInfo.getTotalCount() + " files imported";
                if (analyzeAfterImport && analyzedFiles.size() > 0) {
                    message += ", " + analyzedFiles.size() + " analyzed";
                }
                if (enableVersionControl && versionedFiles.size() > 0) {
                    message += ", " + versionedFiles.size() + " added to version control";
                }
                if (!detailedErrors.isEmpty()) {
                    message += " (" + detailedErrors.size() + " error(s))";
                }
                message += ".";
                if (!importedDomainFiles.isEmpty() && !analyzeAfterImport) {
                    message += " Imported programs are not analyzed yet -- call analyze-program "
                        + "for each program to populate functions, strings, and references.";
                }
                result.put("message", message);

                // Send final progress notification
                if (exchange != null) {
                    exchange.progressNotification(new McpSchema.ProgressNotification(
                        progressToken, (double) totalFiles, (double) totalFiles,
                        message));
                }

                return createJsonResult(result);

            } catch (IllegalArgumentException e) {
                return createErrorResult("Invalid parameter: " + e.getMessage());
            } catch (Exception e) {
                return createErrorResult("Import failed: " + e.getMessage());
            }
        });
    }

    /**
     * Sanitizes a filename by replacing invalid characters with underscores.
     * This is a copy of ImportBatchTask.fixupProjectFilename which is private.
     * Copied from Ghidra 12.0 source - update if Ghidra's implementation changes.
     *
     * @param filename The filename to sanitize
     * @return The sanitized filename with invalid characters replaced by underscores
     */
    private String fixupProjectFilename(String filename) {
        // Replace any invalid characters with underscores
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < filename.length(); i++) {
            char ch = filename.charAt(i);
            sb.append(LocalFileSystem.isValidNameCharacter(ch) ? ch : '_');
        }
        return sb.toString();
    }

    /**
     * Convert a file's FSRL into a target project path, using import path options.
     * This is a copy of ImportBatchTask.fsrlToPath which is package-private.
     * Copied from Ghidra 12.0 source - update if Ghidra's implementation changes.
     * TODO: Consider requesting this method be made public in a future Ghidra release.
     *
     * @param fsrl FSRL of the file to convert
     * @param userSrc FSRL of the user-added source file
     * @param stripLeadingPath Whether to strip the leading path
     * @param stripInteriorContainerPath Whether to strip interior container paths
     * @return Path string for the project destination
     */
    private String fsrlToPath(FSRL fsrl, FSRL userSrc, boolean stripLeadingPath,
            boolean stripInteriorContainerPath) {

        String fullPath = fsrl.toPrettyFullpathString().replace('|', '/');
        String userSrcPath = userSrc.toPrettyFullpathString().replace('|', '/');
        int filename = fullPath.lastIndexOf('/') + 1;
        int uas = userSrcPath.length();

        int leadStart = !stripLeadingPath ? 0 : userSrcPath.lastIndexOf('/') + 1;
        int leadEnd = Math.min(filename, userSrcPath.length());
        String leading = (leadStart < filename) ? fullPath.substring(leadStart, leadEnd) : "";
        String containerPath = uas < filename && !stripInteriorContainerPath
                ? fullPath.substring(uas, filename)
                : "";
        String filenameStr = fullPath.substring(filename);
        String result = FSUtilities.appendPath(leading, containerPath, filenameStr);
        return result;
    }

    /**
     * Register a tool to capture ReVa debug information for troubleshooting.
     * Creates a zip file with system info, logs, configuration, and open programs.
     */
    private void registerCaptureDebugInfoTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("message", Map.of(
            "type", "string",
            "description", "Optional message describing the issue being debugged"
        ));

        List<String> required = new ArrayList<>();

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("capture-reva-debug-info")
            .title("Capture ReVa Debug Information")
            .description("Creates a zip file containing ReVa debug information for troubleshooting issues. " +
                "Includes system info, Ghidra config, ReVa settings, MCP server status, open programs, and logs.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            String message = getOptionalString(request, "message", null);

            try {
                DebugCaptureService debugService = new DebugCaptureService();
                File debugZip = debugService.captureDebugInfo(message);

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("debugZipPath", debugZip.getAbsolutePath());
                result.put("message", "Debug information captured to: " + debugZip.getAbsolutePath());

                return createJsonResult(result);
            } catch (Exception e) {
                return createErrorResult("Failed to capture debug info: " + e.getMessage());
            }
        });
    }

}