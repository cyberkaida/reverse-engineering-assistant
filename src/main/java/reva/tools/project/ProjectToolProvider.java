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
import ghidra.framework.data.DefaultCheckinHandler;
import ghidra.framework.model.DomainObject;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
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
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema;
import reva.debug.DebugCaptureService;
import reva.plugin.RevaProgramManager;
import reva.plugin.ConfigManager;
import reva.tools.AbstractToolProvider;
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

            // Create combined result
            List<Object> resultData = new ArrayList<>();
            resultData.add(metadataInfo);
            resultData.addAll(filesList);

            return createMultiJsonResult(resultData);
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

            // Create metadata
            Map<String, Object> metadataInfo = new HashMap<>();
            metadataInfo.put("count", programsData.size());

            // Create combined result
            List<Object> resultData = new ArrayList<>();
            resultData.add(metadataInfo);
            resultData.addAll(programsData);

            return createMultiJsonResult(resultData);
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
                // Save program first (required before version control operations)
                // Skip save for read-only programs (common in test environments)
                if (!domainFile.isReadOnly()) {
                    try {
                        program.save(message, TaskMonitor.DUMMY);
                        program.flushEvents();  // Ensure SAVED event is processed
                    } catch (java.io.IOException e) {
                        return createErrorResult("Failed to save program: " + e.getMessage());
                    }
                }

                // Release program from cache before version control operations
                // Version control requires no active consumers on the domain file
                boolean wasCached = RevaProgramManager.releaseProgramFromCache(program);
                if (wasCached) {
                    Msg.debug(this, "Released program from cache for version control: " + programPath);
                }

                if (domainFile.canAddToRepository()) {
                    // New file - add to version control
                    domainFile.addToVersionControl(message, !keepCheckedOut, TaskMonitor.DUMMY);

                    // Re-open program to cache if it was cached and we're keeping it checked out
                    if (wasCached && keepCheckedOut) {
                        Program reopenedProgram = RevaProgramManager.reopenProgramToCache(programPath);
                        if (reopenedProgram != null) {
                            Msg.debug(this, "Re-opened program to cache after version control: " + programPath);
                        }
                    }

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

                    // Re-open program to cache if it was cached and we're keeping it checked out
                    if (wasCached && keepCheckedOut) {
                        Program reopenedProgram = RevaProgramManager.reopenProgramToCache(programPath);
                        if (reopenedProgram != null) {
                            Msg.debug(this, "Re-opened program to cache after checkin: " + programPath);
                        }
                    }

                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("action", "checked_in");
                    result.put("programPath", programPath);
                    result.put("message", message);
                    result.put("keepCheckedOut", keepCheckedOut);
                    result.put("isVersioned", domainFile.isVersioned());
                    result.put("isCheckedOut", domainFile.isCheckedOut());

                    return createJsonResult(result);
                }
                else if (!domainFile.isVersioned()) {
                    // Not versioned - changes were already saved at the beginning
                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("action", "saved");
                    result.put("programPath", programPath);
                    result.put("message", message);
                    result.put("isVersioned", false);
                    result.put("info", "Program is not under version control - changes were saved instead");

                    return createJsonResult(result);
                }
                else {
                    // Other version control errors
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
                                // Get analysis manager
                                AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
                                if (analysisManager != null) {
                                    // Create timeout monitor for analysis
                                    TaskMonitor analysisMonitor = TimeoutTaskMonitor.timeoutIn(analysisTimeoutSeconds, TimeUnit.SECONDS);

                                    // Start analysis (async)
                                    analysisManager.startAnalysis(analysisMonitor);

                                    // Wait for completion with timeout
                                    analysisManager.waitForAnalysis(null, analysisMonitor);

                                    if (analysisMonitor.isCancelled()) {
                                        errors.add("Analysis timed out for " + file.getPathname() +
                                            " after " + analysisTimeoutSeconds + " seconds");
                                    } else {
                                        // Save program after analysis
                                        program.save("Auto-analysis complete", monitor);
                                        analyzedFiles.add(file.getPathname());
                                        wasAnalyzed = true;
                                    }
                                } else {
                                    errors.add("Could not get analysis manager for " + file.getPathname());
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
     * Register a tool to analyze a program with Ghidra's auto-analysis
     */
    private void registerAnalyzeProgramTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty(
            "Path to the program to analyze (e.g., '/Hatchery.exe')"
        ));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("analyze-program")
            .title("Analyze Program")
            .description("Run Ghidra's auto-analysis on a program")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get the program
            Program program;
            try {
                program = getProgramFromArgs(request);
            } catch (Exception e) {
                return createErrorResult(e.getMessage());
            }

            String programPath = program.getDomainFile().getPathname();

            try {
                // Get the auto-analysis manager
                AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
                if (analysisManager == null) {
                    return createErrorResult("Could not get analysis manager for program: " + programPath);
                }

                // Start analysis
                analysisManager.startAnalysis(TaskMonitor.DUMMY);

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("programPath", programPath);
                result.put("message", "Analysis started successfully");
                result.put("analysisRunning", analysisManager.isAnalyzing());

                return createJsonResult(result);

            } catch (Exception e) {
                return createErrorResult("Analysis failed: " + e.getMessage());
            }
        });
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
                result.put("oldLanguage", program.getLanguage().getLanguageID().getIdAsString());
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
        maxDepthProperty.put("description", "Maximum container depth to recurse into (default: controlled by 'Import Max Depth' config setting, which defaults to 10)");
        properties.put("maxDepth", maxDepthProperty);

        // analyzeAfterImport parameter (optional)
        Map<String, Object> analyzeProperty = new HashMap<>();
        analyzeProperty.put("type", "boolean");
        analyzeProperty.put("description", "Run auto-analysis after import (default: controlled by 'Wait For Analysis On Import' config setting, which defaults to true)");
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
            .description("Import files, directories, or archives into the Ghidra project using batch import")
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
                    configManager.getDecompilerTimeoutSeconds() * 2 : 300; // 2x decompiler timeout or 5 min default
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
                                    // IMPORTANT: okToOpen must be TRUE (third param). If false, getDomainObject()
                                    // returns null for programs that aren't already open, silently skipping analysis.
                                    domainObject = domainFile.getDomainObject(this, false, true, postMonitor);
                                    if (domainObject instanceof Program program) {
                                        AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
                                        if (analysisManager != null) {
                                            TaskMonitor analysisMonitor = TimeoutTaskMonitor.timeoutIn(analysisTimeoutSeconds, TimeUnit.SECONDS);
                                            analysisManager.startAnalysis(analysisMonitor);
                                            analysisManager.waitForAnalysis(null, analysisMonitor);

                                            if (!analysisMonitor.isCancelled()) {
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

                // Create result data
                Map<String, Object> result = new HashMap<>();
                result.put("success", !importedDomainFiles.isEmpty());
                result.put("importedFrom", path);
                result.put("destinationFolder", destinationFolder);
                result.put("filesDiscovered", batchInfo.getTotalCount());
                result.put("filesImported", importedDomainFiles.size());
                result.put("groupsCreated", batchInfo.getGroups().size());
                result.put("enabledGroups", enabledGroups);
                result.put("skippedGroups", skippedGroups);
                result.put("maxDepthUsed", maxDepth);
                result.put("wasRecursive", recursive);
                result.put("analyzeAfterImport", analyzeAfterImport);
                result.put("enableVersionControl", enableVersionControl);
                result.put("stripLeadingPath", stripLeadingPath);
                result.put("stripAllContainerPath", stripAllContainerPath);
                result.put("mirrorFs", mirrorFs);
                result.put("importedPrograms", importedProgramPaths);

                if (enableVersionControl) {
                    result.put("filesAddedToVersionControl", versionedFiles.size());
                    result.put("versionedPrograms", versionedFiles);
                }

                if (analyzeAfterImport) {
                    result.put("filesAnalyzed", analyzedFiles.size());
                    result.put("analyzedPrograms", analyzedFiles);
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
                result.put("message", message + ".");

                // Send final progress notification
                if (exchange != null) {
                    exchange.progressNotification(new McpSchema.ProgressNotification(
                        progressToken, (double) totalFiles, (double) totalFiles,
                        message + "."));
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