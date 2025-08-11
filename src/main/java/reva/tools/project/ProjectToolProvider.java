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
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.LoadException;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemRef;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.framework.data.DefaultCheckinHandler;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.InvalidNameException;
import ghidra.util.task.TaskMonitor;
import ghidra.base.project.GhidraProject;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.RevaProgramManager;
import reva.tools.AbstractToolProvider;
import reva.tools.ProgramValidationException;
import reva.util.SchemaUtil;

/**
 * Tool provider for project-related operations.
 * Provides tools to get the current program, list project files, and perform version control operations.
 */
public class ProjectToolProvider extends AbstractToolProvider {

    /**
     * Constructor
     * @param server The MCP server
     */
    public ProjectToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() throws McpError {
        registerGetCurrentProgramTool();
        registerListProjectFilesTool();
        registerListOpenProgramsTool();
        registerCheckinProgramTool();
        registerLoadBinaryTool();
        registerChangeProcessorTool();
        registerAnalyzeProgramTool();
    }

    /**
     * Register a tool to get the currently active program
     * @throws McpError if there's an error registering the tool
     */
    private void registerGetCurrentProgramTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();

        // This tool doesn't require any parameters

        List<String> required = new ArrayList<>();

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-current-program")
            .title("Get Current Program")
            .description("Get the currently active program in Ghidra with detailed metadata including analysis status. Returns 'isAnalyzed' flag indicating whether Ghidra's auto-analysis has been run. Unanalyzed programs will have limited function discovery, minimal string detection, and basic symbol information. If you encounter limited results when working with this program's functions, strings, or data structures, use the 'analyze-program' tool to improve the available information.")
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
            programInfo.put("programPath", RevaProgramManager.getCanonicalProgramPath(program));
            programInfo.put("language", program.getLanguage().getLanguageID().getIdAsString());
            programInfo.put("compilerSpec", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
            programInfo.put("creationDate", program.getCreationDate());
            programInfo.put("sizeBytes", program.getMemory().getSize());
            programInfo.put("symbolCount", program.getSymbolTable().getNumSymbols());
            programInfo.put("functionCount", program.getFunctionManager().getFunctionCount());
            programInfo.put("modificationDate", program.getDomainFile().getLastModifiedTime());
            programInfo.put("isReadOnly", program.getDomainFile().isReadOnly());
            programInfo.put("isAnalyzed", GhidraProgramUtilities.isAnalyzed(program));

            return createJsonResult(programInfo);
        });
    }

    /**
     * Register a tool to list files and folders in the Ghidra project
     * @throws McpError if there's an error registering the tool
     */
    private void registerListProjectFilesTool() throws McpError {
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
     * @throws McpError if there's an error registering the tool
     */
    private void registerListOpenProgramsTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();

        // This tool doesn't require any parameters
        List<String> required = new ArrayList<>();

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-open-programs")
            .title("List Open Programs")
            .description("List all programs currently open in Ghidra across all tools with detailed metadata including analysis status. Each program includes an 'isAnalyzed' flag indicating whether Ghidra's auto-analysis has been run. Unanalyzed programs will have limited function discovery, minimal string detection, and basic symbol information. If you encounter limited results when working with a specific program's functions, strings, or data structures, use the 'analyze-program' tool on that program to improve the available information.")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get all open programs
            List<Program> openPrograms = RevaProgramManager.getOpenPrograms();

            if (openPrograms.isEmpty()) {
                return createErrorResult("No programs are currently open in Ghidra");
            }

            // Create result data
            List<Map<String, Object>> programsData = new ArrayList<>();

            for (Program program : openPrograms) {
                Map<String, Object> programInfo = new HashMap<>();
                programInfo.put("programPath", RevaProgramManager.getCanonicalProgramPath(program));
                programInfo.put("language", program.getLanguage().getLanguageID().getIdAsString());
                programInfo.put("compilerSpec", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
                programInfo.put("creationDate", program.getCreationDate());
                programInfo.put("sizeBytes", program.getMemory().getSize());
                programInfo.put("functionCount", program.getFunctionManager().getFunctionCount());
                programInfo.put("symbolCount", program.getSymbolTable().getNumSymbols());
                programInfo.put("modificationDate", program.getDomainFile().getLastModifiedTime());
                programInfo.put("isReadOnly", program.getDomainFile().isReadOnly());
                programInfo.put("isAnalyzed", GhidraProgramUtilities.isAnalyzed(program));

                programsData.add(programInfo);
            }

            // Create metadata about the result
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
     * @throws McpError if there's an error registering the tool
     */
    private void registerCheckinProgramTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty(
            "Path in the Ghidra Project to the program to checkin"
        ));
        properties.put("message", SchemaUtil.stringProperty(
            "Commit message describing the changes being checked in"
        ));
        properties.put("keepCheckedOut", SchemaUtil.booleanPropertyWithDefault(
            "Whether to keep the program checked out after commit", true
        ));

        List<String> required = List.of("programPath", "message");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("checkin-program")
            .title("Check In Program")
            .description("Check in (commit) a program to version control with a message")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get the validated program using the standard helper
            Program program = getProgramFromArgs(request);
            
            // Get the message parameter
            String message;
            try {
                message = getString(request, "message");
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            }

            boolean keepCheckedOut = getOptionalBoolean(request, "keepCheckedOut", true);
            
            // Get the program path for result reporting
            String programPath = RevaProgramManager.getCanonicalProgramPath(program);
            DomainFile domainFile = program.getDomainFile();

            try {
                // Handle new files vs. existing versioned files
                if (domainFile.canAddToRepository()) {
                    // This is a new file that needs to be added to version control
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
                    // This is an existing versioned file that can be checked in
                    DefaultCheckinHandler checkinHandler = new DefaultCheckinHandler(message + "\n💜🐉✨ (ReVa)", keepCheckedOut, false);
                    domainFile.checkin(checkinHandler, TaskMonitor.DUMMY);

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
                else {
                    // Cannot checkin - determine why
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
                }

            } catch (IOException e) {
                return createErrorResult("IO error during checkin: " + e.getMessage());
            } catch (VersionException e) {
                return createErrorResult("Version control error: " + e.getMessage());
            } catch (CancelledException e) {
                return createErrorResult("Checkin operation was cancelled");
            } catch (Exception e) {
                return createErrorResult("Unexpected error during checkin: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to load a binary file from disk into the Ghidra project
     * @throws McpError if there's an error registering the tool
     */
    private void registerLoadBinaryTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("filePath", SchemaUtil.stringProperty(
            "Path to the binary file on disk to import"
        ));
        properties.put("projectPath", SchemaUtil.stringPropertyWithDefault(
            "Where to save the program in the project (default: /)", "/"
        ));
        properties.put("processorSpec", SchemaUtil.stringProperty(
            "Optional processor/compiler spec (e.g., 'x86:LE:64:default', 'golang:BE:64:default'). If not specified, Ghidra will auto-detect."
        ));
        properties.put("runAnalysis", SchemaUtil.booleanPropertyWithDefault(
            "Whether to run auto-analysis after loading", true
        ));
        properties.put("openProgram", SchemaUtil.booleanPropertyWithDefault(
            "Whether to open the program after loading", true
        ));
        properties.put("includePatterns", SchemaUtil.stringArrayProperty(
            "Optional list of glob patterns to include files from archives (e.g., ['*.exe', '*.dll'])"
        ));
        properties.put("excludePatterns", SchemaUtil.stringArrayProperty(
            "Optional list of glob patterns to exclude files from archives (e.g., ['*.txt', '*.md'])"
        ));
        properties.put("maxDepth", SchemaUtil.integerPropertyWithDefault(
            "Maximum recursion depth for nested archives", 10
        ));
        properties.put("autoImportThreshold", SchemaUtil.integerPropertyWithDefault(
            "Maximum number of files to auto-import without listing", 5
        ));
        properties.put("listOnly", SchemaUtil.booleanPropertyWithDefault(
            "Only list archive contents without importing", false
        ));

        List<String> required = List.of("filePath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("load-binary")
            .title("Load Binary File or Archive")
            .description("Load a binary file or archive from disk into the Ghidra project. Supports archives (ZIP, TAR, etc.) with automatic detection, selective import using glob patterns, and recursive processing. If an archive contains more files than autoImportThreshold, returns a listing for manual selection unless patterns are specified.")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get parameters
            String filePath;
            try {
                filePath = getString(request, "filePath");
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            }

            String projectPath = getOptionalString(request, "projectPath", "/");
            String processorSpec = getOptionalString(request, "processorSpec", null);
            boolean runAnalysis = getOptionalBoolean(request, "runAnalysis", true);
            boolean openProgram = getOptionalBoolean(request, "openProgram", true);
            List<String> includePatterns = getOptionalStringList(request.arguments(), "includePatterns", List.of());
            List<String> excludePatterns = getOptionalStringList(request.arguments(), "excludePatterns", List.of());
            int maxDepth = getOptionalInt(request, "maxDepth", 10);
            int autoImportThreshold = getOptionalInt(request, "autoImportThreshold", 5);
            boolean listOnly = getOptionalBoolean(request, "listOnly", false);

            // Get the active project
            Project project = AppInfo.getActiveProject();
            if (project == null) {
                return createErrorResult("No active project found");
            }

            // Verify the path exists
            File targetPath = new File(filePath);
            if (!targetPath.exists()) {
                return createErrorResult("File not found: " + filePath);
            }

            // Handle directories and archives
            if (targetPath.isDirectory()) {
                Map<String, Object> directoryResult = handleDirectoryImport(targetPath, project, projectPath, includePatterns, excludePatterns, 
                    maxDepth, autoImportThreshold, listOnly, runAnalysis, openProgram);
                return createJsonResult(directoryResult);
            }

            // Check if it's an archive file (not a binary executable)
            try {
                String fileName = targetPath.getName().toLowerCase();
                boolean isLikelyArchive = fileName.endsWith(".zip") || fileName.endsWith(".tar") || 
                                         fileName.endsWith(".gz") || fileName.endsWith(".7z") ||
                                         fileName.endsWith(".rar") || fileName.endsWith(".jar");
                                         
                if (isLikelyArchive) {
                    FSRL fsrl = FSRL.fromString("file://" + targetPath.getAbsolutePath());
                    if (FileSystemService.getInstance().isFileFilesystemContainer(fsrl, TaskMonitor.DUMMY)) {
                        Map<String, Object> archiveResult = handleArchiveImport(fsrl, project, projectPath, includePatterns, excludePatterns, 
                            maxDepth, autoImportThreshold, listOnly, runAnalysis, openProgram);
                        return createJsonResult(archiveResult);
                    }
                }
            } catch (Exception e) {
                // Not an archive or error detecting, continue with regular file import
            }

            // Regular file import - preserve existing logic
            if (!targetPath.isFile()) {
                return createErrorResult("Path is not a file: " + filePath);
            }

            try {
                // Create a message log for import messages
                MessageLog messageLog = new MessageLog();
                
                // Parse processor spec if provided
                Language language = null;
                CompilerSpec compilerSpec = null;
                if (processorSpec != null && !processorSpec.isEmpty()) {
                    try {
                        LanguageService languageService = DefaultLanguageService.getLanguageService();
                        LanguageCompilerSpecPair lcsPair = parseProcessorSpec(processorSpec, languageService);
                        if (lcsPair != null) {
                            language = languageService.getLanguage(lcsPair.getLanguageID());
                            compilerSpec = language.getCompilerSpecByID(lcsPair.getCompilerSpecID());
                        } else {
                            return createErrorResult("Invalid processor spec: " + processorSpec);
                        }
                    } catch (Exception e) {
                        return createErrorResult("Invalid processor spec: " + e.getMessage());
                    }
                }

                // Import the binary
                LoadResults<Program> loadResults;
                if (language != null && compilerSpec != null) {
                    // Import with specific language/compiler
                    loadResults = AutoImporter.importByLookingForLcs(
                        targetPath, project, projectPath, language, compilerSpec,
                        this, messageLog, TaskMonitor.DUMMY);
                } else {
                    // Auto-detect format and language
                    loadResults = AutoImporter.importByUsingBestGuess(
                        targetPath, project, projectPath, this, messageLog, TaskMonitor.DUMMY);
                }

                // Check if import succeeded
                if (loadResults == null || loadResults.size() == 0) {
                    String errorMsg = "Failed to import binary: " + targetPath.getName();
                    if (messageLog.hasMessages()) {
                        errorMsg += "\n" + messageLog.toString();
                    }
                    return createErrorResult(errorMsg);
                }

                // Get the primary imported program
                Loaded<Program> primaryLoaded = loadResults.getPrimary();
                Program program = primaryLoaded.getDomainObject();

                // Save the program to the project
                DomainFolder folder;
                if (projectPath.equals("/")) {
                    folder = project.getProjectData().getRootFolder();
                } else {
                    folder = project.getProjectData().getFolder(projectPath);
                    if (folder == null) {
                        // Create folder if it doesn't exist, removing leading slash for createFolder
                        String folderPath = projectPath.startsWith("/") ? projectPath.substring(1) : projectPath;
                        folder = project.getProjectData().getRootFolder().createFolder(folderPath);
                    }
                }

                // Save the program
                loadResults.save(project, this, messageLog, TaskMonitor.DUMMY);

                // Run auto-analysis if requested
                if (runAnalysis) {
                    int transactionID = program.startTransaction("Auto-analysis during binary load");
                    try {
                        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
                        mgr.initializeOptions();
                        mgr.reAnalyzeAll(null);
                        mgr.startAnalysis(TaskMonitor.DUMMY);
                        program.endTransaction(transactionID, true);
                    } catch (Exception e) {
                        program.endTransaction(transactionID, false);
                        throw e;
                    }
                }

                // Open the program if requested
                if (openProgram) {
                    openProgramInTool(program);
                }

                // Register the program with RevaProgramManager for MCP access
                RevaProgramManager.registerProgram(program);

                // Create result data
                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("programName", program.getName());
                result.put("programPath", RevaProgramManager.getCanonicalProgramPath(program));
                result.put("language", program.getLanguage().getLanguageID().getIdAsString());
                result.put("compilerSpec", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
                result.put("executable", program.getExecutablePath());
                result.put("sizeBytes", program.getMemory().getSize());
                result.put("analysisRun", runAnalysis);
                result.put("programOpened", openProgram);

                if (messageLog.hasMessages()) {
                    result.put("importMessages", messageLog.toString());
                }

                // Don't release the program since we want to keep it open
                return createJsonResult(result);

            } catch (CancelledException e) {
                return createErrorResult("Import was cancelled");
            } catch (DuplicateNameException e) {
                return createErrorResult("A program with this name already exists: " + e.getMessage());
            } catch (InvalidNameException e) {
                return createErrorResult("Invalid program name: " + e.getMessage());
            } catch (VersionException e) {
                return createErrorResult("Version error during import: " + e.getMessage());
            } catch (IOException e) {
                return createErrorResult("IO error during import: " + e.getMessage());
            } catch (Exception e) {
                return createErrorResult("Unexpected error during import: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to change the processor architecture of an existing program
     * @throws McpError if there's an error registering the tool
     */
    private void registerChangeProcessorTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty(
            "Path to the program in the project (or 'current' for current program)"
        ));
        properties.put("processorSpec", SchemaUtil.stringProperty(
            "New processor/compiler spec (e.g., 'x86:LE:64:default', 'golang:BE:64:default')"
        ));

        List<String> required = List.of("programPath", "processorSpec");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("change-processor")
            .title("Change Processor Architecture")
            .description("Change the processor architecture of an existing program")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get parameters
            String programPath;
            String processorSpec;
            try {
                programPath = getString(request, "programPath");
                processorSpec = getString(request, "processorSpec");
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            }

            // Get the program
            Program program = getProgramFromArgs(request);
            if (program == null) {
                return createErrorResult("Program not found: " + programPath);
            }

            try {
                // Parse the processor spec
                LanguageService languageService = DefaultLanguageService.getLanguageService();
                LanguageCompilerSpecPair lcsPair = parseProcessorSpec(processorSpec, languageService);
                if (lcsPair == null) {
                    return createErrorResult("Invalid processor spec: " + processorSpec);
                }

                // Get the new language and compiler spec
                Language newLanguage = languageService.getLanguage(lcsPair.getLanguageID());
                CompilerSpec newCompilerSpec = newLanguage.getCompilerSpecByID(lcsPair.getCompilerSpecID());

                // Get current language info for comparison
                String oldLanguage = program.getLanguage().getLanguageID().getIdAsString();
                String oldCompiler = program.getCompilerSpec().getCompilerSpecID().getIdAsString();

                // Change the program's language
                int transactionId = program.startTransaction("Change processor architecture");
                try {
                    program.setLanguage(newLanguage, newCompilerSpec.getCompilerSpecID(), true, TaskMonitor.DUMMY);
                    program.endTransaction(transactionId, true);
                } catch (Exception e) {
                    program.endTransaction(transactionId, false);
                    throw e;
                }

                // Create result data
                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("programPath", programPath);
                result.put("oldLanguage", oldLanguage);
                result.put("oldCompilerSpec", oldCompiler);
                result.put("newLanguage", newLanguage.getLanguageID().getIdAsString());
                result.put("newCompilerSpec", newCompilerSpec.getCompilerSpecID().getIdAsString());
                result.put("message", "Successfully changed processor architecture");

                return createJsonResult(result);

            } catch (Exception e) {
                return createErrorResult("Failed to change processor architecture: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to analyze a program with Ghidra's auto-analysis
     * @throws McpError if there's an error registering the tool
     */
    private void registerAnalyzeProgramTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        
        // Required parameter: programPath
        properties.put("programPath", SchemaUtil.stringProperty(
            "Path to the program to analyze"
        ));
        
        // Optional parameter: force (default false)
        properties.put("force", SchemaUtil.booleanPropertyWithDefault(
            "Re-analyze even if program has already been analyzed", false
        ));
        
        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("analyze-program")
            .title("Analyze Program")
            .description("Run Ghidra auto-analysis on a program. Checks if analysis has already been run and provides hints.")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with the server
        registerTool(tool, (exchange, request) -> {
            try {
                // Extract parameters
                String programPath = getString(request, "programPath");
                boolean force = getOptionalBoolean(request, "force", false);
                
                // Get the program
                Program program = getProgramFromArgs(request);
                
                // Check current analysis status using Ghidra's standard method
                boolean isAnalyzed = GhidraProgramUtilities.isAnalyzed(program);
                
                // If already analyzed and not forcing, return info with hint
                if (isAnalyzed && !force) {
                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("programPath", programPath);
                    result.put("wasAlreadyAnalyzed", true);
                    result.put("analysisTriggered", false);
                    result.put("message", "Program has already been analyzed");
                    result.put("hint", "Use 'force: true' parameter to re-analyze if needed");
                    
                    // Add current analysis stats
                    Map<String, Object> currentStats = new HashMap<>();
                    currentStats.put("functionCount", program.getFunctionManager().getFunctionCount());
                    currentStats.put("symbolCount", program.getSymbolTable().getNumSymbols());
                    currentStats.put("memorySize", program.getMemory().getSize());
                    result.put("currentAnalysisInfo", currentStats);
                    
                    return createJsonResult(result);
                }
                
                // Run analysis
                long startTime = System.currentTimeMillis();
                
                int transactionID = program.startTransaction("Program analysis");
                try {
                    AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
                    mgr.initializeOptions();
                    
                    // If forcing a re-analysis, reset the analysis flags first
                    if (force && isAnalyzed) {
                        GhidraProgramUtilities.resetAnalysisFlags(program);
                    }
                    
                    mgr.reAnalyzeAll(null);
                    mgr.startAnalysis(TaskMonitor.DUMMY);
                    
                    // Mark program as analyzed using Ghidra's standard method
                    GhidraProgramUtilities.markProgramAnalyzed(program);
                    
                    program.endTransaction(transactionID, true);
                } catch (Exception e) {
                    program.endTransaction(transactionID, false);
                    throw e;
                }
                
                long endTime = System.currentTimeMillis();
                long timeElapsed = endTime - startTime;
                
                // Create analysis results
                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("programPath", programPath);
                result.put("wasAlreadyAnalyzed", isAnalyzed);
                result.put("analysisTriggered", true);
                result.put("forced", force);
                result.put("message", force && isAnalyzed ? "Re-analysis completed successfully" : "Analysis completed successfully");
                
                // Add analysis statistics
                Map<String, Object> analysisInfo = new HashMap<>();
                analysisInfo.put("functionsFound", program.getFunctionManager().getFunctionCount());
                analysisInfo.put("symbolsFound", program.getSymbolTable().getNumSymbols());
                analysisInfo.put("timeElapsedMs", timeElapsed);
                analysisInfo.put("timeElapsedSeconds", timeElapsed / 1000.0);
                analysisInfo.put("memorySize", program.getMemory().getSize());
                result.put("analysisInfo", analysisInfo);
                
                return createJsonResult(result);
                
            } catch (IllegalArgumentException | ProgramValidationException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                return createErrorResult("Failed to analyze program: " + e.getMessage());
            }
        });
    }

    /**
     * Parse a processor spec string into a LanguageCompilerSpecPair
     * @param spec The processor spec string (e.g., "x86:LE:64:default")
     * @param languageService The language service to use
     * @return The parsed LanguageCompilerSpecPair, or null if invalid
     */
    private LanguageCompilerSpecPair parseProcessorSpec(String spec, LanguageService languageService) {
        // Split the spec string
        String[] parts = spec.split(":");
        if (parts.length < 2) {
            return null; // Clearly invalid - needs at least processor:something
        }

        try {
            // Build the language ID string
            String processor = parts[0];
            String endian = parts[1];
            String size = parts[2];
            String variant = parts.length > 3 ? parts[3] : "default";

            // Construct language ID
            String languageId = processor + ":" + endian + ":" + size + ":" + variant;

            // Create a LanguageID object and get the language
            LanguageID langId = new LanguageID(languageId);
            Language lang = languageService.getLanguage(langId);
            
            // Get default compiler spec if not specified
            CompilerSpecID compilerSpecId = lang.getDefaultCompilerSpec().getCompilerSpecID();

            return new LanguageCompilerSpecPair(lang.getLanguageID(), compilerSpecId);
        } catch (Exception e) {
            // Try alternate formats
            try {
                List<LanguageDescription> descriptions = languageService.getLanguageDescriptions(false);
                
                // Try partial matches with the provided spec
                String specLower = spec.toLowerCase();
                for (LanguageDescription desc : descriptions) {
                    String langId = desc.getLanguageID().getIdAsString().toLowerCase();
                    
                    // Try exact processor match with parts from the spec
                    if (parts.length >= 3 && desc.getProcessor().toString().equalsIgnoreCase(parts[0])) {
                        // Look for languages with same processor, endian, size
                        String expectedPrefix = parts[0].toLowerCase() + ":" + parts[1].toLowerCase() + ":" + parts[2];
                        if (langId.startsWith(expectedPrefix)) {
                            Language lang = languageService.getLanguage(desc.getLanguageID());
                            return new LanguageCompilerSpecPair(lang.getLanguageID(), 
                                lang.getDefaultCompilerSpec().getCompilerSpecID());
                        }
                    }
                    
                    // Try broader processor name match
                    if (desc.getProcessor().toString().equalsIgnoreCase(specLower) ||
                        langId.startsWith(specLower)) {
                        Language lang = languageService.getLanguage(desc.getLanguageID());
                        return new LanguageCompilerSpecPair(lang.getLanguageID(), 
                            lang.getDefaultCompilerSpec().getCompilerSpecID());
                    }
                }
            } catch (Exception ex) {
                // Ignore and return null
            }
            return null;
        }
    }

    /**
     * Open a program in the current Ghidra tool
     * @param program The program to open
     */
    private void openProgramInTool(Program program) {
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            return;
        }

        ToolManager toolManager = project.getToolManager();
        if (toolManager != null) {
            PluginTool[] runningTools = toolManager.getRunningTools();
            if (runningTools.length > 0) {
                // Open in the first available tool
                PluginTool tool = runningTools[0];
                ProgramManager programManager = tool.getService(ProgramManager.class);
                if (programManager != null) {
                    programManager.openProgram(program.getDomainFile());
                }
            }
        }
    }

    /**
     * Collect files and subfolders from a folder
     * @param folder The folder to collect from
     * @param filesList The list to add file info to
     * @param pathPrefix Path prefix for nested items
     */
    private void collectFilesInFolder(DomainFolder folder, List<Map<String, Object>> filesList, String pathPrefix) {
        // Add subfolders
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

            // Add program-specific info if it's a program
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
                }
                catch (Exception e) {
                    // Ignore errors when getting metadata
                }
            }

            filesList.add(fileInfo);
        }
    }

    /**
     * Recursively collect files and subfolders from a folder
     * @param folder The folder to collect from
     * @param filesList The list to add file info to
     * @param pathPrefix Path prefix for nested items
     */
    private void collectFilesRecursive(DomainFolder folder, List<Map<String, Object>> filesList, String pathPrefix) {
        // Collect files in this folder
        collectFilesInFolder(folder, filesList, pathPrefix);

        // Recursively collect files in subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            String newPrefix = pathPrefix + subfolder.getName() + "/";
            collectFilesRecursive(subfolder, filesList, newPrefix);
        }
    }

    /**
     * Handle importing files from a directory
     */
    private Map<String, Object> handleDirectoryImport(File directory, Project project, String projectPath, 
            List<String> includePatterns, List<String> excludePatterns, int maxDepth, int autoImportThreshold, 
            boolean listOnly, boolean runAnalysis, boolean openProgram) {
        
        try {
            // Collect all importable files from the directory
            List<File> files = new ArrayList<>();
            collectFilesFromDirectory(directory, files, includePatterns, excludePatterns, maxDepth, 0);
            
            if (files.isEmpty()) {
                Map<String, Object> errorResult = new HashMap<>();
                errorResult.put("success", false);
                errorResult.put("error", "No importable files found in directory: " + directory.getName());
                return errorResult;
            }
            
            // If listing only or too many files without patterns, return file listing
            if (listOnly || (files.size() > autoImportThreshold && includePatterns.isEmpty())) {
                return createDirectoryListingResult(directory, files, includePatterns, excludePatterns, maxDepth);
            }
            
            // Import all matching files
            return importMultipleFiles(files, project, projectPath, runAnalysis, openProgram);
            
        } catch (Exception e) {
            Map<String, Object> errorResult = new HashMap<>();
            errorResult.put("success", false);
            errorResult.put("error", "Error processing directory: " + e.getMessage());
            return errorResult;
        }
    }

    /**
     * Handle importing files from an archive
     */
    private Map<String, Object> handleArchiveImport(FSRL archiveFsrl, Project project, String projectPath, 
            List<String> includePatterns, List<String> excludePatterns, int maxDepth, int autoImportThreshold, 
            boolean listOnly, boolean runAnalysis, boolean openProgram) {
        
        try (FileSystemRef fsRef = FileSystemService.getInstance().probeFileForFilesystem(
                archiveFsrl, TaskMonitor.DUMMY, null)) {
            
            if (fsRef == null) {
                Map<String, Object> errorResult = new HashMap<>();
                errorResult.put("success", false);
                errorResult.put("error", "Unable to open archive: " + archiveFsrl);
                return errorResult;
            }
            
            GFileSystem fs = fsRef.getFilesystem();
            List<ArchiveFileInfo> files = new ArrayList<>();
            collectFilesFromArchive(fs, fs.lookup(null), files, includePatterns, excludePatterns, maxDepth, 0);
            
            if (files.isEmpty()) {
                Map<String, Object> errorResult = new HashMap<>();
                errorResult.put("success", false);
                errorResult.put("error", "No importable files found in archive");
                return errorResult;
            }
            
            // If listing only or too many files without patterns, return file listing
            if (listOnly || (files.size() > autoImportThreshold && includePatterns.isEmpty())) {
                return createArchiveListingResult(archiveFsrl, files, includePatterns, excludePatterns, maxDepth);
            }
            
            // Import all matching files
            return importArchiveFiles(files, project, projectPath, runAnalysis, openProgram);
            
        } catch (Exception e) {
            Map<String, Object> errorResult = new HashMap<>();
            errorResult.put("success", false);
            errorResult.put("error", "Error processing archive: " + e.getMessage());
            return errorResult;
        }
    }

    /**
     * Collect files from a directory recursively
     */
    private void collectFilesFromDirectory(File dir, List<File> files, List<String> includePatterns, 
            List<String> excludePatterns, int maxDepth, int currentDepth) {
        
        if (currentDepth >= maxDepth || !dir.isDirectory()) {
            return;
        }
        
        File[] children = dir.listFiles();
        if (children == null) {
            return;
        }
        
        for (File child : children) {
            if (child.isDirectory()) {
                collectFilesFromDirectory(child, files, includePatterns, excludePatterns, maxDepth, currentDepth + 1);
            } else if (child.isFile() && shouldIncludeFile(child.getName(), includePatterns, excludePatterns)) {
                files.add(child);
            }
        }
    }

    /**
     * Collect files from an archive recursively
     */
    private void collectFilesFromArchive(GFileSystem fs, GFile dir, List<ArchiveFileInfo> files, 
            List<String> includePatterns, List<String> excludePatterns, int maxDepth, int currentDepth) {
        
        if (currentDepth >= maxDepth || dir == null) {
            return;
        }
        
        try {
            List<GFile> children = fs.getListing(dir);
            for (GFile child : children) {
                if (child.isDirectory()) {
                    collectFilesFromArchive(fs, child, files, includePatterns, excludePatterns, maxDepth, currentDepth + 1);
                } else if (shouldIncludeFile(child.getName(), includePatterns, excludePatterns)) {
                    files.add(new ArchiveFileInfo(child, currentDepth));
                }
            }
        } catch (IOException e) {
            // Continue processing other files
        }
    }

    /**
     * Check if a file should be included based on patterns
     */
    private boolean shouldIncludeFile(String fileName, List<String> includePatterns, List<String> excludePatterns) {
        // Check exclude patterns first
        for (String excludePattern : excludePatterns) {
            PathMatcher matcher = FileSystems.getDefault().getPathMatcher("glob:" + excludePattern);
            if (matcher.matches(Paths.get(fileName))) {
                return false;
            }
        }
        
        // If no include patterns, include by default
        if (includePatterns.isEmpty()) {
            return true;
        }
        
        // Check include patterns
        for (String includePattern : includePatterns) {
            PathMatcher matcher = FileSystems.getDefault().getPathMatcher("glob:" + includePattern);
            if (matcher.matches(Paths.get(fileName))) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Create a listing result for directory contents
     */
    private Map<String, Object> createDirectoryListingResult(File directory, List<File> files, 
            List<String> includePatterns, List<String> excludePatterns, int maxDepth) {
        
        List<Map<String, Object>> filesList = new ArrayList<>();
        
        for (File file : files) {
            Map<String, Object> fileInfo = new HashMap<>();
            fileInfo.put("filePath", file.getAbsolutePath());
            fileInfo.put("fileName", file.getName());
            fileInfo.put("size", file.length());
            fileInfo.put("type", "file");
            filesList.add(fileInfo);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("isListing", true);
        result.put("sourceType", "directory");
        result.put("sourcePath", directory.getAbsolutePath());
        result.put("fileCount", files.size());
        result.put("maxDepth", maxDepth);
        result.put("includePatterns", includePatterns);
        result.put("excludePatterns", excludePatterns);
        result.put("files", filesList);
        result.put("message", "Directory contains " + files.size() + " files. Use includePatterns to filter or set autoImportThreshold higher to import all.");
        
        return result;
    }

    /**
     * Create a listing result for archive contents
     */
    private Map<String, Object> createArchiveListingResult(FSRL archiveFsrl, List<ArchiveFileInfo> files, 
            List<String> includePatterns, List<String> excludePatterns, int maxDepth) {
        
        List<Map<String, Object>> filesList = new ArrayList<>();
        
        for (ArchiveFileInfo fileInfo : files) {
            Map<String, Object> info = new HashMap<>();
            info.put("filePath", fileInfo.file.getPath());
            info.put("fileName", fileInfo.file.getName());
            info.put("size", fileInfo.file.getLength());
            info.put("depth", fileInfo.depth);
            info.put("type", "file");
            filesList.add(info);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("isListing", true);
        result.put("sourceType", "archive");
        result.put("sourcePath", archiveFsrl.toString());
        result.put("fileCount", files.size());
        result.put("maxDepth", maxDepth);
        result.put("includePatterns", includePatterns);
        result.put("excludePatterns", excludePatterns);
        result.put("files", filesList);
        result.put("message", "Archive contains " + files.size() + " files. Use includePatterns to filter or set autoImportThreshold higher to import all.");
        
        return result;
    }

    /**
     * Import multiple files from the filesystem
     */
    private Map<String, Object> importMultipleFiles(List<File> files, Project project, String projectPath, 
            boolean runAnalysis, boolean openProgram) {
        
        List<Map<String, Object>> results = new ArrayList<>();
        int successCount = 0;
        
        for (File file : files) {
            try {
                MessageLog messageLog = new MessageLog();
                LoadResults<Program> loadResults = AutoImporter.importByUsingBestGuess(
                    file, project, projectPath, this, messageLog, TaskMonitor.DUMMY);
                
                if (loadResults != null && loadResults.size() > 0) {
                    Loaded<Program> primaryLoaded = loadResults.getPrimary();
                    Program program = primaryLoaded.getDomainObject();
                    
                    // Save and register the program
                    loadResults.save(project, this, messageLog, TaskMonitor.DUMMY);
                    
                    if (runAnalysis) {
                        runAnalysisOnProgram(program);
                    }
                    
                    if (openProgram && successCount < 5) { // Limit opening to first 5 programs
                        openProgramInTool(program);
                    }
                    
                    RevaProgramManager.registerProgram(program);
                    
                    Map<String, Object> fileResult = new HashMap<>();
                    fileResult.put("success", true);
                    fileResult.put("filePath", file.getAbsolutePath());
                    fileResult.put("programPath", RevaProgramManager.getCanonicalProgramPath(program));
                    fileResult.put("programName", program.getName());
                    results.add(fileResult);
                    successCount++;
                } else {
                    Map<String, Object> fileResult = new HashMap<>();
                    fileResult.put("success", false);
                    fileResult.put("filePath", file.getAbsolutePath());
                    fileResult.put("error", "Failed to import: " + file.getName());
                    results.add(fileResult);
                }
            } catch (Exception e) {
                Map<String, Object> fileResult = new HashMap<>();
                fileResult.put("success", false);
                fileResult.put("filePath", file.getAbsolutePath());
                fileResult.put("error", "Import error: " + e.getMessage());
                results.add(fileResult);
            }
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("sourceType", "directory");
        result.put("totalFiles", files.size());
        result.put("successCount", successCount);
        result.put("failureCount", files.size() - successCount);
        result.put("results", results);
        
        return result;
    }

    /**
     * Import files from archive
     */
    private Map<String, Object> importArchiveFiles(List<ArchiveFileInfo> files, Project project, String projectPath, 
            boolean runAnalysis, boolean openProgram) {
        
        List<Map<String, Object>> results = new ArrayList<>();
        int successCount = 0;
        
        for (ArchiveFileInfo fileInfo : files) {
            try {
                MessageLog messageLog = new MessageLog();
                
                // Get byte provider for the archive file
                try (ghidra.app.util.bin.ByteProvider byteProvider = 
                        FileSystemService.getInstance().getByteProvider(fileInfo.file.getFSRL(), false, TaskMonitor.DUMMY)) {
                    
                    LoadResults<Program> loadResults = AutoImporter.importByUsingBestGuess(
                        byteProvider, project, projectPath, this, messageLog, TaskMonitor.DUMMY);
                    
                    if (loadResults != null && loadResults.size() > 0) {
                        Loaded<Program> primaryLoaded = loadResults.getPrimary();
                        Program program = primaryLoaded.getDomainObject();
                        
                        // Save and register the program
                        loadResults.save(project, this, messageLog, TaskMonitor.DUMMY);
                        
                        if (runAnalysis) {
                            runAnalysisOnProgram(program);
                        }
                        
                        if (openProgram && successCount < 5) { // Limit opening to first 5 programs
                            openProgramInTool(program);
                        }
                        
                        RevaProgramManager.registerProgram(program);
                        
                        Map<String, Object> fileResult = new HashMap<>();
                        fileResult.put("success", true);
                        fileResult.put("archiveFilePath", fileInfo.file.getPath());
                        fileResult.put("programPath", RevaProgramManager.getCanonicalProgramPath(program));
                        fileResult.put("programName", program.getName());
                        fileResult.put("depth", fileInfo.depth);
                        results.add(fileResult);
                        successCount++;
                    } else {
                        Map<String, Object> fileResult = new HashMap<>();
                        fileResult.put("success", false);
                        fileResult.put("archiveFilePath", fileInfo.file.getPath());
                        fileResult.put("error", "Failed to import: " + fileInfo.file.getName());
                        results.add(fileResult);
                    }
                }
            } catch (Exception e) {
                Map<String, Object> fileResult = new HashMap<>();
                fileResult.put("success", false);
                fileResult.put("archiveFilePath", fileInfo.file.getPath());
                fileResult.put("error", "Import error: " + e.getMessage());
                results.add(fileResult);
            }
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("sourceType", "archive");
        result.put("totalFiles", files.size());
        result.put("successCount", successCount);
        result.put("failureCount", files.size() - successCount);
        result.put("results", results);
        
        return result;
    }

    /**
     * Run analysis on a program
     */
    private void runAnalysisOnProgram(Program program) {
        int transactionID = program.startTransaction("Auto-analysis during batch import");
        try {
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
            mgr.initializeOptions();
            mgr.reAnalyzeAll(null);
            mgr.startAnalysis(TaskMonitor.DUMMY);
            program.endTransaction(transactionID, true);
        } catch (Exception e) {
            program.endTransaction(transactionID, false);
        }
    }

    /**
     * Helper class to track archive file info with nesting depth
     */
    private static class ArchiveFileInfo {
        final GFile file;
        final int depth;
        
        ArchiveFileInfo(GFile file, int depth) {
            this.file = file;
            this.depth = depth;
        }
    }
}