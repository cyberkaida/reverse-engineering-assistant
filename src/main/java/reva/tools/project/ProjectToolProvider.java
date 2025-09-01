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
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemRef;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.framework.data.DefaultCheckinHandler;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
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
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.InvalidNameException;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.RevaProgramManager;
import reva.tools.AbstractToolProvider;
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
        registerAnalyzeProgramTool();
        registerChangeProcessorTool();
        registerImportProgramTool();
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
            .description("List all programs currently open in Ghidra across all tools")
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
                programInfo.put("programPath", program.getDomainFile().getPathname());
                programInfo.put("language", program.getLanguage().getLanguageID().getIdAsString());
                programInfo.put("compilerSpec", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
                programInfo.put("creationDate", program.getCreationDate());
                programInfo.put("sizeBytes", program.getMemory().getSize());
                programInfo.put("functionCount", program.getFunctionManager().getFunctionCount());
                programInfo.put("symbolCount", program.getSymbolTable().getNumSymbols());
                programInfo.put("modificationDate", program.getDomainFile().getLastModifiedTime());
                programInfo.put("isReadOnly", program.getDomainFile().isReadOnly());

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
            String programPath = program.getDomainFile().getPathname();
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
                
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                return createErrorResult("Failed to analyze program: " + e.getMessage());
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
     * Register a comprehensive tool to import programs from files, directories, or archives
     * @throws McpError if there's an error registering the tool
     */
    private void registerImportProgramTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("path", SchemaUtil.stringProperty(
            "Path to file, directory, or archive to import from"
        ));
        
        // Create array property for includePatterns
        Map<String, Object> includeProperty = new HashMap<>();
        includeProperty.put("type", "array");
        includeProperty.put("description", "List of glob patterns to include (e.g., ['*.exe', '*.dll']). If not provided, imports all importable files from path.");
        Map<String, Object> includeItemSchema = new HashMap<>();
        includeItemSchema.put("type", "string");
        includeItemSchema.put("description", "Glob pattern to include");
        includeProperty.put("items", includeItemSchema);
        properties.put("includePatterns", includeProperty);
        
        // Create array property for excludePatterns
        Map<String, Object> excludeProperty = new HashMap<>();
        excludeProperty.put("type", "array");
        excludeProperty.put("description", "List of glob patterns to exclude (e.g., ['*.txt', '*.md']).");
        Map<String, Object> excludeItemSchema = new HashMap<>();
        excludeItemSchema.put("type", "string");
        excludeItemSchema.put("description", "Glob pattern to exclude");
        excludeProperty.put("items", excludeItemSchema);
        properties.put("excludePatterns", excludeProperty);
        
        properties.put("projectPath", SchemaUtil.stringPropertyWithDefault(
            "Where to save the programs in the project (default: /)", "/"
        ));
        properties.put("processorSpec", SchemaUtil.stringProperty(
            "Optional processor/compiler spec (e.g., 'x86:LE:64:default', 'golang:BE:64:default'). If not specified, Ghidra will auto-detect."
        ));
        properties.put("runAnalysis", SchemaUtil.booleanPropertyWithDefault(
            "Whether to run auto-analysis after loading", true
        ));
        properties.put("openProgram", SchemaUtil.booleanPropertyWithDefault(
            "Whether to open the programs after loading", true
        ));
        properties.put("browseOnly", SchemaUtil.booleanPropertyWithDefault(
            "Only browse and list contents without importing", false
        ));
        properties.put("maxDepth", SchemaUtil.integerPropertyWithDefault(
            "Maximum recursion depth for nested archives", 10
        ));
        properties.put("autoImportThreshold", SchemaUtil.integerPropertyWithDefault(
            "Maximum number of files to auto-import without listing", 5
        ));

        List<String> required = List.of("path");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("import-program")
            .title("Import Program")
            .description("Import programs from files, directories, or archives. Supports browsing contents and selective import with patterns. Handles ZIP, TAR, and other archive formats.")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get parameters
            String path;
            try {
                path = getString(request, "path");
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            }

            List<String> includePatterns = getOptionalStringList(request.arguments(), "includePatterns", new ArrayList<>());
            List<String> excludePatterns = getOptionalStringList(request.arguments(), "excludePatterns", new ArrayList<>());
            String projectPath = getOptionalString(request, "projectPath", "/");
            String processorSpec = getOptionalString(request, "processorSpec", null);
            boolean runAnalysis = getOptionalBoolean(request, "runAnalysis", true);
            boolean openProgram = getOptionalBoolean(request, "openProgram", true);
            boolean browseOnly = getOptionalBoolean(request, "browseOnly", false);
            int maxDepth = getOptionalInt(request, "maxDepth", 10);
            int autoImportThreshold = getOptionalInt(request, "autoImportThreshold", 5);

            // Get the active project
            Project project = AppInfo.getActiveProject();
            if (project == null) {
                return createErrorResult("No active project found");
            }

            File pathFile = new File(path);
            
            if (!pathFile.exists()) {
                return createErrorResult("Path not found: " + path);
            }
            
            // Browse mode or no specific patterns - list contents first
            if (browseOnly) {
                return browsePathContents(pathFile, includePatterns, excludePatterns, maxDepth);
            }
            
            // Import mode - handle different path types
            try {
                if (pathFile.isDirectory()) {
                    LanguageService langService = DefaultLanguageService.getLanguageService();
                    LanguageCompilerSpecPair processor = parseProcessorSpec(processorSpec, langService);
                    return handleDirectoryImport(pathFile, projectPath, processor, runAnalysis, openProgram, 
                        includePatterns, excludePatterns, autoImportThreshold);
                } else if (isArchiveFile(pathFile)) {
                    FSRL archiveFsrl = FileSystemService.getInstance().getLocalFSRL(pathFile);
                    LanguageService langService = DefaultLanguageService.getLanguageService();
                    LanguageCompilerSpecPair processor = parseProcessorSpec(processorSpec, langService);
                    return handleArchiveImport(archiveFsrl, projectPath, processor, runAnalysis, openProgram, 
                        includePatterns, excludePatterns, maxDepth, autoImportThreshold);
                } else {
                    // Single file import
                    LanguageService langService = DefaultLanguageService.getLanguageService();
                    LanguageCompilerSpecPair processor = parseProcessorSpec(processorSpec, langService);
                    return handleFileImport(pathFile, projectPath, processor, runAnalysis, openProgram);
                }
            } catch (Exception e) {
                return createErrorResult("Import failed: " + e.getMessage());
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
        // Handle null spec
        if (spec == null || spec.trim().isEmpty()) {
            return null;
        }
        
        // Split the spec string
        String[] parts = spec.split(":");
        if (parts.length < 2) {
            return null; // Clearly invalid - needs at least processor:something
        }

        try {
            // Build the language ID string
            String processor = parts[0];
            String endian = parts[1];
            String size = parts.length > 2 ? parts[2] : "32";
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
     * Browse and list contents of a path (directory, archive, or single file)
     */
    private McpSchema.CallToolResult browsePathContents(File path, List<String> includePatterns, List<String> excludePatterns, int maxDepth) {
        List<Map<String, Object>> filesList = new ArrayList<>();
        Map<String, Object> result = new HashMap<>();
        
        result.put("success", true);
        result.put("isListing", true);
        result.put("path", path.getAbsolutePath());
        
        if (path.isDirectory()) {
            result.put("sourceType", "directory");
            // List directory contents with pattern filtering
            browseDirectoryContents(path, filesList, includePatterns, excludePatterns, maxDepth, 0);
            result.put("totalFiles", filesList.size());
            result.put("message", "Directory contents listed successfully");
            
        } else if (isArchiveFile(path)) {
            result.put("sourceType", "archive");
            result.put("archiveType", getArchiveType(path));
            
            try {
                // Browse archive contents using FileSystemService
                FSRL fsrl = FileSystemService.getInstance().getLocalFSRL(path);
                List<Map<String, Object>> archiveContents = browseArchiveContents(fsrl, includePatterns, excludePatterns, maxDepth);
                filesList.addAll(archiveContents);
                result.put("totalFiles", archiveContents.size());
                result.put("message", "Archive contents listed successfully. Use includePatterns to filter and set browseOnly=false to import specific files.");
            } catch (Exception e) {
                result.put("totalFiles", 0);
                result.put("message", "Archive detected but contents cannot be browsed: " + e.getMessage() + 
                    ". Use includePatterns to import specific files from the archive.");
                result.put("error", e.getMessage());
            }
            
        } else {
            result.put("sourceType", "file");
            // Single file
            filesList.add(createFileInfo(path));
            result.put("totalFiles", 1);
            result.put("message", "Single file listed successfully");
        }
        
        // Add files list to result if there are any
        if (!filesList.isEmpty()) {
            result.put("files", filesList);
        }
        
        return createJsonResult(result);
    }

    // Core import handling methods
    
    private McpSchema.CallToolResult handleFileImport(File file, String projectPath, LanguageCompilerSpecPair processor, 
            boolean runAnalysis, boolean openProgram) throws Exception {
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            return createErrorResult("No active project found");
        }

        // Get project folder
        DomainFolder folder = getOrCreateProjectFolder(project, projectPath);
        if (folder == null) {
            return createErrorResult("Failed to create project folder: " + projectPath);
        }

        // Import the file
        Map<String, Object> result = importSingleFile(file, folder, processor, runAnalysis, openProgram);
        
        // Return structured result
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("sourceType", "file");
        response.put("sourcePath", file.getAbsolutePath());
        response.put("isListing", false);
        response.put("totalFiles", 1);
        response.put("successCount", result.get("success").equals(true) ? 1 : 0);
        response.put("failureCount", result.get("success").equals(true) ? 0 : 1);
        response.put("results", List.of(result));
        
        return createJsonResult(response);
    }

    private McpSchema.CallToolResult handleDirectoryImport(File directory, String projectPath, LanguageCompilerSpecPair processor, 
            boolean runAnalysis, boolean openProgram, List<String> includePatterns, List<String> excludePatterns,
            int autoImportThreshold) throws Exception {
        
        // Collect files from directory
        List<File> filesToImport = collectFilesFromDirectory(directory, includePatterns, excludePatterns);
        
        // Check auto-import threshold
        if (filesToImport.size() > autoImportThreshold && (includePatterns == null || includePatterns.isEmpty())) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("error", "Too many files found (" + filesToImport.size() + 
                "). Use includePatterns to filter files or increase autoImportThreshold.");
            response.put("foundFiles", filesToImport.size());
            response.put("threshold", autoImportThreshold);
            return createJsonResult(response);
        }
        
        // Import files
        return importMultipleFiles(filesToImport, projectPath, processor, runAnalysis, openProgram, 
            "directory", directory.getAbsolutePath());
    }

    private McpSchema.CallToolResult handleArchiveImport(FSRL archiveFsrl, String projectPath, LanguageCompilerSpecPair processor, 
            boolean runAnalysis, boolean openProgram, List<String> includePatterns, List<String> excludePatterns,
            int maxDepth, int autoImportThreshold) throws Exception {
        
        // Collect files from archive
        List<FSRL> filesToImport = collectFilesFromArchive(archiveFsrl, includePatterns, excludePatterns, maxDepth);
        
        // Check auto-import threshold
        if (filesToImport.size() > autoImportThreshold && (includePatterns == null || includePatterns.isEmpty())) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("error", "Too many files found in archive (" + filesToImport.size() + 
                "). Use includePatterns to filter files or increase autoImportThreshold.");
            response.put("foundFiles", filesToImport.size());
            response.put("threshold", autoImportThreshold);
            return createJsonResult(response);
        }
        
        // Import files from archive
        return importMultipleFilesFromArchive(filesToImport, projectPath, processor, runAnalysis, openProgram, 
            archiveFsrl.toString());
    }

    private List<File> collectFilesFromDirectory(File directory, List<String> includePatterns, List<String> excludePatterns) {
        List<File> files = new ArrayList<>();
        collectFilesFromDirectoryRecursive(directory, files, includePatterns, excludePatterns);
        return files;
    }

    private void collectFilesFromDirectoryRecursive(File directory, List<File> files, 
            List<String> includePatterns, List<String> excludePatterns) {
        
        File[] dirFiles = directory.listFiles();
        if (dirFiles == null) return;
        
        for (File file : dirFiles) {
            if (file.isDirectory()) {
                collectFilesFromDirectoryRecursive(file, files, includePatterns, excludePatterns);
            } else if (file.isFile()) {
                if (shouldIncludeFile(file.getName(), includePatterns, excludePatterns) && isPossibleBinaryFile(file)) {
                    files.add(file);
                }
            }
        }
    }

    private List<FSRL> collectFilesFromArchive(FSRL archiveFsrl, List<String> includePatterns, 
            List<String> excludePatterns, int maxDepth) throws IOException, CancelledException {
        
        List<FSRL> files = new ArrayList<>();
        
        try (FileSystemRef fsRef = FileSystemService.getInstance().getFilesystem(archiveFsrl.getFS(), TaskMonitor.DUMMY)) {
            if (fsRef == null) {
                throw new IOException("Unable to open archive filesystem: " + archiveFsrl);
            }
            
            GFileSystem fs = fsRef.getFilesystem();
            collectFilesFromArchiveRecursive(fs, fs.getRootDir(), files, includePatterns, excludePatterns, maxDepth, 0);
        }
        
        return files;
    }

    private void collectFilesFromArchiveRecursive(GFileSystem fs, GFile directory, List<FSRL> files,
            List<String> includePatterns, List<String> excludePatterns, int maxDepth, int currentDepth) {
        
        if (currentDepth >= maxDepth) {
            return;
        }
        
        try {
            List<GFile> dirFiles = fs.getListing(directory);
            if (dirFiles == null) return;
            
            for (GFile file : dirFiles) {
                if (file.isDirectory()) {
                    collectFilesFromArchiveRecursive(fs, file, files, includePatterns, excludePatterns, 
                        maxDepth, currentDepth + 1);
                } else {
                    String fileName = file.getName();
                    if (shouldIncludeFile(fileName, includePatterns, excludePatterns) && 
                        isPossibleBinaryFile(fileName)) {
                        files.add(file.getFSRL());
                    }
                }
            }
        } catch (IOException e) {
            // Log error but continue processing other files
        }
    }

    private boolean shouldIncludeFile(String fileName, List<String> includePatterns, List<String> excludePatterns) {
        // Check exclude patterns first
        if (excludePatterns != null && !excludePatterns.isEmpty()) {
            for (String pattern : excludePatterns) {
                if (matchesPattern(fileName, pattern)) {
                    return false;
                }
            }
        }
        
        // Check include patterns
        if (includePatterns != null && !includePatterns.isEmpty()) {
            for (String pattern : includePatterns) {
                if (matchesPattern(fileName, pattern)) {
                    return true;
                }
            }
            return false; // No include patterns matched
        }
        
        return true; // No patterns specified, include all
    }

    private boolean matchesPattern(String fileName, String pattern) {
        try {
            PathMatcher matcher = FileSystems.getDefault().getPathMatcher("glob:" + pattern);
            return matcher.matches(Paths.get(fileName).getFileName());
        } catch (Exception e) {
            // Fallback to simple pattern matching
            return simplePatternMatch(fileName, pattern);
        }
    }

    private boolean simplePatternMatch(String fileName, String pattern) {
        // Simple glob pattern matching with * and ?
        pattern = pattern.replace("*", ".*").replace("?", ".");
        return fileName.matches(pattern);
    }

    private McpSchema.CallToolResult importMultipleFiles(List<File> files, String projectPath, LanguageCompilerSpecPair processor,
            boolean runAnalysis, boolean openProgram, String sourceType, String sourcePath) throws Exception {
        
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            return createErrorResult("No active project found");
        }

        DomainFolder folder = getOrCreateProjectFolder(project, projectPath);
        if (folder == null) {
            return createErrorResult("Failed to create project folder: " + projectPath);
        }

        List<Map<String, Object>> results = new ArrayList<>();
        int successCount = 0;
        int failureCount = 0;

        for (File file : files) {
            try {
                Map<String, Object> result = importSingleFile(file, folder, processor, runAnalysis, openProgram);
                results.add(result);
                if (result.get("success").equals(true)) {
                    successCount++;
                } else {
                    failureCount++;
                }
            } catch (Exception e) {
                Map<String, Object> errorResult = new HashMap<>();
                errorResult.put("success", false);
                errorResult.put("filePath", file.getAbsolutePath());
                errorResult.put("error", e.getMessage());
                results.add(errorResult);
                failureCount++;
            }
        }

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("sourceType", sourceType);
        response.put("sourcePath", sourcePath);
        response.put("isListing", false);
        response.put("totalFiles", files.size());
        response.put("successCount", successCount);
        response.put("failureCount", failureCount);
        response.put("results", results);

        return createJsonResult(response);
    }

    private McpSchema.CallToolResult importMultipleFilesFromArchive(List<FSRL> files, String projectPath, 
            LanguageCompilerSpecPair processor, boolean runAnalysis, boolean openProgram, String sourcePath) throws Exception {
        
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            return createErrorResult("No active project found");
        }

        DomainFolder folder = getOrCreateProjectFolder(project, projectPath);
        if (folder == null) {
            return createErrorResult("Failed to create project folder: " + projectPath);
        }

        List<Map<String, Object>> results = new ArrayList<>();
        int successCount = 0;
        int failureCount = 0;

        for (FSRL fileFsrl : files) {
            try {
                Map<String, Object> result = importSingleFileFromArchive(fileFsrl, folder, processor, runAnalysis, openProgram);
                results.add(result);
                if (result.get("success").equals(true)) {
                    successCount++;
                } else {
                    failureCount++;
                }
            } catch (Exception e) {
                Map<String, Object> errorResult = new HashMap<>();
                errorResult.put("success", false);
                errorResult.put("filePath", fileFsrl.toString());
                errorResult.put("error", e.getMessage());
                results.add(errorResult);
                failureCount++;
            }
        }

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("sourceType", "archive");
        response.put("sourcePath", sourcePath);
        response.put("isListing", false);
        response.put("totalFiles", files.size());
        response.put("successCount", successCount);
        response.put("failureCount", failureCount);
        response.put("results", results);

        return createJsonResult(response);
    }

    private Map<String, Object> importSingleFile(File file, DomainFolder folder, LanguageCompilerSpecPair processor,
            boolean runAnalysis, boolean openProgram) throws Exception {
        
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Create unique program name
            String baseName = file.getName();
            String programName = createUniqueFileName(folder, baseName);
            
            // Use AutoImporter to import the file
            Project project = AppInfo.getActiveProject();
            MessageLog messageLog = new MessageLog();
            LoadResults<Program> loadResults = AutoImporter.importByUsingBestGuess(
                file, project, folder.getPathname() + "/" + programName, this, messageLog, TaskMonitor.DUMMY);
            
            if (loadResults == null || loadResults.size() == 0) {
                result.put("success", false);
                result.put("filePath", file.getAbsolutePath());
                result.put("error", "No programs were imported from file");
                return result;
            }
            
            // Save the loaded programs to the project
            loadResults.save(project, this, messageLog, TaskMonitor.DUMMY);
            
            // Get the primary imported program
            Program program = loadResults.getPrimaryDomainObject();
            String programPath = program.getDomainFile().getPathname();
            
            // Run analysis on all loaded programs if requested
            if (runAnalysis) {
                for (Loaded<Program> loaded : loadResults) {
                    Program loadedProgram = loaded.getDomainObject();
                    int analysisTransactionID = loadedProgram.startTransaction("Import program analysis");
                    try {
                        AutoAnalysisManager.getAnalysisManager(loadedProgram).startAnalysis(TaskMonitor.DUMMY);
                        loadedProgram.endTransaction(analysisTransactionID, true);
                    } catch (Exception e) {
                        loadedProgram.endTransaction(analysisTransactionID, false);
                        // Log but don't fail the import due to analysis issues
                    }
                }
            }
            
            // Open all programs if requested
            if (openProgram) {
                for (Loaded<Program> loaded : loadResults) {
                    openProgramInTool(loaded.getDomainObject());
                }
            }
            
            result.put("success", true);
            result.put("filePath", file.getAbsolutePath());
            result.put("programPath", programPath);
            result.put("programName", programName);
            result.put("totalProgramsImported", loadResults.size());
            
            // Release the LoadResults (this will release all loaded programs)
            loadResults.release(this);
            
        } catch (Exception e) {
            result.put("success", false);
            result.put("filePath", file.getAbsolutePath());
            result.put("error", e.getMessage());
        }
        
        return result;
    }

    private Map<String, Object> importSingleFileFromArchive(FSRL fileFsrl, DomainFolder folder, 
            LanguageCompilerSpecPair processor, boolean runAnalysis, boolean openProgram) throws Exception {
        
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Extract file name from FSRL
            String fileName = fileFsrl.getName();
            String programName = createUniqueFileName(folder, fileName);
            
            // Use AutoImporter to import from archive
            Project project = AppInfo.getActiveProject();
            MessageLog messageLog = new MessageLog();
            LoadResults<Program> loadResults = AutoImporter.importByUsingBestGuess(
                fileFsrl, project, folder.getPathname() + "/" + programName, this, messageLog, TaskMonitor.DUMMY);
            
            if (loadResults == null || loadResults.size() == 0) {
                result.put("success", false);
                result.put("filePath", fileFsrl.toString());
                result.put("error", "No programs were imported from archive file");
                return result;
            }
            
            // Save the loaded programs to the project
            loadResults.save(project, this, messageLog, TaskMonitor.DUMMY);
            
            // Get the primary imported program
            Program program = loadResults.getPrimaryDomainObject();
            String programPath = program.getDomainFile().getPathname();
            
            // Run analysis on all loaded programs if requested
            if (runAnalysis) {
                for (Loaded<Program> loaded : loadResults) {
                    Program loadedProgram = loaded.getDomainObject();
                    int analysisTransactionID = loadedProgram.startTransaction("Import program analysis");
                    try {
                        AutoAnalysisManager.getAnalysisManager(loadedProgram).startAnalysis(TaskMonitor.DUMMY);
                        loadedProgram.endTransaction(analysisTransactionID, true);
                    } catch (Exception e) {
                        loadedProgram.endTransaction(analysisTransactionID, false);
                        // Log but don't fail the import due to analysis issues
                    }
                }
            }
            
            // Open all programs if requested
            if (openProgram) {
                for (Loaded<Program> loaded : loadResults) {
                    openProgramInTool(loaded.getDomainObject());
                }
            }
            
            result.put("success", true);
            result.put("filePath", fileFsrl.toString());
            result.put("programPath", programPath);
            result.put("programName", programName);
            result.put("totalProgramsImported", loadResults.size());
            
            // Release the LoadResults (this will release all loaded programs)
            loadResults.release(this);
            
        } catch (Exception e) {
            result.put("success", false);
            result.put("filePath", fileFsrl.toString());
            result.put("error", e.getMessage());
        }
        
        return result;
    }

    private DomainFolder getOrCreateProjectFolder(Project project, String folderPath) {
        if (folderPath == null || folderPath.equals("/") || folderPath.isEmpty()) {
            return project.getProjectData().getRootFolder();
        }
        
        // Normalize path
        if (!folderPath.startsWith("/")) {
            folderPath = "/" + folderPath;
        }
        
        DomainFolder folder = project.getProjectData().getFolder(folderPath);
        if (folder != null) {
            return folder;
        }
        
        // Create folder hierarchy
        String[] parts = folderPath.substring(1).split("/");
        DomainFolder currentFolder = project.getProjectData().getRootFolder();
        
        try {
            for (String part : parts) {
                if (!part.isEmpty()) {
                    DomainFolder subFolder = currentFolder.getFolder(part);
                    if (subFolder == null) {
                        subFolder = currentFolder.createFolder(part);
                    }
                    currentFolder = subFolder;
                }
            }
        } catch (Exception e) {
            return null;
        }
        
        return currentFolder;
    }

    private String createUniqueFileName(DomainFolder folder, String baseName) {
        String name = baseName;
        int counter = 1;
        
        while (folder.getFile(name) != null) {
            int dotIndex = baseName.lastIndexOf('.');
            if (dotIndex > 0) {
                String nameWithoutExt = baseName.substring(0, dotIndex);
                String extension = baseName.substring(dotIndex);
                name = nameWithoutExt + "_" + counter + extension;
            } else {
                name = baseName + "_" + counter;
            }
            counter++;
        }
        
        return name;
    }

    private boolean isPossibleBinaryFile(File file) {
        return isPossibleBinaryFile(file.getName());
    }

    private boolean isPossibleBinaryFile(String fileName) {
        if (fileName == null || fileName.isEmpty()) {
            return false;
        }
        
        String lowerName = fileName.toLowerCase();
        
        // Common binary file extensions
        return lowerName.endsWith(".exe") || lowerName.endsWith(".dll") || lowerName.endsWith(".so") ||
               lowerName.endsWith(".dylib") || lowerName.endsWith(".bin") || lowerName.endsWith(".elf") ||
               lowerName.endsWith(".o") || lowerName.endsWith(".obj") || lowerName.endsWith(".sys") ||
               lowerName.endsWith(".drv") || lowerName.endsWith(".com") || lowerName.endsWith(".scr") ||
               lowerName.endsWith(".msi") || lowerName.endsWith(".cab") || lowerName.endsWith(".dmp") ||
               // No extension (common for Unix executables)
               !lowerName.contains(".");
    }

    private boolean isArchiveFile(File file) {
        try {
            // Use Ghidra's FileSystemService for content-based archive detection
            // This properly detects all supported archive formats including CaRT archives
            FSRL fsrl = FileSystemService.getInstance().getLocalFSRL(file);
            return FileSystemService.getInstance().isFileFilesystemContainer(fsrl, TaskMonitor.DUMMY);
        } catch (Exception e) {
            // Fallback to extension-based detection if FileSystemService fails
            String lowerName = file.getName().toLowerCase();
            return lowerName.endsWith(".zip") || lowerName.endsWith(".tar") || lowerName.endsWith(".gz") ||
                   lowerName.endsWith(".7z") || lowerName.endsWith(".rar") || lowerName.endsWith(".bz2") ||
                   lowerName.endsWith(".tar.gz") || lowerName.endsWith(".tgz") || lowerName.endsWith(".tar.bz2");
        }
    }

    private Map<String, Object> createFileInfo(File file) {
        Map<String, Object> info = new HashMap<>();
        info.put("name", file.getName());
        info.put("path", file.getAbsolutePath());
        info.put("size", file.length());
        info.put("lastModified", file.lastModified());
        info.put("isDirectory", file.isDirectory());
        info.put("isFile", file.isFile());
        info.put("canRead", file.canRead());
        info.put("isPossibleBinary", isPossibleBinaryFile(file));
        info.put("isArchive", isArchiveFile(file));
        return info;
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

    // Browse helper methods
    
    private void browseDirectoryContents(File directory, List<Map<String, Object>> filesList, 
            List<String> includePatterns, List<String> excludePatterns, int maxDepth, int currentDepth) {
        
        if (currentDepth >= maxDepth) {
            return;
        }
        
        File[] dirFiles = directory.listFiles();
        if (dirFiles == null) return;
        
        for (File file : dirFiles) {
            if (file.isDirectory()) {
                filesList.add(createFileInfo(file));
                if (currentDepth + 1 < maxDepth) {
                    browseDirectoryContents(file, filesList, includePatterns, excludePatterns, maxDepth, currentDepth + 1);
                }
            } else if (file.isFile()) {
                if (shouldIncludeFile(file.getName(), includePatterns, excludePatterns)) {
                    filesList.add(createFileInfo(file));
                }
            }
        }
    }

    private List<Map<String, Object>> browseArchiveContents(FSRL archiveFsrl, List<String> includePatterns, 
            List<String> excludePatterns, int maxDepth) {
        
        List<Map<String, Object>> filesList = new ArrayList<>();
        
        try (FileSystemRef fsRef = FileSystemService.getInstance().getFilesystem(archiveFsrl.getFS(), TaskMonitor.DUMMY)) {
            if (fsRef == null) {
                return filesList;
            }
            
            GFileSystem fs = fsRef.getFilesystem();
            browseArchiveContentsRecursive(fs, fs.getRootDir(), filesList, includePatterns, excludePatterns, maxDepth, 0);
        } catch (Exception e) {
            // Return empty list if browsing fails
        }
        
        return filesList;
    }

    private void browseArchiveContentsRecursive(GFileSystem fs, GFile directory, List<Map<String, Object>> filesList,
            List<String> includePatterns, List<String> excludePatterns, int maxDepth, int currentDepth) {
        
        if (currentDepth >= maxDepth) {
            return;
        }
        
        try {
            List<GFile> dirFiles = fs.getListing(directory);
            if (dirFiles == null) return;
            
            for (GFile file : dirFiles) {
                Map<String, Object> fileInfo = new HashMap<>();
                fileInfo.put("name", file.getName());
                fileInfo.put("path", file.getFSRL().toString());
                fileInfo.put("size", file.getLength());
                fileInfo.put("isDirectory", file.isDirectory());
                fileInfo.put("isFile", !file.isDirectory());
                fileInfo.put("isPossibleBinary", isPossibleBinaryFile(file.getName()));
                
                if (file.isDirectory()) {
                    filesList.add(fileInfo);
                    if (currentDepth + 1 < maxDepth) {
                        browseArchiveContentsRecursive(fs, file, filesList, includePatterns, excludePatterns, 
                            maxDepth, currentDepth + 1);
                    }
                } else {
                    if (shouldIncludeFile(file.getName(), includePatterns, excludePatterns)) {
                        filesList.add(fileInfo);
                    }
                }
            }
        } catch (IOException e) {
            // Continue processing other files
        }
    }

    private String getArchiveType(File file) {
        String name = file.getName().toLowerCase();
        if (name.endsWith(".zip")) return "zip";
        if (name.endsWith(".tar") || name.endsWith(".tar.gz") || name.endsWith(".tgz")) return "tar";
        if (name.endsWith(".7z")) return "7z";
        if (name.endsWith(".rar")) return "rar";
        if (name.endsWith(".gz")) return "gzip";
        if (name.endsWith(".bz2")) return "bzip2";
        return "unknown";
    }
}