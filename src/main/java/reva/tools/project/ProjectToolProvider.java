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

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.data.DefaultCheckinHandler;
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
import ghidra.util.task.TaskMonitor;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.plugins.importer.batch.BatchInfo;
import ghidra.plugins.importer.tasks.ImportBatchTask;
import ghidra.util.task.TaskLauncher;
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
        registerImportFileTool();
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
     * @throws McpError if there's an error registering the tool
     */
    private void registerCheckinProgramTool() throws McpError {
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
                    // Determine specific reason why checkin is not possible
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

            } catch (Exception e) {
                return createErrorResult("Checkin failed: " + e.getMessage());
            }
        });
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
     * @throws McpError if there's an error registering the tool
     */
    private void registerAnalyzeProgramTool() throws McpError {
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
     * @throws McpError if there's an error registering the tool
     */
    private void registerChangeProcessorTool() throws McpError {
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
     * @throws McpError if there's an error registering the tool
     */
    private void registerImportFileTool() throws McpError {
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

        // maxDepth parameter (optional)
        Map<String, Object> maxDepthProperty = new HashMap<>();
        maxDepthProperty.put("type", "integer");
        maxDepthProperty.put("description", "Maximum container depth to recurse into (default: 20)");
        properties.put("maxDepth", maxDepthProperty);

        // analyzeAfterImport parameter (optional)
        Map<String, Object> analyzeProperty = new HashMap<>();
        analyzeProperty.put("type", "boolean");
        analyzeProperty.put("description", "Run auto-analysis after import (default: false)");
        properties.put("analyzeAfterImport", analyzeProperty);

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

                // Get optional parameters with defaults
                String destinationFolder = getOptionalString(request, "destinationFolder", "/");
                boolean recursive = getOptionalBoolean(request, "recursive", true);
                int maxDepth = getOptionalInt(request, "maxDepth", 20);
                boolean analyzeAfterImport = getOptionalBoolean(request, "analyzeAfterImport", false);

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

                // Create and launch the import task
                ImportBatchTask importTask = new ImportBatchTask(batchInfo, destFolder, null, true, false);
                TaskLauncher launcher = new TaskLauncher(importTask, null);

                // Create result data
                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("importedFrom", path);
                result.put("destinationFolder", destinationFolder);
                result.put("filesDiscovered", batchInfo.getTotalCount());
                result.put("groupsCreated", batchInfo.getGroups().size());
                result.put("maxDepthUsed", maxDepth);
                result.put("wasRecursive", recursive);
                result.put("analyzeAfterImport", analyzeAfterImport);
                result.put("message", "Import completed successfully. " + batchInfo.getTotalCount() + " files imported.");

                return createJsonResult(result);

            } catch (IllegalArgumentException e) {
                return createErrorResult("Invalid parameter: " + e.getMessage());
            } catch (Exception e) {
                return createErrorResult("Import failed: " + e.getMessage());
            }
        });
    }

}