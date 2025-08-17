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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.LoadException;
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

        List<String> required = List.of("filePath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("load-binary")
            .title("Load Binary File")
            .description("Load a binary file from disk into the Ghidra project")
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

            // Get the active project
            Project project = AppInfo.getActiveProject();
            if (project == null) {
                return createErrorResult("No active project found");
            }

            // Verify the file exists
            File binaryFile = new File(filePath);
            if (!binaryFile.exists()) {
                return createErrorResult("File not found: " + filePath);
            }
            if (!binaryFile.isFile()) {
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
                        }
                    } catch (Exception e) {
                        return createErrorResult("Invalid processor spec '" + processorSpec + "': " + e.getMessage());
                    }
                }

                // Import the binary
                LoadResults<Program> loadResults;
                if (language != null && compilerSpec != null) {
                    // Import with specific language/compiler
                    loadResults = AutoImporter.importByLookingForLcs(
                        binaryFile, project, projectPath, language, compilerSpec,
                        this, messageLog, TaskMonitor.DUMMY);
                } else {
                    // Auto-detect format and language
                    loadResults = AutoImporter.importByUsingBestGuess(
                        binaryFile, project, projectPath, this, messageLog, TaskMonitor.DUMMY);
                }

                // Check if import succeeded
                if (loadResults == null || loadResults.size() == 0) {
                    String errorMsg = "Failed to import binary: " + binaryFile.getName();
                    if (messageLog.hasMessages()) {
                        errorMsg += "\n" + messageLog.toString();
                    }
                    return createErrorResult(errorMsg);
                }

                // Get the primary imported program
                Loaded<Program> primaryLoaded = loadResults.getPrimary();
                Program program = primaryLoaded.getDomainObject();

                // Save the program to the project
                DomainFolder folder = project.getProjectData().getFolder(projectPath);
                if (folder == null) {
                    // Create folder if it doesn't exist
                    folder = project.getProjectData().getRootFolder().createFolder(projectPath);
                }

                // Save the program
                loadResults.save(project, this, messageLog, TaskMonitor.DUMMY);

                // Run auto-analysis if requested
                if (runAnalysis) {
                    AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
                    mgr.initializeOptions();
                    mgr.reAnalyzeAll(null);
                    mgr.startAnalysis(TaskMonitor.DUMMY);
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
                result.put("programPath", program.getDomainFile().getPathname());
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
        properties.put("programPath", SchemaUtil.createStringProperty(
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
        if (parts.length < 3 || parts.length > 4) {
            return null;
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
            // Try alternate format: just the processor name with default settings
            try {
                List<LanguageDescription> descriptions = languageService.getLanguageDescriptions(false);
                for (LanguageDescription desc : descriptions) {
                    if (desc.getProcessor().toString().equalsIgnoreCase(spec) ||
                        desc.getLanguageID().getIdAsString().startsWith(spec.toLowerCase())) {
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
}