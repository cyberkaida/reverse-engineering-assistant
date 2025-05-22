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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.RevaProgramManager;
import reva.tools.AbstractToolProvider;
import reva.util.SchemaUtil;

/**
 * Tool provider for project-related operations.
 * Provides tools to get the current program and list project files.
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
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-current-program",
            "Get the currently active program in Ghidra",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get all open programs
            List<Program> openPrograms = RevaProgramManager.getOpenPrograms();

            if (openPrograms.isEmpty()) {
                return createErrorResult("No programs are currently open in Ghidra");
            }

            // For now, just return the first program (assuming it's the active one)
            Program program = openPrograms.get(0);

            // Create result data
            Map<String, Object> programInfo = new HashMap<>();
            programInfo.put("name", program.getName());
            programInfo.put("path", program.getDomainFile().getPathname());
            programInfo.put("language", program.getLanguage().getLanguageID().getIdAsString());
            programInfo.put("compilerSpec", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
            programInfo.put("executable", program.getExecutablePath());
            programInfo.put("creationDate", program.getCreationDate());
            programInfo.put("sizeBytes", program.getMemory().getSize());
            programInfo.put("symbolCount", program.getSymbolTable().getNumSymbols());
            programInfo.put("functionCount", program.getFunctionManager().getFunctionCount());
            programInfo.put("programId", program.getDomainFile().getFileID());
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
        McpSchema.Tool tool = new McpSchema.Tool(
            "list-project-files",
            "List files and folders in the Ghidra project",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get the folder path from the request
            String folderPath = (String) args.get("folderPath");
            if (folderPath == null) {
                return createErrorResult("No folder path provided");
            }

            // Get the recursive flag
            boolean recursive = args.containsKey("recursive") ?
                (Boolean) args.get("recursive") : false;

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
        McpSchema.Tool tool = new McpSchema.Tool(
            "list-open-programs",
            "List all programs currently open in Ghidra across all tools",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get all open programs
            List<Program> openPrograms = RevaProgramManager.getOpenPrograms();

            if (openPrograms.isEmpty()) {
                return createErrorResult("No programs are currently open in Ghidra");
            }

            // Create result data
            List<Map<String, Object>> programsData = new ArrayList<>();

            for (Program program : openPrograms) {
                Map<String, Object> programInfo = new HashMap<>();
                programInfo.put("name", program.getName());
                programInfo.put("path", program.getDomainFile().getPathname());
                programInfo.put("language", program.getLanguage().getLanguageID().getIdAsString());
                programInfo.put("compilerSpec", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
                programInfo.put("executable", program.getExecutablePath());
                programInfo.put("creationDate", program.getCreationDate());
                programInfo.put("sizeBytes", program.getMemory().getSize());
                programInfo.put("functionCount", program.getFunctionManager().getFunctionCount());
                programInfo.put("symbolCount", program.getSymbolTable().getNumSymbols());
                programInfo.put("programId", program.getDomainFile().getFileID());

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
     * Collect files and subfolders from a folder
     * @param folder The folder to collect from
     * @param filesList The list to add file info to
     * @param pathPrefix Path prefix for nested items
     */
    private void collectFilesInFolder(DomainFolder folder, List<Map<String, Object>> filesList, String pathPrefix) {
        // Add subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            Map<String, Object> folderInfo = new HashMap<>();
            folderInfo.put("name", subfolder.getName());
            folderInfo.put("path", pathPrefix + subfolder.getName());
            folderInfo.put("type", "folder");
            folderInfo.put("childCount", subfolder.getFiles().length + subfolder.getFolders().length);
            filesList.add(folderInfo);
        }

        // Add files
        for (DomainFile file : folder.getFiles()) {
            Map<String, Object> fileInfo = new HashMap<>();
            fileInfo.put("name", file.getName());
            fileInfo.put("path", file.getPathname());
            fileInfo.put("type", "file");
            fileInfo.put("contentType", file.getContentType());
            fileInfo.put("fileID", file.getFileID());
            fileInfo.put("lastModified", file.getLastModifiedTime());
            fileInfo.put("readOnly", file.isReadOnly());
            fileInfo.put("versioned", file.isVersioned());
            fileInfo.put("checked", file.isCheckedOut());
            fileInfo.put("hasMetadata", file.getMetadata() != null);

            // Add program-specific info if it's a program
            if (file.getContentType().equals("Program")) {
                try {
                    fileInfo.put("programLanguage", file.getMetadata().get("CREATED_WITH_LANGUAGE"));
                    fileInfo.put("programSize", file.getMetadata().get("Executable MD5"));
                    fileInfo.put("programCreator", file.getMetadata().get("Created With"));
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