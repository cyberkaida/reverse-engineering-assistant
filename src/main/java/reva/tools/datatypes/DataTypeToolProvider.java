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
package reva.tools.datatypes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.services.DataTypeArchiveService;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.RevaProgramManager;
import reva.tools.AbstractToolProvider;
import reva.util.DataTypeParserUtil;
import reva.util.RevaInternalServiceRegistry;

/**
 * Tool provider for data type operations.
 * Provides tools to list data type archives and access data types.
 */
public class DataTypeToolProvider extends AbstractToolProvider {
    /**
     * Constructor
     * @param server The MCP server
     */
    public DataTypeToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() throws McpError {
        registerGetDataTypeArchivesTool();
        registerGetDataTypesTool();
        registerGetDataTypeByStringTool();
    }

    /**
     * Register a tool to get data type archives for a specific program
     * @throws McpError if there's an error registering the tool
     */
    private void registerGetDataTypeArchivesTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to get data type archives for"
        ));
        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-data-type-archives")
            .title("Get Data Type Archives")
            .description("Get data type archives for a specific program")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get the validated program using the standard helper
            Program targetProgram = getProgramFromArgs(request);

            // Create result data
            List<Map<String, Object>> archivesData = new ArrayList<>();

            // Always add built-in data type manager first
            DataTypeManager builtInDTM = BuiltInDataTypeManager.getDataTypeManager();
            Map<String, Object> builtInInfo = new HashMap<>();
            builtInInfo.put("name", builtInDTM.getName());
            builtInInfo.put("type", "BUILT_IN");
            builtInInfo.put("id", builtInDTM.getUniversalID() != null ? builtInDTM.getUniversalID().getValue() : null);
            builtInInfo.put("dataTypeCount", builtInDTM.getDataTypeCount(true));
            builtInInfo.put("categoryCount", builtInDTM.getCategoryCount());
            archivesData.add(builtInInfo);

            // Add the specified program first
            
            DataTypeManager dtm = targetProgram.getDataTypeManager();
            Map<String, Object> archiveInfo = new HashMap<>();
            archiveInfo.put("name", dtm.getName());
            archiveInfo.put("type", "PROGRAM");
            archiveInfo.put("id", dtm.getUniversalID() != null ? dtm.getUniversalID().getValue() : null);
            archiveInfo.put("dataTypeCount", dtm.getDataTypeCount(true));
            archiveInfo.put("categoryCount", dtm.getCategoryCount());
            archiveInfo.put("programPath", targetProgram.getDomainFile().getPathname());
            archivesData.add(archiveInfo);

            // Add any other open programs 
            List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
            for (Program program : openPrograms) {
                // Skip if this is the target program (already added)
                if (program.getDomainFile().getPathname().equals(targetProgram.getDomainFile().getPathname())) {
                    continue;
                }

                DataTypeManager programDtm = program.getDataTypeManager();

                Map<String, Object> programArchiveInfo = new HashMap<>();
                programArchiveInfo.put("name", programDtm.getName());
                programArchiveInfo.put("type", "PROGRAM");
                programArchiveInfo.put("id", programDtm.getUniversalID() != null ? programDtm.getUniversalID().getValue() : null);
                programArchiveInfo.put("dataTypeCount", programDtm.getDataTypeCount(true));
                programArchiveInfo.put("categoryCount", programDtm.getCategoryCount());
                programArchiveInfo.put("programPath", program.getDomainFile().getPathname());

                archivesData.add(programArchiveInfo);
            }

            // Try to add standalone data type managers if RevaPlugin is available
            // This is optional - if not available, we still have built-in and program types
            reva.plugin.RevaPlugin plugin = RevaInternalServiceRegistry.getService(reva.plugin.RevaPlugin.class);
            if (plugin != null) {
                DataTypeArchiveService archiveService = plugin.getTool().getService(DataTypeArchiveService.class);
                if (archiveService != null) {
                    // Get all data type managers
                    DataTypeManager[] managers = archiveService.getDataTypeManagers();

                    // Add standalone data type managers
                    for (DataTypeManager standaloneDtm : managers) {
                        // Skip if this is a program data type manager (already added)
                        boolean isProgramDTM = false;
                        for (Program program : openPrograms) {
                            if (standaloneDtm == program.getDataTypeManager()) {
                                isProgramDTM = true;
                                break;
                            }
                        }
                        if (isProgramDTM) {
                            continue;
                        }

                        Map<String, Object> standaloneArchiveInfo = new HashMap<>();
                        standaloneArchiveInfo.put("name", standaloneDtm.getName());
                        standaloneArchiveInfo.put("type", standaloneDtm.getType().toString());
                        standaloneArchiveInfo.put("id", standaloneDtm.getUniversalID() != null ? standaloneDtm.getUniversalID().getValue() : null);
                        standaloneArchiveInfo.put("dataTypeCount", standaloneDtm.getDataTypeCount(true));
                        standaloneArchiveInfo.put("categoryCount", standaloneDtm.getCategoryCount());

                        archivesData.add(standaloneArchiveInfo);
                    }
                }
            }

            // Create metadata about the result
            Map<String, Object> metadataInfo = new HashMap<>();
            metadataInfo.put("count", archivesData.size());

            // Create combined result
            List<Object> resultData = new ArrayList<>();
            resultData.add(metadataInfo);
            resultData.addAll(archivesData);

            return createMultiJsonResult(resultData);
        });
    }

    /**
     * Register a tool to get data types from an archive
     * @throws McpError if there's an error registering the tool
     */
    private void registerGetDataTypesTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to get data types from"
        ));
        properties.put("archiveName", Map.of(
            "type", "string",
            "description", "Name of the data type archive"
        ));
        properties.put("categoryPath", Map.of(
            "type", "string",
            "description", "Path to category to list data types from (e.g., '/Structure'). Use '/' for root category.",
            "default", "/"
        ));
        properties.put("includeSubcategories", Map.of(
            "type", "boolean",
            "description", "Whether to include data types from subcategories",
            "default", false
        ));
        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (0-based)",
            "default", 0
        ));
        properties.put("maxCount", Map.of(
            "type", "integer",
            "description", "Maximum number of data types to return",
            "default", 100
        ));

        List<String> required = List.of("programPath", "archiveName");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-data-types")
            .title("Get Data Types")
            .description("Get data types from a data type archive")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get the validated program using the standard helper
            Program targetProgram = getProgramFromArgs(request);
            
            // Get the required archive name parameter
            String archiveName;
            try {
                archiveName = getString(request, "archiveName");
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            }

            // Get pagination parameters
            String categoryPath = getOptionalString(request, "categoryPath", "/");
            boolean includeSubcategories = getOptionalBoolean(request, "includeSubcategories", false);
            int startIndex = getOptionalInt(request, "startIndex", 0);
            int maxCount = getOptionalInt(request, "maxCount", 100);

            // Get the program path for the data type manager lookup
            String programPath = targetProgram.getDomainFile().getPathname();
            
            // Find the data type manager for the specified program
            DataTypeManager dtm = DataTypeParserUtil.findDataTypeManager(archiveName, programPath);
            if (dtm == null) {
                return createErrorResult("Data type archive not found: " + archiveName);
            }

            // Get the category
            Category category;
            if (categoryPath.equals("/")) {
                category = dtm.getRootCategory();
            } else {
                // Create a CategoryPath from the string path
                ghidra.program.model.data.CategoryPath path = new ghidra.program.model.data.CategoryPath(categoryPath);
                category = dtm.getCategory(path);
                if (category == null) {
                    return createErrorResult("Category not found: " + categoryPath);
                }
            }

            // Create result data
            List<Map<String, Object>> dataTypesData = new ArrayList<>();

            // Add data types with pagination
            List<DataType> dataTypes = new ArrayList<>();
            if (includeSubcategories) {
                addDataTypesRecursively(category, dataTypes);
            } else {
                for (DataType dt : category.getDataTypes()) {
                    dataTypes.add(dt);
                }
            }

            // Apply pagination
            int endIndex = Math.min(startIndex + maxCount, dataTypes.size());
            if (startIndex < dataTypes.size()) {
                for (int i = startIndex; i < endIndex; i++) {
                    DataType dt = dataTypes.get(i);
                    Map<String, Object> dataTypeInfo = createDataTypeInfo(dt);
                    dataTypesData.add(dataTypeInfo);
                }
            }

            // Create metadata about the result
            Map<String, Object> metadataInfo = new HashMap<>();
            metadataInfo.put("archiveName", archiveName);
            metadataInfo.put("categoryPath", categoryPath);
            metadataInfo.put("includeSubcategories", includeSubcategories);
            metadataInfo.put("startIndex", startIndex);
            metadataInfo.put("totalCount", dataTypes.size());
            metadataInfo.put("returnedCount", dataTypesData.size());

            // Create combined result
            List<Object> resultData = new ArrayList<>();
            resultData.add(metadataInfo);
            resultData.addAll(dataTypesData);

            return createMultiJsonResult(resultData);
        });
    }

    /**
     * Register a tool to get a data type by string representation (e.g., "char**")
     * @throws McpError if there's an error registering the tool
     */
    private void registerGetDataTypeByStringTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to search for data types in"
        ));
        properties.put("dataTypeString", Map.of(
            "type", "string",
            "description", "String representation of the data type (e.g., 'char**', 'int[10]')"
        ));
        properties.put("archiveName", Map.of(
            "type", "string",
            "description", "Optional name of the data type archive to search in. If not provided, all archives will be searched.",
            "default", ""
        ));

        List<String> required = List.of("programPath", "dataTypeString");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-data-type-by-string")
            .title("Get Data Type by String")
            .description("Get a data type by its string representation")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get the validated program using the standard helper
            Program targetProgram = getProgramFromArgs(request);
            
            // Get the required data type string parameter
            String dataTypeString;
            try {
                dataTypeString = getString(request, "dataTypeString");
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            }

            // Get the optional archive name
            String archiveName = getOptionalString(request, "archiveName", "");

            // Get the program path for the data type manager lookup
            String programPath = targetProgram.getDomainFile().getPathname();

            try {
                // Use the utility class to parse the data type with program context
                Map<String, Object> result = DataTypeParserUtil.parseDataTypeFromString(dataTypeString, archiveName, programPath);

                if (result == null) {
                    return createErrorResult("Could not find or parse data type: " + dataTypeString);
                }

                return createJsonResult(result);
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (IllegalStateException e) {
                Msg.error(this, "Data type archive service is not available", e);
                return createErrorResult("Data type archive service is not available");
            } catch (Exception e) {
                Msg.error(this, "Error parsing data type: " + dataTypeString, e);
                return createErrorResult("Error parsing data type: " + e.getMessage());
            }
        });
    }

    /**
     * Add data types recursively from a category and its subcategories
     * @param category The category to get data types from
     * @param dataTypes The list to add data types to
     */
    private void addDataTypesRecursively(Category category, List<DataType> dataTypes) {
        // Add data types from this category
        for (DataType dt : category.getDataTypes()) {
            dataTypes.add(dt);
        }

        // Add data types from subcategories
        for (Category subCategory : category.getCategories()) {
            addDataTypesRecursively(subCategory, dataTypes);
        }
    }

    /**
     * Create a map with information about a data type
     * @param dt The data type
     * @return Map with data type information
     */
    private Map<String, Object> createDataTypeInfo(DataType dt) {
        return DataTypeParserUtil.createDataTypeInfo(dt);
    }
}
