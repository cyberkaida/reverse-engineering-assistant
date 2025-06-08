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
        registerGetOpenArchivesTool();
        registerGetDataTypesTool();
        registerGetDataTypeByStringTool();
    }

    /**
     * Register a tool to get open data type archives
     * @throws McpError if there's an error registering the tool
     */
    private void registerGetOpenArchivesTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        // This tool doesn't require any parameters
        List<String> required = new ArrayList<>();

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-data-type-archives",
            "Get all open data type archives",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get the RevaPlugin to access the PluginTool
            reva.plugin.RevaPlugin plugin = RevaInternalServiceRegistry.getService(reva.plugin.RevaPlugin.class);
            if (plugin == null) {
                Msg.error(this, "RevaPlugin is not available");
                return createErrorResult("RevaPlugin is not available");
            }

            // Get data type archive service from the plugin tool
            DataTypeArchiveService archiveService = plugin.getTool().getService(DataTypeArchiveService.class);
            if (archiveService == null) {
                Msg.error(this, "Data type archive service is not available");
                return createErrorResult("Data type archive service is not available");
            }

            // Get all data type managers
            DataTypeManager[] managers = archiveService.getDataTypeManagers();

            // Create result data
            List<Map<String, Object>> archivesData = new ArrayList<>();

            // Add program data type managers
            List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
            for (Program program : openPrograms) {
                DataTypeManager dtm = program.getDataTypeManager();

                Map<String, Object> archiveInfo = new HashMap<>();
                archiveInfo.put("name", dtm.getName());
                archiveInfo.put("type", "PROGRAM");
                archiveInfo.put("id", dtm.getUniversalID() != null ? dtm.getUniversalID().getValue() : null);
                archiveInfo.put("dataTypeCount", dtm.getDataTypeCount(true));
                archiveInfo.put("categoryCount", dtm.getCategoryCount());
                archiveInfo.put("programPath", program.getDomainFile().getPathname());

                archivesData.add(archiveInfo);
            }

            // Add standalone data type managers
            for (DataTypeManager dtm : managers) {
                // Skip if this is a program data type manager (already added)
                boolean isProgramDTM = false;
                for (Program program : openPrograms) {
                    if (dtm == program.getDataTypeManager()) {
                        isProgramDTM = true;
                        break;
                    }
                }
                if (isProgramDTM) {
                    continue;
                }

                Map<String, Object> archiveInfo = new HashMap<>();
                archiveInfo.put("name", dtm.getName());
                archiveInfo.put("type", dtm.getType().toString());
                archiveInfo.put("id", dtm.getUniversalID() != null ? dtm.getUniversalID().getValue() : null);
                archiveInfo.put("dataTypeCount", dtm.getDataTypeCount(true));
                archiveInfo.put("categoryCount", dtm.getCategoryCount());

                archivesData.add(archiveInfo);
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

        List<String> required = List.of("archiveName");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-data-types",
            "Get data types from a data type archive",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get the archive name from the request
            String archiveName;
            try {
                archiveName = getString(args, "archiveName");
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            }

            // Get pagination parameters
            String categoryPath = getOptionalString(args, "categoryPath", "/");
            boolean includeSubcategories = getOptionalBoolean(args, "includeSubcategories", false);
            int startIndex = getOptionalInt(args, "startIndex", 0);
            int maxCount = getOptionalInt(args, "maxCount", 100);

            // Find the data type manager
            DataTypeManager dtm = DataTypeParserUtil.findDataTypeManager(archiveName);
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
        properties.put("dataTypeString", Map.of(
            "type", "string",
            "description", "String representation of the data type (e.g., 'char**', 'int[10]')"
        ));
        properties.put("archiveName", Map.of(
            "type", "string",
            "description", "Optional name of the data type archive to search in. If not provided, all archives will be searched.",
            "default", ""
        ));

        List<String> required = List.of("dataTypeString");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-data-type-by-string",
            "Get a data type by its string representation",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get the data type string from the request
            String dataTypeString = (String) args.get("dataTypeString");

            // Get the optional archive name
            String archiveName = args.containsKey("archiveName") ?
                (String) args.get("archiveName") : "";

            try {
                // Use the utility class to parse the data type
                Map<String, Object> result = DataTypeParserUtil.parseDataTypeFromString(dataTypeString, archiveName);

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
