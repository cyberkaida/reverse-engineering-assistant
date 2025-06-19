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
package reva.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.services.DataTypeArchiveService;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import reva.plugin.RevaProgramManager;

/**
 * Utility class for parsing data types from strings.
 * Used by various tools that need to convert string representations to Ghidra data types.
 */
public class DataTypeParserUtil {

    /**
     * Find a data type manager by name
     * @param name Name of the data type manager
     * @return The data type manager or null if not found
     */
    public static DataTypeManager findDataTypeManager(String name) {
        return findDataTypeManager(name, null);
    }

    /**
     * Find a data type manager by name, prioritizing the specified program
     * @param name Name of the data type manager
     * @param programPath Path to the program to prioritize (can be null)
     * @return The data type manager or null if not found
     */
    public static DataTypeManager findDataTypeManager(String name, String programPath) {
        // First check the specified program (highest priority)
        if (programPath != null && !programPath.isEmpty()) {
            Program targetProgram = RevaProgramManager.getProgramByPath(programPath);
            if (targetProgram != null) {
                DataTypeManager dtm = targetProgram.getDataTypeManager();
                if (dtm.getName().equals(name)) {
                    return dtm;
                }
            }
        }

        // Then check all open programs (program-specific data types)
        List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
        for (Program program : openPrograms) {
            DataTypeManager dtm = program.getDataTypeManager();
            if (dtm.getName().equals(name)) {
                return dtm;
            }
        }

        // Then check standalone data type managers (loaded/associated archives)
        reva.plugin.RevaPlugin plugin = RevaInternalServiceRegistry.getService(reva.plugin.RevaPlugin.class);
        if (plugin != null) {
            DataTypeArchiveService archiveService = plugin.getTool().getService(DataTypeArchiveService.class);
            if (archiveService != null) {
                DataTypeManager[] managers = archiveService.getDataTypeManagers();
                for (DataTypeManager dtm : managers) {
                    if (dtm.getName().equals(name)) {
                        return dtm;
                    }
                }
            }
        }

        // Finally check built-in data type manager (fallback)
        DataTypeManager builtInDTM = BuiltInDataTypeManager.getDataTypeManager();
        if (builtInDTM.getName().equals(name)) {
            return builtInDTM;
        }

        return null;
    }

    /**
     * Parse a data type from its string representation and return the actual DataType object
     * This method is for internal use by tools that need the actual DataType object,
     * not for MCP responses which should only contain metadata.
     *
     * @param dataTypeString String representation of the data type (e.g., "char**", "int[10]")
     * @param archiveName Optional name of specific archive to search in, or empty string to search all
     * @return The DataType object or null if not found
     * @throws Exception if there's an error parsing the data type
     */
    public static DataType parseDataTypeObjectFromString(String dataTypeString, String archiveName)
            throws Exception {
        if (dataTypeString == null || dataTypeString.isEmpty()) {
            throw new IllegalArgumentException("No data type string provided");
        }

        // Get data type managers to search in - for this method we use empty programPath since it's the legacy method
        List<DataTypeManager> managersToSearch = getDataTypeManagersToSearch(archiveName, "");
        if (managersToSearch.isEmpty()) {
            throw new IllegalStateException("No data type managers available");
        }

        // Search for the data type
        for (DataTypeManager dtm : managersToSearch) {
            try {
                // Use Ghidra's DataTypeParser to parse the string
                ghidra.util.data.DataTypeParser parser = new ghidra.util.data.DataTypeParser(
                    dtm, dtm, null, ghidra.util.data.DataTypeParser.AllowedDataTypes.ALL);

                DataType dt = parser.parse(dataTypeString);
                if (dt != null) {
                    return dt;
                }
            } catch (Exception e) {
                // Continue with next manager if this one fails
            }
        }

        return null;
    }


    /**
     * Parse a data type from its string representation with program context
     * @param dataTypeString String representation of the data type (e.g., "char**", "int[10]")
     * @param archiveName Optional name of specific archive to search in, or empty string to search all
     * @param programPath Path to the program to prioritize for searching
     * @return Map containing the found data type information or null if not found
     * @throws Exception if there's an error parsing the data type
     */
    public static Map<String, Object> parseDataTypeFromString(String dataTypeString, String archiveName, String programPath)
            throws Exception {
        if (dataTypeString == null || dataTypeString.isEmpty()) {
            throw new IllegalArgumentException("No data type string provided");
        }

        // Get data type managers to search in
        List<DataTypeManager> managersToSearch = getDataTypeManagersToSearch(archiveName, programPath);
        if (managersToSearch.isEmpty()) {
            throw new IllegalStateException("No data type managers available");
        }

        // Search for the data type
        DataType foundDataType = null;
        DataTypeManager foundManager = null;

        for (DataTypeManager dtm : managersToSearch) {
            try {
                // Use Ghidra's DataTypeParser to parse the string
                ghidra.util.data.DataTypeParser parser = new ghidra.util.data.DataTypeParser(
                    dtm, dtm, null, ghidra.util.data.DataTypeParser.AllowedDataTypes.ALL);

                DataType dt = parser.parse(dataTypeString);
                if (dt != null) {
                    foundDataType = dt;
                    foundManager = dtm;
                    break;
                }
            } catch (Exception e) {
                // Continue with next manager if this one fails
            }
        }

        if (foundDataType == null) {
            return null;
        }

        // Create result data
        // NOTE: We do NOT include the actual DataType object in the response map
        // as it can contain circular references and recursive structures that would
        // cause serialization issues. Instead, we only include metadata about the data type.
        Map<String, Object> dataTypeInfo = createDataTypeInfo(foundDataType);
        dataTypeInfo.put("archiveName", foundManager.getName());
        dataTypeInfo.put("requestedString", dataTypeString);

        return dataTypeInfo;
    }


    /**
     * Get list of data type managers to search based on the archive name and program context
     * @param archiveName Name of archive to search in, or empty string to search all
     * @param programPath Path to the program to search in (required)
     * @return List of data type managers to search
     */
    private static List<DataTypeManager> getDataTypeManagersToSearch(String archiveName, String programPath) {
        List<DataTypeManager> managersToSearch = new ArrayList<>();

        if (archiveName != null && !archiveName.isEmpty()) {
            // Search in the specified archive only, prioritizing the specified program
            DataTypeManager dtm = findDataTypeManager(archiveName, programPath);
            if (dtm != null) {
                managersToSearch.add(dtm);
            }
            // If looking for a specific archive but not found, still include built-in types as fallback
            if (managersToSearch.isEmpty()) {
                managersToSearch.add(BuiltInDataTypeManager.getDataTypeManager());
            }
        } else {
            // Always add built-in data type manager first - it contains basic types like int, char, etc.
            managersToSearch.add(BuiltInDataTypeManager.getDataTypeManager());
            
            // Add the specified program's data type manager first
            Program targetProgram = RevaProgramManager.getProgramByPath(programPath);
            if (targetProgram != null) {
                managersToSearch.add(targetProgram.getDataTypeManager());
            }
            
            // Add other open program data type managers
            List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
            for (Program program : openPrograms) {
                // Skip if this is the target program (already added)
                if (targetProgram != null && program.getDomainFile().getPathname().equals(targetProgram.getDomainFile().getPathname())) {
                    continue;
                }
                managersToSearch.add(program.getDataTypeManager());
            }

            // Try to add standalone data type managers if RevaPlugin is available
            // This is optional - if not available, we can still work with built-in and program types
            reva.plugin.RevaPlugin plugin = RevaInternalServiceRegistry.getService(reva.plugin.RevaPlugin.class);
            if (plugin != null) {
                DataTypeArchiveService archiveService = plugin.getTool().getService(DataTypeArchiveService.class);
                if (archiveService != null) {
                    // Add standalone data type managers
                    Collections.addAll(managersToSearch, archiveService.getDataTypeManagers());
                }
            }
        }

        return managersToSearch;
    }

    /**
     * Create a map with information about a data type
     * @param dt The data type
     * @return Map with data type information
     */
    public static Map<String, Object> createDataTypeInfo(DataType dt) {
        Map<String, Object> info = new HashMap<>();
        info.put("name", dt.getName());
        info.put("displayName", dt.getDisplayName());
        info.put("categoryPath", dt.getCategoryPath().getPath());
        info.put("description", dt.getDescription());
        info.put("id", dt.getUniversalID() != null ? dt.getUniversalID().getValue() : null);
        info.put("size", dt.getLength());
        info.put("alignment", dt.getAlignment());
        info.put("dataTypeName", dt.getClass().getSimpleName());

        // Check if data type is part of the built-in types
        if (dt.getDataTypeManager() != null) {
            info.put("sourceArchiveName", dt.getSourceArchive() != null ?
                dt.getSourceArchive().getName() : "Local");
        }

        return info;
    }
}
