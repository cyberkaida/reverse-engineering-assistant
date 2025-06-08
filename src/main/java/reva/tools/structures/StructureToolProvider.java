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
package reva.tools.structures;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.RevaProgramManager;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.DataTypeParserUtil;
import reva.util.SchemaUtil;

/**
 * Tool provider for structure definition and manipulation operations.
 * Provides tools to create, modify, and apply structures in Ghidra programs.
 */
public class StructureToolProvider extends AbstractToolProvider {
    /**
     * Constructor
     * @param server The MCP server
     */
    public StructureToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() throws McpError {
        registerParseCStructureTool();
        registerValidateCStructureTool();
        registerCreateStructureTool();
        registerAddStructureFieldTool();
        registerGetStructureInfoTool();
        registerListStructuresTool();
        registerApplyStructureTool();
        registerDeleteStructureTool();
        registerParseCHeaderTool();
    }

    /**
     * Register tool to parse C-style structure definitions
     */
    private void registerParseCStructureTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("cDefinition", SchemaUtil.createStringProperty("C-style structure definition"));
        properties.put("category", SchemaUtil.createOptionalStringProperty("Category path (default: /)"));
        
        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("cDefinition");

        McpSchema.Tool tool = new McpSchema.Tool(
            "parse-c-structure",
            "Parse and create structures from C-style definitions",
            createSchema(properties, required)
        );

        registerTool(tool, (exchange, args) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(args);
                String cDefinition = getString(args, "cDefinition");
                String category = getOptionalString(args, "category", "/");

                DataTypeManager dtm = program.getDataTypeManager();
                CParser parser = new CParser(dtm);
                
                int txId = program.startTransaction("Parse C Structure");
                try {
                    DataType dt = parser.parse(cDefinition);
                    if (dt == null) {
                        throw new Exception("Failed to parse structure definition");
                    }

                    // Move to specified category
                    CategoryPath catPath = new CategoryPath(category);
                    Category cat = dtm.createCategory(catPath);
                    
                    // Resolve into the program's DTM
                    DataType resolved = dtm.resolve(dt, DataTypeConflictHandler.REPLACE_HANDLER);
                    if (cat != null && resolved.getCategoryPath() != catPath) {
                        resolved.setName(resolved.getName());
                        cat.moveDataType(resolved, DataTypeConflictHandler.REPLACE_HANDLER);
                    }
                    
                    program.endTransaction(txId, true);
                    
                    // Return structure info
                    Map<String, Object> result = createStructureInfo(resolved);
                    result.put("message", "Successfully created structure: " + resolved.getName());
                    return createJsonResult(result);
                    
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    Msg.error(this, "Failed to parse C structure", e);
                    return createErrorResult("Failed to parse: " + e.getMessage());
                }
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to validate C-style structure definitions without creating them
     */
    private void registerValidateCStructureTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("cDefinition", SchemaUtil.createStringProperty("C-style structure definition to validate"));
        
        List<String> required = new ArrayList<>();
        required.add("cDefinition");

        McpSchema.Tool tool = new McpSchema.Tool(
            "validate-c-structure",
            "Validate C-style structure definition without creating it",
            createSchema(properties, required)
        );

        registerTool(tool, (exchange, args) -> {
            try {
                String cDefinition = getString(args, "cDefinition");
                
                // Create a temporary parser with a standalone DTM
                DataTypeManager tempDtm = new StandAloneDataTypeManager("temp");
                CParser parser = new CParser(tempDtm);
                
                try {
                    DataType dt = parser.parse(cDefinition);
                    if (dt == null) {
                        return createErrorResult("Invalid structure definition");
                    }
                    
                    Map<String, Object> result = new HashMap<>();
                    result.put("valid", true);
                    result.put("parsedType", dt.getName());
                    result.put("displayName", dt.getDisplayName());
                    result.put("size", dt.getLength());
                    
                    if (dt instanceof Structure) {
                        Structure struct = (Structure) dt;
                        result.put("fieldCount", struct.getNumComponents());
                        result.put("isUnion", false);
                    } else if (dt instanceof Union) {
                        Union union = (Union) dt;
                        result.put("fieldCount", union.getNumComponents());
                        result.put("isUnion", true);
                    }
                    
                    return createJsonResult(result);
                    
                } catch (Exception e) {
                    Map<String, Object> result = new HashMap<>();
                    result.put("valid", false);
                    result.put("error", e.getMessage());
                    return createJsonResult(result);
                } finally {
                    tempDtm.close();
                }
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to create an empty structure
     */
    private void registerCreateStructureTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("name", SchemaUtil.createStringProperty("Name of the structure"));
        properties.put("size", SchemaUtil.createOptionalNumberProperty("Initial size (0 for auto-sizing)"));
        properties.put("type", SchemaUtil.createOptionalStringProperty("Type: 'structure' or 'union' (default: structure)"));
        properties.put("category", SchemaUtil.createOptionalStringProperty("Category path (default: /)"));
        properties.put("packed", SchemaUtil.createOptionalBooleanProperty("Whether structure should be packed"));
        properties.put("description", SchemaUtil.createOptionalStringProperty("Description of the structure"));
        
        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("name");

        McpSchema.Tool tool = new McpSchema.Tool(
            "create-structure",
            "Create a new empty structure or union",
            createSchema(properties, required)
        );

        registerTool(tool, (exchange, args) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(args);
                String name = getString(args, "name");
                int size = getOptionalInt(args, "size", 0);
                String type = getOptionalString(args, "type", "structure");
                String category = getOptionalString(args, "category", "/");
                boolean packed = getOptionalBoolean(args, "packed", false);
                String description = getOptionalString(args, "description", null);

                DataTypeManager dtm = program.getDataTypeManager();
                CategoryPath catPath = new CategoryPath(category);
                
                int txId = program.startTransaction("Create Structure");
                try {
                    // Create category if needed
                    Category cat = dtm.createCategory(catPath);
                    
                    // Create structure or union
                    Composite composite;
                    if ("union".equalsIgnoreCase(type)) {
                        composite = new UnionDataType(catPath, name, dtm);
                    } else {
                        composite = new StructureDataType(catPath, name, size, dtm);
                        if (packed && composite instanceof Structure) {
                            ((Structure) composite).setPackingEnabled(true);
                        }
                    }
                    
                    if (description != null) {
                        composite.setDescription(description);
                    }
                    
                    // Add to DTM
                    DataType resolved = dtm.addDataType(composite, DataTypeConflictHandler.REPLACE_HANDLER);
                    
                    program.endTransaction(txId, true);
                    
                    Map<String, Object> result = createStructureInfo(resolved);
                    result.put("message", "Successfully created " + type + ": " + name);
                    return createJsonResult(result);
                    
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    Msg.error(this, "Failed to create structure", e);
                    return createErrorResult("Failed to create structure: " + e.getMessage());
                }
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to add fields to structures
     */
    private void registerAddStructureFieldTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("structureName", SchemaUtil.createStringProperty("Name of the structure"));
        properties.put("fieldName", SchemaUtil.createStringProperty("Name of the field"));
        properties.put("dataType", SchemaUtil.createStringProperty("Data type (e.g., 'int', 'char[32]')"));
        properties.put("offset", SchemaUtil.createOptionalNumberProperty("Offset (for structures, omit to append)"));
        properties.put("comment", SchemaUtil.createOptionalStringProperty("Field comment"));
        
        // Bitfield support
        Map<String, Object> bitfieldProps = new HashMap<>();
        bitfieldProps.put("bitSize", SchemaUtil.createNumberProperty("Size in bits"));
        bitfieldProps.put("bitOffset", SchemaUtil.createOptionalNumberProperty("Bit offset within byte"));
        properties.put("bitfield", SchemaUtil.createOptionalObjectProperty("Bitfield configuration", bitfieldProps));
        
        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("structureName");
        required.add("fieldName");
        required.add("dataType");

        McpSchema.Tool tool = new McpSchema.Tool(
            "add-structure-field",
            "Add a field to an existing structure",
            createSchema(properties, required)
        );

        registerTool(tool, (exchange, args) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(args);
                String structureName = getString(args, "structureName");
                String fieldName = getString(args, "fieldName");
                String dataTypeStr = getString(args, "dataType");
                Integer offset = getOptionalInteger(args, "offset", null);
                String comment = getOptionalString(args, "comment", null);
                Map<String, Object> bitfield = getOptionalMap(args, "bitfield", null);

                DataTypeManager dtm = program.getDataTypeManager();
                
                // Find the structure
                DataType dt = dtm.getDataType(structureName);
                if (dt == null) {
                    // Search in all categories
                    dt = findDataTypeByName(dtm, structureName);
                }
                
                if (dt == null) {
                    return createErrorResult("Structure not found: " + structureName);
                }
                
                if (!(dt instanceof Composite)) {
                    return createErrorResult("Data type is not a structure or union: " + structureName);
                }
                
                Composite composite = (Composite) dt;
                
                // Parse the field data type
                DataType fieldType = null;
                try {
                    // First try using the program's own DTM directly for better test compatibility
                    DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
                    fieldType = parser.parse(dataTypeStr);
                } catch (Exception e) {
                    // Fallback to the utility method
                    try {
                        fieldType = DataTypeParserUtil.parseDataTypeObjectFromString(dataTypeStr, "");
                    } catch (Exception e2) {
                        // Ignore fallback failure
                    }
                }
                
                if (fieldType == null) {
                    return createErrorResult("Invalid data type: " + dataTypeStr);
                }
                
                int txId = program.startTransaction("Add Structure Field");
                try {
                    if (bitfield != null) {
                        // Handle bitfield
                        if (!(composite instanceof Structure)) {
                            throw new Exception("Bitfields are only supported in structures, not unions");
                        }
                        Structure struct = (Structure) composite;
                        int bitSize = getInt(bitfield, "bitSize");
                        
                        if (offset != null) {
                            int bitOffset = getOptionalInt(bitfield, "bitOffset", 0);
                            struct.insertBitFieldAt(offset, fieldType.getLength(), bitOffset, 
                                fieldType, bitSize, fieldName, comment);
                        } else {
                            struct.addBitField(fieldType, bitSize, fieldName, comment);
                        }
                    } else {
                        // Regular field
                        if (composite instanceof Structure) {
                            Structure struct = (Structure) composite;
                            if (offset != null) {
                                struct.insertAtOffset(offset, fieldType, fieldType.getLength(), 
                                    fieldName, comment);
                            } else {
                                struct.add(fieldType, fieldName, comment);
                            }
                        } else if (composite instanceof Union) {
                            Union union = (Union) composite;
                            union.add(fieldType, fieldName, comment);
                        }
                    }
                    
                    program.endTransaction(txId, true);
                    
                    Map<String, Object> result = createStructureInfo(composite);
                    result.put("message", "Successfully added field: " + fieldName);
                    return createJsonResult(result);
                    
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    Msg.error(this, "Failed to add field", e);
                    return createErrorResult("Failed to add field: " + e.getMessage());
                }
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to get structure information
     */
    private void registerGetStructureInfoTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("structureName", SchemaUtil.createStringProperty("Name of the structure"));
        
        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("structureName");

        McpSchema.Tool tool = new McpSchema.Tool(
            "get-structure-info",
            "Get detailed information about a structure",
            createSchema(properties, required)
        );

        registerTool(tool, (exchange, args) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(args);
                String structureName = getString(args, "structureName");

                DataTypeManager dtm = program.getDataTypeManager();
                DataType dt = findDataTypeByName(dtm, structureName);
                
                if (dt == null) {
                    return createErrorResult("Structure not found: " + structureName);
                }
                
                if (!(dt instanceof Composite)) {
                    return createErrorResult("Data type is not a structure or union: " + structureName);
                }
                
                return createJsonResult(createDetailedStructureInfo((Composite) dt));
                
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to list structures
     */
    private void registerListStructuresTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("category", SchemaUtil.createOptionalStringProperty("Filter by category path"));
        properties.put("nameFilter", SchemaUtil.createOptionalStringProperty("Filter by name (substring match)"));
        properties.put("includeBuiltIn", SchemaUtil.createOptionalBooleanProperty("Include built-in types"));
        
        List<String> required = new ArrayList<>();
        required.add("programPath");

        McpSchema.Tool tool = new McpSchema.Tool(
            "list-structures",
            "List all structures in a program",
            createSchema(properties, required)
        );

        registerTool(tool, (exchange, args) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(args);
                String categoryFilter = getOptionalString(args, "category", null);
                String nameFilter = getOptionalString(args, "nameFilter", null);
                boolean includeBuiltIn = getOptionalBoolean(args, "includeBuiltIn", false);

                DataTypeManager dtm = program.getDataTypeManager();
                List<Map<String, Object>> structures = new ArrayList<>();
                
                // Get all data types
                Iterator<DataType> iter = dtm.getAllDataTypes();
                while (iter.hasNext()) {
                    DataType dt = iter.next();
                    if (!(dt instanceof Composite)) {
                        continue;
                    }
                    
                    // Apply filters
                    if (!includeBuiltIn && dt.getSourceArchive().getName().equals("BuiltInTypes")) {
                        continue;
                    }
                    
                    if (categoryFilter != null && 
                        !dt.getCategoryPath().getPath().startsWith(categoryFilter)) {
                        continue;
                    }
                    
                    if (nameFilter != null && 
                        !dt.getName().toLowerCase().contains(nameFilter.toLowerCase())) {
                        continue;
                    }
                    
                    structures.add(createStructureInfo(dt));
                }
                
                Map<String, Object> result = new HashMap<>();
                result.put("count", structures.size());
                result.put("structures", structures);
                
                return createJsonResult(result);
                
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to apply structure at address
     */
    private void registerApplyStructureTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("structureName", SchemaUtil.createStringProperty("Name of the structure"));
        properties.put("addressOrSymbol", SchemaUtil.createStringProperty("Address or symbol name to apply structure"));
        properties.put("clearExisting", SchemaUtil.createOptionalBooleanProperty("Clear existing data"));
        
        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("structureName");
        required.add("addressOrSymbol");

        McpSchema.Tool tool = new McpSchema.Tool(
            "apply-structure",
            "Apply a structure at a specific address",
            createSchema(properties, required)
        );

        registerTool(tool, (exchange, args) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(args);
                String structureName = getString(args, "structureName");
                Address address = getAddressFromArgs(args, program, "addressOrSymbol");
                boolean clearExisting = getOptionalBoolean(args, "clearExisting", true);

                DataTypeManager dtm = program.getDataTypeManager();
                DataType dt = findDataTypeByName(dtm, structureName);
                
                if (dt == null) {
                    return createErrorResult("Structure not found: " + structureName);
                }
                
                if (!(dt instanceof Composite)) {
                    return createErrorResult("Data type is not a structure or union: " + structureName);
                }
                
                // Check if address is in valid memory
                Memory memory = program.getMemory();
                if (!memory.contains(address)) {
                    return createErrorResult("Address is not in valid memory: " + AddressUtil.formatAddress(address));
                }
                
                int txId = program.startTransaction("Apply Structure");
                try {
                    Listing listing = program.getListing();
                    
                    if (clearExisting) {
                        // Clear existing data
                        Data existingData = listing.getDataAt(address);
                        if (existingData != null) {
                            listing.clearCodeUnits(address, address.add(existingData.getLength() - 1), false);
                        }
                    }
                    
                    // Create data
                    Data data = listing.createData(address, dt);
                    
                    program.endTransaction(txId, true);
                    
                    Map<String, Object> result = new HashMap<>();
                    result.put("message", "Successfully applied structure at " + AddressUtil.formatAddress(address));
                    result.put("address", AddressUtil.formatAddress(address));
                    result.put("structureName", dt.getName());
                    result.put("size", data.getLength());
                    
                    return createJsonResult(result);
                    
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    Msg.error(this, "Failed to apply structure", e);
                    return createErrorResult("Failed to apply structure: " + e.getMessage());
                }
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to delete a structure
     */
    private void registerDeleteStructureTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("structureName", SchemaUtil.createStringProperty("Name of the structure to delete"));
        
        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("structureName");

        McpSchema.Tool tool = new McpSchema.Tool(
            "delete-structure",
            "Delete a structure from the program",
            createSchema(properties, required)
        );

        registerTool(tool, (exchange, args) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(args);
                String structureName = getString(args, "structureName");

                DataTypeManager dtm = program.getDataTypeManager();
                DataType dt = findDataTypeByName(dtm, structureName);
                
                if (dt == null) {
                    return createErrorResult("Structure not found: " + structureName);
                }
                
                int txId = program.startTransaction("Delete Structure");
                try {
                    boolean removed = dtm.remove(dt, null);
                    
                    program.endTransaction(txId, true);
                    
                    if (removed) {
                        Map<String, Object> result = new HashMap<>();
                        result.put("message", "Successfully deleted structure: " + structureName);
                        result.put("deleted", true);
                        return createJsonResult(result);
                    } else {
                        return createErrorResult("Failed to delete structure (may be in use)");
                    }
                    
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    Msg.error(this, "Failed to delete structure", e);
                    return createErrorResult("Failed to delete structure: " + e.getMessage());
                }
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to parse C header files
     */
    private void registerParseCHeaderTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("headerContent", SchemaUtil.createStringProperty("C header file content"));
        properties.put("category", SchemaUtil.createOptionalStringProperty("Category path (default: /)"));
        
        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("headerContent");

        McpSchema.Tool tool = new McpSchema.Tool(
            "parse-c-header",
            "Parse an entire C header file and create all structures",
            createSchema(properties, required)
        );

        registerTool(tool, (exchange, args) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(args);
                String headerContent = getString(args, "headerContent");
                String category = getOptionalString(args, "category", "/");

                DataTypeManager dtm = program.getDataTypeManager();
                CParser parser = new CParser(dtm);
                
                int txId = program.startTransaction("Parse C Header");
                List<Map<String, Object>> createdTypes = new ArrayList<>();
                
                try {
                    // Parse the entire header content as one unit to handle dependencies
                    CategoryPath catPath = new CategoryPath(category);
                    Category cat = dtm.createCategory(catPath);
                    
                    // Use CParser to parse the entire header content
                    DataType dt = parser.parse(headerContent);
                    if (dt != null) {
                        DataType resolved = dtm.resolve(dt, DataTypeConflictHandler.REPLACE_HANDLER);
                        if (cat != null && resolved.getCategoryPath() != catPath) {
                            resolved.setName(resolved.getName());
                            cat.moveDataType(resolved, DataTypeConflictHandler.REPLACE_HANDLER);
                        }
                        createdTypes.add(createStructureInfo(resolved));
                    }
                    
                    // If single parse didn't work, try parsing line by line
                    if (createdTypes.isEmpty()) {
                        String[] lines = headerContent.split("\n");
                        StringBuilder currentDef = new StringBuilder();
                        
                        for (String line : lines) {
                            line = line.trim();
                            if (line.isEmpty()) continue;
                            
                            currentDef.append(line).append("\n");
                            
                            // If line ends with semicolon, try to parse this definition
                            if (line.endsWith(";")) {
                                try {
                                    DataType lineDt = parser.parse(currentDef.toString());
                                    if (lineDt != null) {
                                        DataType resolved = dtm.resolve(lineDt, DataTypeConflictHandler.REPLACE_HANDLER);
                                        if (cat != null && resolved.getCategoryPath() != catPath) {
                                            resolved.setName(resolved.getName());
                                            cat.moveDataType(resolved, DataTypeConflictHandler.REPLACE_HANDLER);
                                        }
                                        createdTypes.add(createStructureInfo(resolved));
                                    }
                                } catch (Exception e) {
                                    // Log but continue with other definitions
                                    Msg.warn(this, "Failed to parse definition: " + currentDef.toString().substring(0, Math.min(50, currentDef.length())) + "...");
                                }
                                currentDef = new StringBuilder(); // Reset for next definition
                            }
                        }
                    }
                    
                    program.endTransaction(txId, true);
                    
                    Map<String, Object> result = new HashMap<>();
                    result.put("message", "Successfully parsed header file");
                    result.put("createdCount", createdTypes.size());
                    result.put("createdTypes", createdTypes);
                    return createJsonResult(result);
                    
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    Msg.error(this, "Failed to parse header", e);
                    return createErrorResult("Failed to parse header: " + e.getMessage());
                }
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Helper method to find a data type by name in all categories
     */
    private DataType findDataTypeByName(DataTypeManager dtm, String name) {
        // First try direct lookup
        DataType dt = dtm.getDataType(name);
        if (dt != null) {
            return dt;
        }
        
        // Search all categories
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dataType = iter.next();
            if (dataType.getName().equals(name)) {
                return dataType;
            }
        }
        
        return null;
    }

    /**
     * Create basic structure info map
     */
    private Map<String, Object> createStructureInfo(DataType dt) {
        Map<String, Object> info = DataTypeParserUtil.createDataTypeInfo(dt);
        
        if (dt instanceof Composite) {
            Composite composite = (Composite) dt;
            info.put("isUnion", dt instanceof Union);
            info.put("numComponents", composite.getNumComponents());
            
            if (dt instanceof Structure) {
                Structure struct = (Structure) dt;
                info.put("isPacked", struct.isPackingEnabled());
                // hasFlexibleArray check would go here if method exists
            }
        }
        
        return info;
    }

    /**
     * Create detailed structure info including all fields
     */
    private Map<String, Object> createDetailedStructureInfo(Composite composite) {
        Map<String, Object> info = createStructureInfo(composite);
        
        // Add field information
        List<Map<String, Object>> fields = new ArrayList<>();
        for (int i = 0; i < composite.getNumComponents(); i++) {
            DataTypeComponent comp = composite.getComponent(i);
            Map<String, Object> fieldInfo = new HashMap<>();
            
            fieldInfo.put("ordinal", comp.getOrdinal());
            fieldInfo.put("offset", comp.getOffset());
            fieldInfo.put("length", comp.getLength());
            fieldInfo.put("fieldName", comp.getFieldName());
            fieldInfo.put("comment", comp.getComment());
            
            DataType fieldType = comp.getDataType();
            fieldInfo.put("dataType", fieldType.getDisplayName());
            fieldInfo.put("dataTypeSize", fieldType.getLength());
            
            // Check if it's a bitfield
            if (comp.isBitFieldComponent()) {
                BitFieldDataType bitfield = (BitFieldDataType) fieldType;
                fieldInfo.put("isBitfield", true);
                fieldInfo.put("bitSize", bitfield.getBitSize());
                fieldInfo.put("bitOffset", bitfield.getBitOffset());
                fieldInfo.put("baseDataType", bitfield.getBaseDataType().getDisplayName());
            } else {
                fieldInfo.put("isBitfield", false);
            }
            
            fields.add(fieldInfo);
        }
        
        info.put("fields", fields);
        
        // Add C representation
        if (composite instanceof Structure) {
            info.put("cRepresentation", generateCRepresentation((Structure) composite));
        }
        
        return info;
    }

    /**
     * Generate C representation of a structure
     */
    private String generateCRepresentation(Structure struct) {
        StringBuilder sb = new StringBuilder();
        sb.append("struct ").append(struct.getName()).append(" {\n");
        
        for (int i = 0; i < struct.getNumComponents(); i++) {
            DataTypeComponent comp = struct.getComponent(i);
            sb.append("    ");
            
            DataType fieldType = comp.getDataType();
            if (comp.isBitFieldComponent()) {
                BitFieldDataType bitfield = (BitFieldDataType) fieldType;
                sb.append(bitfield.getBaseDataType().getDisplayName());
                sb.append(" ").append(comp.getFieldName());
                sb.append(" : ").append(bitfield.getBitSize());
            } else {
                sb.append(fieldType.getDisplayName());
                sb.append(" ").append(comp.getFieldName());
            }
            
            sb.append(";");
            
            if (comp.getComment() != null) {
                sb.append(" // ").append(comp.getComment());
            }
            
            sb.append("\n");
        }
        
        sb.append("};");
        return sb.toString();
    }

}