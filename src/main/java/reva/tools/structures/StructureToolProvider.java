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

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.DataTypeParserUtil;
import reva.util.SchemaUtil;
import reva.util.StructureUsageAnalyzer;

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
    public void registerTools() {
        registerParseCStructureTool();
        registerValidateCStructureTool();
        registerCreateStructureTool();
        registerAddStructureFieldTool();
        registerModifyStructureFieldTool();
        registerModifyStructureFromCTool();
        registerGetStructureInfoTool();
        registerListStructuresTool();
        registerApplyStructureTool();
        registerDeleteStructureTool();
        registerParseCHeaderTool();
        registerFindStructureUsagesTool();
        registerInferStructureFromUsageTool();
    }

    /**
     * Register tool to parse C-style structure definitions
     */
    private void registerParseCStructureTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("cDefinition", SchemaUtil.createStringProperty("C-style structure definition"));
        properties.put("category", SchemaUtil.createOptionalStringProperty("Category path (default: /)"));
        
        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("cDefinition");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("parse-c-structure")
            .title("Parse C Structure")
            .description("Parse and create structures from C-style definitions")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String cDefinition = getString(request, "cDefinition");
                String category = getOptionalString(request, "category", "/");

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
    private void registerValidateCStructureTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("cDefinition", SchemaUtil.createStringProperty("C-style structure definition to validate"));
        
        List<String> required = new ArrayList<>();
        required.add("cDefinition");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("validate-c-structure")
            .title("Validate C Structure")
            .description("Validate C-style structure definition without creating it")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                String cDefinition = getString(request, "cDefinition");
                
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
    private void registerCreateStructureTool() {
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

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("create-structure")
            .title("Create Structure")
            .description("Create a new empty structure or union")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String name = getString(request, "name");
                int size = getOptionalInt(request, "size", 0);
                String type = getOptionalString(request, "type", "structure");
                String category = getOptionalString(request, "category", "/");
                boolean packed = getOptionalBoolean(request, "packed", false);
                String description = getOptionalString(request, "description", null);

                DataTypeManager dtm = program.getDataTypeManager();
                CategoryPath catPath = new CategoryPath(category);
                
                int txId = program.startTransaction("Create Structure");
                try {
                    // Create category if needed
                    dtm.createCategory(catPath);
                    
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
    private void registerAddStructureFieldTool() {
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

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("add-structure-field")
            .title("Add Structure Field")
            .description("Add a field to an existing structure")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String structureName = getString(request, "structureName");
                String fieldName = getString(request, "fieldName");
                String dataTypeStr = getString(request, "dataType");
                Integer offset = getOptionalInteger(request.arguments(), "offset", null);
                String comment = getOptionalString(request, "comment", null);
                Map<String, Object> bitfield = getOptionalMap(request.arguments(), "bitfield", null);

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
     * Register tool to modify existing structure fields
     */
    private void registerModifyStructureFieldTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("structureName", SchemaUtil.createStringProperty("Name of the structure"));
        properties.put("fieldName", SchemaUtil.createOptionalStringProperty("Name of the field to modify (use this OR offset)"));
        properties.put("offset", SchemaUtil.createOptionalNumberProperty("Offset of the field to modify (use this OR fieldName)"));
        properties.put("newDataType", SchemaUtil.createOptionalStringProperty("New data type for the field"));
        properties.put("newFieldName", SchemaUtil.createOptionalStringProperty("New name for the field"));
        properties.put("newComment", SchemaUtil.createOptionalStringProperty("New comment for the field"));
        properties.put("newLength", SchemaUtil.createOptionalNumberProperty("New length for the field (advanced)"));
        properties.put("allowSizeChange", SchemaUtil.createOptionalBooleanProperty(
            "Allow modifications that change field size and shift subsequent field offsets (default: false). " +
            "If false and the modification would change size, a warning is returned instead of making the change."));

        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("structureName");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("modify-structure-field")
            .title("Modify Structure Field")
            .description("Modify an existing field in a structure. Supports changing data type, name, comment, and length. " +
                         "Identify the field by name OR offset. At least one modification parameter (newDataType, newFieldName, newComment, or newLength) is required.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String structureName = getString(request, "structureName");
                String fieldName = getOptionalString(request, "fieldName", null);
                Integer offset = getOptionalInteger(request.arguments(), "offset", null);
                String newDataTypeStr = getOptionalString(request, "newDataType", null);
                String newFieldName = getOptionalString(request, "newFieldName", null);
                String newComment = getOptionalString(request, "newComment", null);
                Integer newLength = getOptionalInteger(request.arguments(), "newLength", null);
                boolean allowSizeChange = getOptionalBoolean(request, "allowSizeChange", false);

                // Validate: must have either fieldName or offset
                if (fieldName == null && offset == null) {
                    return createErrorResult("Must specify either fieldName or offset to identify the field to modify");
                }

                // Validate: must have at least one modification
                if (newDataTypeStr == null && newFieldName == null && newComment == null && newLength == null) {
                    return createErrorResult("Must specify at least one modification (newDataType, newFieldName, newComment, or newLength)");
                }

                DataTypeManager dtm = program.getDataTypeManager();

                // Find the structure
                DataType dt = findDataTypeByName(dtm, structureName);
                if (dt == null) {
                    return createErrorResult("Structure not found: " + structureName);
                }

                if (!(dt instanceof Structure)) {
                    return createErrorResult("Data type is not a structure: " + structureName + " (unions not supported for field modification)");
                }

                Structure struct = (Structure) dt;

                // Find the field component
                DataTypeComponent targetComponent = null;
                int targetOrdinal = -1;

                if (offset != null) {
                    // Find by offset
                    targetComponent = struct.getComponentAt(offset);
                    if (targetComponent == null) {
                        return createErrorResult("No field found at offset " + offset + " in structure " + structureName);
                    }
                    targetOrdinal = targetComponent.getOrdinal();
                } else {
                    // Find by name
                    for (int i = 0; i < struct.getNumComponents(); i++) {
                        DataTypeComponent comp = struct.getComponent(i);
                        if (fieldName.equals(comp.getFieldName())) {
                            targetComponent = comp;
                            targetOrdinal = i;
                            break;
                        }
                    }
                    if (targetComponent == null) {
                        return createErrorResult("Field not found: " + fieldName + " in structure " + structureName);
                    }
                }

                // Determine what we're replacing with
                DataType replacementDataType = targetComponent.getDataType();
                String replacementFieldName = targetComponent.getFieldName();
                String replacementComment = targetComponent.getComment();
                int replacementLength = targetComponent.getLength();

                // Parse new data type if provided
                if (newDataTypeStr != null) {
                    try {
                        // First try using the program's own DTM directly
                        DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
                        replacementDataType = parser.parse(newDataTypeStr);
                    } catch (Exception e) {
                        // Fallback to the utility method
                        try {
                            replacementDataType = DataTypeParserUtil.parseDataTypeObjectFromString(newDataTypeStr, "");
                        } catch (Exception e2) {
                            return createErrorResult("Invalid data type: " + newDataTypeStr);
                        }
                    }

                    if (replacementDataType == null) {
                        return createErrorResult("Invalid data type: " + newDataTypeStr);
                    }

                    // Update length to match new data type if not explicitly provided
                    if (newLength == null) {
                        replacementLength = replacementDataType.getLength();
                    }
                }

                // Apply new field name if provided
                if (newFieldName != null) {
                    replacementFieldName = newFieldName;
                }

                // Apply new comment if provided
                if (newComment != null) {
                    replacementComment = newComment;
                }

                // Apply new length if provided
                if (newLength != null) {
                    replacementLength = newLength;
                }

                // Check if size will change and warn if not allowed
                int oldLength = targetComponent.getLength();
                int sizeDelta = replacementLength - oldLength;
                boolean willShiftOffsets = sizeDelta != 0 && targetOrdinal < (struct.getNumComponents() - 1);

                if (willShiftOffsets && !allowSizeChange) {
                    // Count affected fields (fields after this one)
                    int affectedFieldCount = struct.getNumComponents() - targetOrdinal - 1;
                    int oldStructSize = struct.getLength();
                    int newStructSize = oldStructSize + sizeDelta;

                    // Return warning with impact details
                    Map<String, Object> warning = new HashMap<>();
                    warning.put("canModify", false);
                    warning.put("modified", false);
                    warning.put("warning", String.format(
                        "This change shifts offsets of %d field(s). Structure size changes from %d to %d bytes. " +
                        "Use allowSizeChange=true to proceed.",
                        affectedFieldCount, oldStructSize, newStructSize));

                    Map<String, Object> impact = new HashMap<>();
                    impact.put("oldFieldSize", oldLength);
                    impact.put("newFieldSize", replacementLength);
                    impact.put("sizeDelta", sizeDelta);
                    impact.put("affectedFieldCount", affectedFieldCount);
                    impact.put("oldStructureSize", oldStructSize);
                    impact.put("newStructureSize", newStructSize);
                    warning.put("impact", impact);

                    warning.put("structureName", structureName);
                    warning.put("fieldName", targetComponent.getFieldName());
                    warning.put("fieldOffset", targetComponent.getOffset());
                    warning.put("programPath", program.getDomainFile().getPathname());

                    return createJsonResult(warning);
                }

                int txId = program.startTransaction("Modify Structure Field");
                try {
                    // Use replace() to update the field
                    struct.replace(targetOrdinal, replacementDataType, replacementLength,
                                   replacementFieldName, replacementComment);

                    program.endTransaction(txId, true);

                    Map<String, Object> result = createDetailedStructureInfo(struct);
                    result.put("message", "Successfully modified field in structure: " + structureName);
                    result.put("modifiedField", replacementFieldName);
                    return createJsonResult(result);

                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    Msg.error(this, "Failed to modify field", e);
                    return createErrorResult("Failed to modify field: " + e.getMessage());
                }
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to modify a structure using a C definition
     */
    private void registerModifyStructureFromCTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("cDefinition", SchemaUtil.createStringProperty("Complete C structure definition with modifications"));

        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("cDefinition");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("modify-structure-from-c")
            .title("Modify Structure from C")
            .description("Modify an existing structure using a C-style definition. " +
                         "The structure name must match an existing structure. " +
                         "Fields will be added, modified, or removed to match the definition. " +
                         "Best practice: Read the structure with get-structure-info before modifying to understand the current layout.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String cDefinition = getString(request, "cDefinition");

                DataTypeManager dtm = program.getDataTypeManager();

                // Parse the C definition
                DataType parsedDt = null;
                try {
                    CParser parser = new CParser(dtm);
                    parsedDt = parser.parse(cDefinition);
                } catch (Exception e) {
                    return createErrorResult("Failed to parse C definition: " + e.getMessage());
                }

                if (parsedDt == null) {
                    return createErrorResult("Failed to parse structure definition");
                }

                if (!(parsedDt instanceof Structure)) {
                    return createErrorResult("Parsed definition is not a structure (unions not supported for modification)");
                }

                Structure parsedStruct = (Structure) parsedDt;
                String structureName = parsedStruct.getName();

                // Find existing structure
                DataType existingDt = findDataTypeByName(dtm, structureName);
                if (existingDt == null) {
                    return createErrorResult("Structure not found: " + structureName + ". Use parse-c-structure to create a new structure instead.");
                }

                if (!(existingDt instanceof Structure)) {
                    return createErrorResult("Existing data type is not a structure: " + structureName);
                }

                Structure existingStruct = (Structure) existingDt;

                int txId = program.startTransaction("Modify Structure from C");
                try {
                    // Clear existing structure and rebuild from parsed definition
                    // We'll do this by replacing all components

                    // First, remove all existing components
                    while (existingStruct.getNumComponents() > 0) {
                        existingStruct.delete(0);
                    }

                    // Now add all components from the parsed structure
                    for (int i = 0; i < parsedStruct.getNumComponents(); i++) {
                        DataTypeComponent comp = parsedStruct.getComponent(i);
                        DataType fieldType = comp.getDataType();

                        // Resolve the field type in the program's DTM
                        fieldType = dtm.resolve(fieldType, DataTypeConflictHandler.DEFAULT_HANDLER);

                        if (comp.isBitFieldComponent()) {
                            // Handle bitfield
                            BitFieldDataType bitfield = (BitFieldDataType) fieldType;
                            existingStruct.addBitField(
                                bitfield.getBaseDataType(),
                                bitfield.getBitSize(),
                                comp.getFieldName(),
                                comp.getComment()
                            );
                        } else {
                            // Regular field
                            existingStruct.add(fieldType, comp.getFieldName(), comp.getComment());
                        }
                    }

                    // Copy other properties
                    if (parsedStruct.getDescription() != null) {
                        existingStruct.setDescription(parsedStruct.getDescription());
                    }
                    existingStruct.setPackingEnabled(parsedStruct.isPackingEnabled());

                    program.endTransaction(txId, true);

                    Map<String, Object> result = createDetailedStructureInfo(existingStruct);
                    result.put("message", "Successfully modified structure from C definition: " + structureName);
                    result.put("fieldsCount", existingStruct.getNumComponents());
                    return createJsonResult(result);

                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    Msg.error(this, "Failed to modify structure from C", e);
                    return createErrorResult("Failed to modify structure: " + e.getMessage());
                }
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to get structure information
     */
    private void registerGetStructureInfoTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("structureName", SchemaUtil.createStringProperty("Name of the structure"));
        
        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("structureName");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-structure-info")
            .title("Get Structure Info")
            .description("Get detailed information about a structure")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String structureName = getString(request, "structureName");

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
     * Register tool to list structures with pagination
     */
    private void registerListStructuresTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("category", SchemaUtil.createOptionalStringProperty("Filter by category path"));
        properties.put("nameFilter", SchemaUtil.createOptionalStringProperty("Filter by name (substring match)"));
        properties.put("includeBuiltIn", SchemaUtil.createOptionalBooleanProperty("Include built-in types"));
        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (0-based)",
            "default", 0
        ));
        properties.put("maxCount", Map.of(
            "type", "integer",
            "description", "Maximum number of structures to return (default 100)",
            "default", 100
        ));

        List<String> required = new ArrayList<>();
        required.add("programPath");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-structures")
            .title("List Structures")
            .description("List structures/unions in a program with pagination. Use startIndex and maxCount for large programs.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String categoryFilter = getOptionalString(request, "category", null);
                String nameFilter = getOptionalString(request, "nameFilter", null);
                boolean includeBuiltIn = getOptionalBoolean(request, "includeBuiltIn", false);
                int startIndex = getOptionalInt(request, "startIndex", 0);
                int maxCount = getOptionalInt(request, "maxCount", 100);

                DataTypeManager dtm = program.getDataTypeManager();
                List<Map<String, Object>> structures = new ArrayList<>();

                // Count matching structures and collect paginated results
                int totalMatching = 0;
                int currentIndex = 0;

                Iterator<DataType> iter = dtm.getAllDataTypes();
                while (iter.hasNext()) {
                    DataType dt = iter.next();
                    if (!(dt instanceof Composite)) {
                        continue;
                    }

                    // Apply filters
                    if (!includeBuiltIn && dt.getSourceArchive() != null &&
                        dt.getSourceArchive().getName().equals("BuiltInTypes")) {
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

                    // This structure matches the filters
                    totalMatching++;

                    // Only collect if within pagination window
                    if (currentIndex >= startIndex && structures.size() < maxCount) {
                        structures.add(createStructureInfo(dt));
                    }
                    currentIndex++;
                }

                Map<String, Object> result = new HashMap<>();
                result.put("structures", structures);
                result.put("pagination", Map.of(
                    "startIndex", startIndex,
                    "requestedCount", maxCount,
                    "actualCount", structures.size(),
                    "nextStartIndex", startIndex + structures.size(),
                    "totalCount", totalMatching
                ));

                return createJsonResult(result);

            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to apply structure at address
     */
    private void registerApplyStructureTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("structureName", SchemaUtil.createStringProperty("Name of the structure"));
        properties.put("addressOrSymbol", SchemaUtil.createStringProperty("Address or symbol name to apply structure"));
        properties.put("clearExisting", SchemaUtil.createOptionalBooleanProperty("Clear existing data"));
        
        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("structureName");
        required.add("addressOrSymbol");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("apply-structure")
            .title("Apply Structure")
            .description("Apply a structure at a specific address")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String structureName = getString(request, "structureName");
                Address address = getAddressFromArgs(request, program, "addressOrSymbol");
                boolean clearExisting = getOptionalBoolean(request, "clearExisting", true);

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
     * Register tool to delete a structure with reference checking
     */
    private void registerDeleteStructureTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("structureName", SchemaUtil.createStringProperty("Name of the structure to delete"));
        properties.put("force", SchemaUtil.createOptionalBooleanProperty("Force deletion even if structure is referenced (default: false)"));

        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("structureName");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("delete-structure")
            .title("Delete Structure")
            .description("Delete a structure from the program. " +
                         "Checks for references (function signatures, variables, memory) before deletion. " +
                         "Use force=true to delete anyway despite references.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String structureName = getString(request, "structureName");
                boolean force = getOptionalBoolean(request, "force", false);

                DataTypeManager dtm = program.getDataTypeManager();
                DataType dt = findDataTypeByName(dtm, structureName);

                if (dt == null) {
                    return createErrorResult("Structure not found: " + structureName);
                }

                // Check for references to this structure
                List<String> functionReferences = new ArrayList<>();
                List<String> memoryReferences = new ArrayList<>();

                // Check function parameters and return types
                ghidra.program.model.listing.FunctionIterator functions = program.getFunctionManager().getFunctions(true);
                while (functions.hasNext()) {
                    ghidra.program.model.listing.Function func = functions.next();

                    // Check return type
                    if (func.getReturnType().isEquivalent(dt)) {
                        functionReferences.add(func.getName() + " (return type)");
                    }

                    // Check parameters
                    for (ghidra.program.model.listing.Parameter param : func.getParameters()) {
                        if (param.getDataType().isEquivalent(dt)) {
                            functionReferences.add(func.getName() + " (parameter: " + param.getName() + ")");
                        }
                    }

                    // Check local variables
                    for (ghidra.program.model.listing.Variable var : func.getAllVariables()) {
                        if (var.getDataType().isEquivalent(dt)) {
                            functionReferences.add(func.getName() + " (variable: " + var.getName() + ")");
                        }
                    }
                }

                // Check memory for applied instances
                Listing listing = program.getListing();
                ghidra.program.model.listing.DataIterator dataIter = listing.getDefinedData(true);
                while (dataIter.hasNext()) {
                    Data data = dataIter.next();
                    if (data.getDataType().isEquivalent(dt)) {
                        memoryReferences.add(AddressUtil.formatAddress(data.getAddress()));
                    }
                }

                int totalReferences = functionReferences.size() + memoryReferences.size();

                // If references exist and not forcing, return warning
                if (totalReferences > 0 && !force) {
                    Map<String, Object> result = new HashMap<>();
                    result.put("canDelete", false);
                    result.put("deleted", false);

                    Map<String, Object> references = new HashMap<>();
                    references.put("count", totalReferences);
                    references.put("functions", functionReferences);
                    references.put("memoryLocations", memoryReferences);
                    result.put("references", references);

                    result.put("warning", "Structure '" + structureName + "' is referenced in " +
                               functionReferences.size() + " function(s) and " +
                               memoryReferences.size() + " memory location(s). " +
                               "Use force=true to delete anyway.");

                    return createJsonResult(result);
                }

                // Proceed with deletion
                int txId = program.startTransaction("Delete Structure");
                try {
                    boolean removed = dtm.remove(dt);

                    program.endTransaction(txId, true);

                    if (removed) {
                        Map<String, Object> result = new HashMap<>();
                        result.put("message", "Successfully deleted structure: " + structureName);
                        result.put("deleted", true);
                        result.put("hadReferences", totalReferences > 0);
                        result.put("referencesCleared", totalReferences);
                        return createJsonResult(result);
                    } else {
                        return createErrorResult("Failed to delete structure (may be locked or in use by another process)");
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
    private void registerParseCHeaderTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("headerContent", SchemaUtil.createStringProperty("C header file content"));
        properties.put("category", SchemaUtil.createOptionalStringProperty("Category path (default: /)"));
        
        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("headerContent");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("parse-c-header")
            .title("Parse C Header")
            .description("Parse an entire C header file and create all structures")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String headerContent = getString(request, "headerContent");
                String category = getOptionalString(request, "category", "/");

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

        // Add field information with undefined byte condensing
        List<Map<String, Object>> fields = new ArrayList<>();

        int i = 0;
        while (i < composite.getNumComponents()) {
            DataTypeComponent comp = composite.getComponent(i);

            // Check if this is an undefined byte that should be condensed
            if (isUndefinedField(comp)) {
                // Count consecutive undefined bytes
                int startOffset = comp.getOffset();
                int startOrdinal = comp.getOrdinal();
                int totalLength = 0;
                int count = 0;

                while (i < composite.getNumComponents()) {
                    DataTypeComponent nextComp = composite.getComponent(i);
                    if (!isUndefinedField(nextComp)) {
                        break;
                    }
                    totalLength += nextComp.getLength();
                    count++;
                    i++;
                }

                // Create a condensed entry for the undefined range
                Map<String, Object> fieldInfo = new HashMap<>();
                fieldInfo.put("ordinal", startOrdinal);
                fieldInfo.put("offset", startOffset);
                fieldInfo.put("length", totalLength);
                fieldInfo.put("fieldName", "<undefined>");
                fieldInfo.put("dataType", "undefined");
                fieldInfo.put("dataTypeSize", totalLength);
                fieldInfo.put("isBitfield", false);
                fieldInfo.put("isCondensed", true);
                fieldInfo.put("componentCount", count);

                fields.add(fieldInfo);
            } else {
                // Regular field - add as-is
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

                fieldInfo.put("isCondensed", false);

                fields.add(fieldInfo);
                i++;
            }
        }

        info.put("fields", fields);

        // Add C representation
        if (composite instanceof Structure) {
            info.put("cRepresentation", generateCRepresentation((Structure) composite));
        }

        return info;
    }

    /**
     * Check if a field is an undefined/default field that should be condensed
     */
    private boolean isUndefinedField(DataTypeComponent comp) {
        // Check if the field name is null or empty (undefined)
        String fieldName = comp.getFieldName();
        if (fieldName == null || fieldName.isEmpty()) {
            return true;
        }

        // Check if it's a Ghidra default field name like "field_0x0", "field_0x1", etc.
        // These are generated for undefined structure areas
        if (fieldName.startsWith("field_0x") || fieldName.startsWith("field0x")) {
            return true;
        }

        // Check if the datatype is "undefined" or "undefined1"
        DataType fieldType = comp.getDataType();
        String typeName = fieldType.getName();
        if (typeName != null && typeName.startsWith("undefined")) {
            return true;
        }

        return false;
    }

    /**
     * Generate C representation of a structure with undefined byte condensing
     */
    private String generateCRepresentation(Structure struct) {
        StringBuilder sb = new StringBuilder();
        sb.append("struct ").append(struct.getName()).append(" {\n");

        int i = 0;
        while (i < struct.getNumComponents()) {
            DataTypeComponent comp = struct.getComponent(i);
            sb.append("    ");

            // Check if this is an undefined field that should be condensed
            if (isUndefinedField(comp)) {
                // Count consecutive undefined bytes
                int startOffset = comp.getOffset();
                int totalLength = 0;
                int count = 0;

                while (i < struct.getNumComponents()) {
                    DataTypeComponent nextComp = struct.getComponent(i);
                    if (!isUndefinedField(nextComp)) {
                        break;
                    }
                    totalLength += nextComp.getLength();
                    count++;
                    i++;
                }

                // Generate condensed line with offset range comment
                sb.append("undefined reserved_0x");
                sb.append(String.format("%x", startOffset));
                sb.append("[").append(count).append("]");
                sb.append(";");
                sb.append(" // 0x");
                sb.append(String.format("%x", startOffset));
                sb.append("-0x");
                sb.append(String.format("%x", startOffset + totalLength - 1));
                sb.append("\n");
            } else {
                // Regular field - output as-is
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
                i++;
            }
        }

        sb.append("};");
        return sb.toString();
    }

    /**
     * Register tool to find all usages of a structure in the program.
     * Checks function return types, parameters, local variables, and memory instances.
     */
    private void registerFindStructureUsagesTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("structureName", SchemaUtil.createStringProperty("Name of the structure to find usages of"));

        List<String> required = List.of("programPath", "structureName");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("find-structure-usages")
            .title("Find Structure Usages")
            .description("Find all places where a structure is used in the program. Returns functions using the structure as return type, parameter, or local variable, plus memory locations where the structure is applied.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            String structureName = getString(request, "structureName");

            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByName(dtm, structureName);

            if (dt == null) {
                return createErrorResult("Structure not found: " + structureName +
                    ". Use list-structures to see available structures.");
            }

            // Collect detailed usage information
            List<Map<String, Object>> functionUsages = new ArrayList<>();
            List<Map<String, Object>> memoryUsages = new ArrayList<>();

            // Check function parameters, return types, and local variables
            ghidra.program.model.listing.FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                ghidra.program.model.listing.Function func = functions.next();
                String funcName = func.getName();
                String funcAddress = AddressUtil.formatAddress(func.getEntryPoint());

                // Check return type
                if (func.getReturnType().isEquivalent(dt)) {
                    Map<String, Object> usage = new HashMap<>();
                    usage.put("functionName", funcName);
                    usage.put("functionAddress", funcAddress);
                    usage.put("usageType", "return_type");
                    usage.put("dataType", func.getReturnType().getDisplayName());
                    functionUsages.add(usage);
                }

                // Check parameters
                for (ghidra.program.model.listing.Parameter param : func.getParameters()) {
                    if (param.getDataType().isEquivalent(dt)) {
                        Map<String, Object> usage = new HashMap<>();
                        usage.put("functionName", funcName);
                        usage.put("functionAddress", funcAddress);
                        usage.put("usageType", "parameter");
                        usage.put("parameterName", param.getName());
                        usage.put("parameterIndex", param.getOrdinal());
                        usage.put("dataType", param.getDataType().getDisplayName());
                        functionUsages.add(usage);
                    }
                }

                // Check local variables
                for (ghidra.program.model.listing.Variable var : func.getAllVariables()) {
                    // Skip parameters (already checked above)
                    if (var instanceof ghidra.program.model.listing.Parameter) {
                        continue;
                    }
                    if (var.getDataType().isEquivalent(dt)) {
                        Map<String, Object> usage = new HashMap<>();
                        usage.put("functionName", funcName);
                        usage.put("functionAddress", funcAddress);
                        usage.put("usageType", "local_variable");
                        usage.put("variableName", var.getName());
                        usage.put("dataType", var.getDataType().getDisplayName());
                        functionUsages.add(usage);
                    }
                }
            }

            // Check memory for applied instances
            Listing listing = program.getListing();
            ghidra.program.model.listing.DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext()) {
                Data data = dataIter.next();
                if (data.getDataType().isEquivalent(dt)) {
                    Map<String, Object> usage = new HashMap<>();
                    usage.put("address", AddressUtil.formatAddress(data.getAddress()));
                    usage.put("dataType", data.getDataType().getDisplayName());

                    // Try to get symbol name if available
                    ghidra.program.model.symbol.Symbol symbol = program.getSymbolTable().getPrimarySymbol(data.getAddress());
                    if (symbol != null) {
                        usage.put("symbolName", symbol.getName());
                    }

                    usage.put("size", data.getLength());
                    memoryUsages.add(usage);
                }
            }

            // Build result with categorized usages
            Map<String, Object> result = new HashMap<>();
            result.put("structureName", structureName);
            result.put("structureSize", dt.getLength());
            result.put("totalUsages", functionUsages.size() + memoryUsages.size());

            // Summary breakdown
            Map<String, Object> summary = new HashMap<>();
            long returnTypeCount = functionUsages.stream()
                .filter(u -> "return_type".equals(u.get("usageType"))).count();
            long parameterCount = functionUsages.stream()
                .filter(u -> "parameter".equals(u.get("usageType"))).count();
            long variableCount = functionUsages.stream()
                .filter(u -> "local_variable".equals(u.get("usageType"))).count();

            summary.put("returnTypes", returnTypeCount);
            summary.put("parameters", parameterCount);
            summary.put("localVariables", variableCount);
            summary.put("memoryInstances", memoryUsages.size());
            result.put("summary", summary);

            result.put("functionUsages", functionUsages);
            result.put("memoryUsages", memoryUsages);
            result.put("programPath", program.getDomainFile().getPathname());

            return createJsonResult(result);
        });
    }

    /**
     * Register a tool to infer structure layout from variable usage patterns.
     * Analyzes how a function parameter or variable is accessed to infer field offsets.
     */
    private void registerInferStructureFromUsageTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path to the program"));
        properties.put("functionAddress", SchemaUtil.createStringProperty(
            "Address or name of the function to analyze"));
        properties.put("parameterIndex", Map.of(
            "type", "integer",
            "description", "0-based parameter index to analyze (default: 0 for first parameter)",
            "default", 0
        ));
        properties.put("variableName", SchemaUtil.createOptionalStringProperty(
            "Name of local variable to analyze instead of a parameter"));
        properties.put("structName", SchemaUtil.createOptionalStringProperty(
            "Name for the inferred structure (default: Inferred_<function>_param<N>)"));

        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("functionAddress");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("infer-structure-from-usage")
            .title("Infer Structure from Usage")
            .description("Analyze how a function parameter or variable is used to infer its structure layout. " +
                "Examines pcode operations to find field offset accesses and infers types from access sizes. " +
                "Returns a C structure definition that can be used with parse-c-structure to create the type.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);
                String programPath = program.getDomainFile().getPathname();
                String functionLocation = getString(request, "functionAddress");
                int parameterIndex = getOptionalInt(request, "parameterIndex", 0);
                String variableName = getOptionalString(request, "variableName", null);
                String structName = getOptionalString(request, "structName", null);

                // Resolve function
                Address funcAddr = getAddressFromArgs(request, program, "functionAddress");
                if (funcAddr == null) {
                    return createErrorResult("Invalid function address or name: " + functionLocation);
                }

                Function function = program.getFunctionManager().getFunctionAt(funcAddr);
                if (function == null) {
                    function = program.getFunctionManager().getFunctionContaining(funcAddr);
                }
                if (function == null) {
                    return createErrorResult("No function found at " + AddressUtil.formatAddress(funcAddr));
                }

                // Generate default struct name if not provided
                if (structName == null || structName.isEmpty()) {
                    if (variableName != null) {
                        structName = "Inferred_" + function.getName() + "_" + variableName;
                    } else {
                        structName = "Inferred_" + function.getName() + "_param" + parameterIndex;
                    }
                }

                // Decompile the function
                DecompInterface decompiler = new DecompInterface();
                try {
                    decompiler.toggleCCode(true);
                    decompiler.toggleSyntaxTree(true);
                    decompiler.setSimplificationStyle("decompile");

                    if (!decompiler.openProgram(program)) {
                        return createErrorResult("Failed to initialize decompiler");
                    }

                    DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
                    if (!results.decompileCompleted()) {
                        return createErrorResult("Decompilation failed: " + results.getErrorMessage());
                    }

                    HighFunction hf = results.getHighFunction();
                    if (hf == null) {
                        return createErrorResult("Failed to get high-level function representation");
                    }

                    // Find the target variable
                    HighVariable targetVar = null;
                    String targetDescription = null;

                    if (variableName != null && !variableName.isEmpty()) {
                        // Find by variable name
                        targetVar = StructureUsageAnalyzer.findVariableByName(hf, variableName);
                        targetDescription = "variable '" + variableName + "'";
                    } else {
                        // Find by parameter index
                        targetVar = StructureUsageAnalyzer.findParameterByIndex(hf, parameterIndex);
                        targetDescription = "parameter " + parameterIndex;
                    }

                    if (targetVar == null) {
                        return createErrorResult("Could not find " + targetDescription + " in function " +
                            function.getName());
                    }

                    // Analyze memory accesses
                    List<StructureUsageAnalyzer.MemoryAccess> accesses =
                        StructureUsageAnalyzer.analyzeMemoryAccesses(hf, targetVar);

                    // Build response
                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("functionName", function.getName());
                    result.put("functionAddress", AddressUtil.formatAddress(function.getEntryPoint()));
                    result.put("analyzedTarget", targetDescription);
                    result.put("structName", structName);
                    result.put("programPath", programPath);

                    // Generate structure definition
                    String structDef = StructureUsageAnalyzer.generateStructureDefinition(accesses, structName);
                    result.put("inferredStructure", structDef);

                    // Aggregate accesses for summary
                    Map<Long, Map<String, Object>> aggregated =
                        StructureUsageAnalyzer.aggregateAccessesByOffset(accesses);
                    result.put("accessCount", accesses.size());
                    result.put("uniqueOffsets", aggregated.size());

                    // Calculate inferred size
                    long maxOffset = 0;
                    int maxSize = 0;
                    for (StructureUsageAnalyzer.MemoryAccess access : accesses) {
                        if (access.offset + access.size > maxOffset + maxSize) {
                            maxOffset = access.offset;
                            maxSize = access.size;
                        }
                    }
                    result.put("inferredSize", maxOffset + maxSize);

                    // Include detailed field info
                    List<Map<String, Object>> fields = new ArrayList<>();
                    for (Map.Entry<Long, Map<String, Object>> entry : aggregated.entrySet()) {
                        fields.add(entry.getValue());
                    }
                    // Sort by offset
                    fields.sort((a, b) -> {
                        long offA = (Long) a.get("offsetDecimal");
                        long offB = (Long) b.get("offsetDecimal");
                        return Long.compare(offA, offB);
                    });
                    result.put("fields", fields);

                    // Add usage hint
                    result.put("hint", "Use parse-c-structure with the inferredStructure value to create this type");

                    return createJsonResult(result);

                } finally {
                    decompiler.dispose();
                }

            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                return createErrorResult("Unexpected error: " + e.getMessage());
            }
        });
    }

}