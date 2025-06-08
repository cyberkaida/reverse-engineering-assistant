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
package reva.tools.data;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Content;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.tools.AbstractToolProvider;
import reva.tools.ProgramValidationException;
import reva.util.AddressUtil;
import reva.util.DataTypeParserUtil;

/**
 * Tool provider for accessing data at specific addresses or by symbol names in programs.
 */
public class DataToolProvider extends AbstractToolProvider {
    /**
     * Constructor
     * @param server The MCP server
     */
    public DataToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() throws McpError {
        registerGetDataTool();
        registerApplyDataTypeTool();
        registerCreateLabelTool();
    }

    /**
     * Register a unified tool to get data by address or symbol name
     * @throws McpError if there's an error registering the tool
     */
    private void registerGetDataTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the data"
        ));
        properties.put("addressOrSymbol", Map.of(
            "type", "string",
            "description", "Address or symbol name to get data from (e.g., '0x00400000' or 'main')"
        ));

        List<String> required = List.of("programPath", "addressOrSymbol");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-data",
            "Get data at a specific address or symbol in a program",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get program and address using helper methods
            Program program = getProgramFromArgs(args);
            Address address = getAddressFromArgs(args, program, "addressOrSymbol");

            return getDataAtAddressResult(program, address);
        });
    }

    /**
     * Register a tool to apply a data type to an address or symbol
     * @throws McpError if there's an error registering the tool
     */
    private void registerApplyDataTypeTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("addressOrSymbol", Map.of(
            "type", "string",
            "description", "Address or symbol name to apply the data type to (e.g., '0x00400000' or 'main')"
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

        List<String> required = List.of("programPath", "addressOrSymbol", "dataTypeString");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "apply-data-type",
            "Apply a data type to a specific address or symbol in a program",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(args);
            Address targetAddress = getAddressFromArgs(args, program, "addressOrSymbol");
            String dataTypeString = getString(args, "dataTypeString");
            String archiveName = getOptionalString(args, "archiveName", "");

            if (dataTypeString.trim().isEmpty()) {
                return createErrorResult("Data type string cannot be empty");
            }

            try {
                // Try to parse the data type from the string and get the actual DataType object
                DataType dataType;
                try {
                    dataType = DataTypeParserUtil.parseDataTypeObjectFromString(dataTypeString, archiveName);
                    if (dataType == null) {
                        return createErrorResult("Could not find data type: " + dataTypeString +
                            ". Try using the get-data-type-archives and get-data-types tools to find available data types.");
                    }
                } catch (Exception e) {
                    return createErrorResult("Error parsing data type: " + e.getMessage() +
                        ". Try using the get-data-type-archives and get-data-types tools to find available data types.");
                }

                // Start a transaction to apply the data type
                int transactionID = program.startTransaction("Apply Data Type");
                boolean success = false;

                try {

                    // Get the listing and apply the data type at the symbol's address
                    Listing listing = program.getListing();

                    // Clear any existing data at the address
                    if (listing.getDataAt(targetAddress) != null) {
                        listing.clearCodeUnits(targetAddress, targetAddress.add(dataType.getLength() - 1), false);
                    }

                    // Create the data at the address with the specified data type
                    Data createdData = listing.createData(targetAddress, dataType);

                    if (createdData == null) {
                        throw new Exception("Failed to create data at address: " + targetAddress);
                    }

                    success = true;

                    // Create result data
                    Map<String, Object> resultData = new HashMap<>();
                    resultData.put("success", true);
                    resultData.put("address", "0x" + targetAddress.toString());
                    resultData.put("dataType", dataType.getName());
                    resultData.put("dataTypeDisplayName", dataType.getDisplayName());
                    resultData.put("length", dataType.getLength());

                    return createJsonResult(resultData);
                } finally {
                    // End transaction
                    program.endTransaction(transactionID, success);
                }
            } catch (Exception e) {
                return createErrorResult("Error applying data type to symbol: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to create a label at a specific address in a program
     * @throws McpError if there's an error registering the tool
     */
    private void registerCreateLabelTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the address"
        ));
        properties.put("addressOrSymbol", Map.of(
            "type", "string",
            "description", "Address or symbol name to create label at (e.g., '0x00400000' or 'main')"
        ));
        properties.put("labelName", Map.of(
            "type", "string",
            "description", "Name for the label to create"
        ));
        properties.put("setAsPrimary", Map.of(
            "type", "boolean",
            "description", "Whether to set this label as primary if other labels exist at the address",
            "default", true
        ));

        List<String> required = List.of("programPath", "addressOrSymbol", "labelName");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "create-label",
            "Create a label at a specific address in a program",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get program and parameters using helper methods
            Program program;
            String labelName;
            Address address;
            try {
                program = getProgramFromArgs(args);
                labelName = getString(args, "labelName");
                address = getAddressFromArgs(args, program, "addressOrSymbol");
            } catch (IllegalArgumentException | ProgramValidationException e) {
                return createErrorResult(e.getMessage());
            }
            boolean setAsPrimary = getOptionalBoolean(args, "setAsPrimary", true);

            if (labelName.trim().isEmpty()) {
                return createErrorResult("Label name cannot be empty");
            }

            // Start a transaction to create the label
            int transactionID = program.startTransaction("Create Label");
            boolean success = false;

            try {
                // Get the symbol table
                SymbolTable symbolTable = program.getSymbolTable();

                // Create the label
                Symbol symbol = symbolTable.createLabel(address, labelName,
                    program.getGlobalNamespace(), ghidra.program.model.symbol.SourceType.USER_DEFINED);

                if (symbol == null) {
                    throw new Exception("Failed to create label at address: " + address);
                }

                // Set the label as primary if requested
                if (setAsPrimary && !symbol.isPrimary()) {
                    symbol.setPrimary();
                }

                success = true;

                // Create result data
                Map<String, Object> resultData = new HashMap<>();
                resultData.put("success", true);
                resultData.put("labelName", labelName);
                resultData.put("address", "0x" + address.toString());
                resultData.put("isPrimary", symbol.isPrimary());

                return createJsonResult(resultData);
            } catch (Exception e) {
                return createErrorResult("Error creating label: " + e.getMessage());
            } finally {
                // End transaction
                program.endTransaction(transactionID, success);
            }
        });
    }

    /**
     * Helper method to get data at a specific address and format the result
     * @param program The program to look up data in
     * @param address The address where to find data
     * @return Call tool result with data information
     */
    private CallToolResult getDataAtAddressResult(Program program, Address address) {

        // Get data at or containing the address
        Data data = AddressUtil.getContainingData(program, address);
        if (data == null) {
            return createErrorResult("No data found at address: " + AddressUtil.formatAddress(address));
        }

        // Create result data
        Map<String, Object> resultData = new HashMap<>();
        resultData.put("address", AddressUtil.formatAddress(data.getAddress()));
        resultData.put("dataType", data.getDataType().getName());
        resultData.put("length", data.getLength());

        // Check if the address is for a symbol
        SymbolTable symbolTable = program.getSymbolTable();
        Symbol primarySymbol = symbolTable.getPrimarySymbol(data.getAddress());
        if (primarySymbol != null) {
            resultData.put("symbolName", primarySymbol.getName());
            resultData.put("symbolNamespace", primarySymbol.getParentNamespace().getName());
        }

        // Get the bytes and convert to hex
        StringBuilder hexString = new StringBuilder();
        try {
            byte[] bytes = data.getBytes();
            for (byte b : bytes) {
                hexString.append(String.format("%02x", b & 0xff));
            }
            resultData.put("hexBytes", hexString.toString());
        } catch (MemoryAccessException e) {
            resultData.put("hexBytesError", "Memory access error: " + e.getMessage());
        }

        // Get the string representation that would be shown in the listing
        String representation = data.getDefaultValueRepresentation();
        resultData.put("representation", representation);

        // Get the value object
        Object value = data.getValue();
        if (value != null) {
            resultData.put("valueType", value.getClass().getSimpleName());
            resultData.put("value", value.toString());
        } else {
            resultData.put("value", null);
        }

        try {
            List<Content> contents = new ArrayList<>();
            contents.add(new TextContent(JSON.writeValueAsString(resultData)));
            return new CallToolResult(contents, false);
        } catch (JsonProcessingException e) {
            return createErrorResult("Error converting data to JSON: " + e.getMessage());
        }
    }
}
