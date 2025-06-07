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
import reva.plugin.RevaProgramManager;
import reva.tools.AbstractToolProvider;
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
        registerGetDataByAddressTool();
        registerGetDataBySymbolTool();
        registerApplyDataTypeToSymbolTool();
        registerCreateLabelTool();
    }

    /**
     * Register a tool to get data at a specific address in a program
     * @throws McpError if there's an error registering the tool
     */
    private void registerGetDataByAddressTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the data"
        ));
        properties.put("address", Map.of(
            "type", "string",
            "description", "Address or symbol name to get data from (e.g., '0x00400000' or 'main')"
        ));

        List<String> required = List.of("programPath", "address");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-data-at-address",
            "Get data at a specific address in a program",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get the program path and address from the request
            String programPath = (String) args.get("programPath");
            String addressString = (String) args.get("address");

            if (programPath == null) {
                return createErrorResult("No program path provided");
            }
            if (addressString == null) {
                return createErrorResult("No address provided");
            }

            // Get the program from the path
            Program program;
            try {
                program = getValidatedProgram(programPath);
            } catch (IllegalArgumentException | IllegalStateException e) {
                return createErrorResult(e.getMessage());
            }

            // Parse the address or symbol
            Address address = AddressUtil.resolveAddressOrSymbol(program, addressString);
            if (address == null) {
                return createErrorResult("Invalid address or symbol: " + addressString);
            }

            return getDataAtAddressResult(program, address);
        });
    }

    /**
     * Register a tool to get data by symbol name in a program
     * @throws McpError if there's an error registering the tool
     */
    private void registerGetDataBySymbolTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the data"
        ));
        properties.put("symbolName", Map.of(
            "type", "string",
            "description", "Name of the symbol to get data for"
        ));

        List<String> required = List.of("programPath", "symbolName");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-data-by-symbol",
            "Get data for a specific symbol in a program",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get the program path and symbol name from the request
            String programPath = (String) args.get("programPath");
            String symbolName = (String) args.get("symbolName");

            if (programPath == null) {
                return createErrorResult("No program path provided");
            }
            if (symbolName == null) {
                return createErrorResult("No symbol name provided");
            }

            // Get the program from the path
            Program program;
            try {
                program = getValidatedProgram(programPath);
            } catch (IllegalArgumentException | IllegalStateException e) {
                return createErrorResult(e.getMessage());
            }

            // Find the symbol
            SymbolTable symbolTable = program.getSymbolTable();
            List<Symbol> symbols = symbolTable.getLabelOrFunctionSymbols(symbolName, null);

            if (symbols.isEmpty()) {
                return createErrorResult("Symbol not found: " + symbolName);
            }

            // Use the first matching symbol's address
            Symbol symbol = symbols.get(0);
            Address address = symbol.getAddress();

            return getDataAtAddressResult(program, address);
        });
    }

    /**
     * Register a tool to apply a data type to a symbol
     * @throws McpError if there's an error registering the tool
     */
    private void registerApplyDataTypeToSymbolTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the symbol"
        ));
        properties.put("symbolName", Map.of(
            "type", "string",
            "description", "Name of the symbol to apply the data type to"
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

        List<String> required = List.of("programPath", "symbolName", "dataTypeString");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "apply-data-type-to-symbol",
            "Apply a data type to a symbol in a program",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get the parameters from the request
            String programPath = (String) args.get("programPath");
            String symbolName = (String) args.get("symbolName");
            String dataTypeString = (String) args.get("dataTypeString");
            String archiveName = args.containsKey("archiveName") ? (String) args.get("archiveName") : "";

            if (programPath == null) {
                return createErrorResult("No program path provided");
            }
            if (symbolName == null) {
                return createErrorResult("No symbol name provided");
            }
            if (dataTypeString == null || dataTypeString.isEmpty()) {
                return createErrorResult("No data type string provided");
            }

            // Get the program from the path
            Program program;
            try {
                program = getValidatedProgram(programPath);
            } catch (IllegalArgumentException | IllegalStateException e) {
                return createErrorResult(e.getMessage());
            }

            // Find the symbol
            SymbolTable symbolTable = program.getSymbolTable();
            List<Symbol> symbols = symbolTable.getLabelOrFunctionSymbols(symbolName, null);

            if (symbols.isEmpty()) {
                return createErrorResult("Symbol not found: " + symbolName);
            }

            // Use the first matching symbol
            Symbol symbol = symbols.get(0);
            Address symbolAddress = symbol.getAddress();

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
                int transactionID = program.startTransaction("Apply Data Type to Symbol");
                boolean success = false;

                try {

                    // Get the listing and apply the data type at the symbol's address
                    Listing listing = program.getListing();

                    // Clear any existing data at the address
                    if (listing.getDataAt(symbolAddress) != null) {
                        listing.clearCodeUnits(symbolAddress, symbolAddress.add(dataType.getLength() - 1), false);
                    }

                    // Create the data at the address with the specified data type
                    Data createdData = listing.createData(symbolAddress, dataType);

                    if (createdData == null) {
                        throw new Exception("Failed to create data at address: " + symbolAddress);
                    }

                    success = true;

                    // Create result data
                    Map<String, Object> resultData = new HashMap<>();
                    resultData.put("success", true);
                    resultData.put("symbolName", symbol.getName());
                    resultData.put("address", "0x" + symbolAddress.toString());
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
        properties.put("address", Map.of(
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

        List<String> required = List.of("programPath", "address", "labelName");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "create-label",
            "Create a label at a specific address in a program",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get the parameters from the request
            String programPath = (String) args.get("programPath");
            String addressString = (String) args.get("address");
            String labelName = (String) args.get("labelName");
            boolean setAsPrimary = args.containsKey("setAsPrimary") ?
                (Boolean) args.get("setAsPrimary") : true;

            if (programPath == null) {
                return createErrorResult("No program path provided");
            }
            if (addressString == null) {
                return createErrorResult("No address provided");
            }
            if (labelName == null || labelName.isEmpty()) {
                return createErrorResult("No label name provided");
            }

            // Get the program from the path
            Program program;
            try {
                program = getValidatedProgram(programPath);
            } catch (IllegalArgumentException | IllegalStateException e) {
                return createErrorResult(e.getMessage());
            }

            // Parse the address or symbol
            Address address = AddressUtil.resolveAddressOrSymbol(program, addressString);
            if (address == null) {
                return createErrorResult("Invalid address or symbol: " + addressString);
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
        // Get the listing
        Listing listing = program.getListing();

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
