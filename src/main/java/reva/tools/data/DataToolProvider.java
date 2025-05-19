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
            "description", "Address to get data from (e.g., '0x00400000')"
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
            Program program = RevaProgramManager.getProgramByPath(programPath);
            if (program == null) {
                return createErrorResult("Failed to find Program: " + programPath);
            }

            // Parse the address
            Address address;
            if (addressString.toLowerCase().startsWith("0x")) {
                addressString = addressString.substring(2);
            }
            try {
                address = program.getAddressFactory().getAddress(addressString);
            } catch (Exception e) {
                return createErrorResult("Invalid address format: " + addressString);
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
            Program program = RevaProgramManager.getProgramByPath(programPath);
            if (program == null) {
                return createErrorResult("Failed to find Program: " + programPath);
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
     * Helper method to get data at a specific address and format the result
     * @param program The program to look up data in
     * @param address The address where to find data
     * @return Call tool result with data information
     */
    private CallToolResult getDataAtAddressResult(Program program, Address address) {
        // Get the listing
        Listing listing = program.getListing();

        // Get data at the address
        Data data = listing.getDataContaining(address);
        if (data == null) {
            return createErrorResult("No data found at address: 0x" + address.toString());
        }

        // Create result data
        Map<String, Object> resultData = new HashMap<>();
        resultData.put("address", "0x" + data.getAddress().toString());
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
