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
package reva.tools.symbols;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.RevaProgramManager;
import reva.tools.AbstractToolProvider;
import reva.util.SymbolUtil;

/**
 * Tool provider for symbol-related operations.
 */
public class SymbolToolProvider extends AbstractToolProvider {
    /**
     * Constructor
     * @param server The MCP server
     */
    public SymbolToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() throws McpError {
        registerSymbolsCountTool();
        registerSymbolsTool();
    }

    /**
     * Register a tool to get the count of symbols in a program
     * @throws McpError if there's an error registering the tool
     */
    private void registerSymbolsCountTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to get symbol count from"
        ));
        properties.put("includeExternal", Map.of(
            "type", "boolean",
            "description", "Whether to include external symbols in the count",
            "default", false
        ));
        properties.put("filterDefaultNames", Map.of(
            "type", "boolean",
            "description", "Whether to filter out default Ghidra generated names like FUN_, DAT_, etc.",
            "default", true
        ));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-symbols-count",
            "Get the total count of symbols in the program (use this before calling get-symbols to plan pagination)",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (io.modelcontextprotocol.server.McpSyncServerExchange exchange, Map<String, Object> args) -> {
            // Get the program path from the request
            String programPath = (String) args.get("programPath");
            if (programPath == null) {
                return createErrorResult("No program path provided");
            }

            // Get the program from the path
            Program program;
            try {
                program = getValidatedProgram(programPath);
            } catch (IllegalArgumentException | IllegalStateException e) {
                return createErrorResult(e.getMessage());
            }

            // Get parameters
            boolean includeExternal = args.containsKey("includeExternal") ?
                (Boolean) args.get("includeExternal") : false;
            boolean filterDefaultNames = args.containsKey("filterDefaultNames") ?
                (Boolean) args.get("filterDefaultNames") : true;

            // Count the symbols
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);

            AtomicInteger count = new AtomicInteger(0);
            symbolIterator.forEach(symbol -> {
                // Skip external symbols if not included
                if (!includeExternal && symbol.isExternal()) {
                    return;
                }

                if (!filterDefaultNames || !SymbolUtil.isDefaultSymbolName(symbol.getName())) {
                    count.incrementAndGet();
                }
            });

            // Create result data
            Map<String, Object> countData = new HashMap<>();
            countData.put("count", count.get());
            countData.put("includeExternal", includeExternal);
            countData.put("filterDefaultNames", filterDefaultNames);

            return createJsonResult(countData);
        });
    }

    /**
     * Register a tool to get symbols from a program with pagination
     * @throws McpError if there's an error registering the tool
     */
    private void registerSymbolsTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to get symbols from"
        ));
        properties.put("includeExternal", Map.of(
            "type", "boolean",
            "description", "Whether to include external symbols in the result",
            "default", false
        ));
        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (0-based)",
            "default", 0
        ));
        properties.put("maxCount", Map.of(
            "type", "integer",
            "description", "Maximum number of symbols to return (recommend using get-symbols-count first and using chunks of 200)",
            "default", 200
        ));
        properties.put("filterDefaultNames", Map.of(
            "type", "boolean",
            "description", "Whether to filter out default Ghidra generated names like FUN_, DAT_, etc.",
            "default", true
        ));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-symbols",
            "Get symbols from the selected program with pagination (use get-symbols-count first to determine total count)",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (io.modelcontextprotocol.server.McpSyncServerExchange exchange, Map<String, Object> args) -> {
            // Get the program path from the request
            String programPath = (String) args.get("programPath");
            if (programPath == null) {
                return createErrorResult("No program path provided");
            }

            // Get parameters
            boolean includeExternal = args.containsKey("includeExternal") ?
                (Boolean) args.get("includeExternal") : false;
            int startIndex = args.containsKey("startIndex") ?
                ((Number) args.get("startIndex")).intValue() : 0;
            int maxCount = args.containsKey("maxCount") ?
                ((Number) args.get("maxCount")).intValue() : 200;
            boolean filterDefaultNames = args.containsKey("filterDefaultNames") ?
                (Boolean) args.get("filterDefaultNames") : true;

            // Get the program from the path
            Program program;
            try {
                program = getValidatedProgram(programPath);
            } catch (IllegalArgumentException | IllegalStateException e) {
                return createErrorResult(e.getMessage());
            }

            // Get the symbols with pagination
            List<Map<String, Object>> symbolData = new ArrayList<>();
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);

            AtomicInteger currentIndex = new AtomicInteger(0);

            symbolIterator.forEach(symbol -> {
                // Skip external symbols if not included
                if (!includeExternal && symbol.isExternal()) {
                    return;
                }

                // Skip default names if filtering is enabled
                if (filterDefaultNames && SymbolUtil.isDefaultSymbolName(symbol.getName())) {
                    return;
                }

                int index = currentIndex.getAndIncrement();

                // Skip symbols before the start index
                if (index < startIndex) {
                    return;
                }

                // Stop after we've collected maxCount symbols
                if (symbolData.size() >= maxCount) {
                    return;
                }

                // Collect symbol data
                symbolData.add(createSymbolInfo(symbol));
            });

            // Create pagination metadata
            Map<String, Object> paginationInfo = new HashMap<>();
            paginationInfo.put("startIndex", startIndex);
            paginationInfo.put("requestedCount", maxCount);
            paginationInfo.put("actualCount", symbolData.size());
            paginationInfo.put("nextStartIndex", startIndex + symbolData.size());
            paginationInfo.put("totalProcessed", currentIndex.get());
            paginationInfo.put("includeExternal", includeExternal);
            paginationInfo.put("filterDefaultNames", filterDefaultNames);

            // Create result with metadata and symbols
            List<Object> resultData = new ArrayList<>();
            resultData.add(paginationInfo);
            resultData.addAll(symbolData);

            return createMultiJsonResult(resultData);
        });
    }

    /**
     * Create a map of symbol information
     * @param symbol The symbol to extract information from
     * @return Map containing symbol properties
     */
    private Map<String, Object> createSymbolInfo(Symbol symbol) {
        Map<String, Object> symbolInfo = new HashMap<>();
        symbolInfo.put("name", symbol.getName());
        symbolInfo.put("address", "0x" + symbol.getAddress().toString());
        symbolInfo.put("namespace", symbol.getParentNamespace().getName());
        symbolInfo.put("id", symbol.getID());
        symbolInfo.put("symbolType", symbol.getSymbolType().toString());
        symbolInfo.put("isPrimary", symbol.isPrimary());
        symbolInfo.put("isExternal", symbol.isExternal());

        // For function symbols, add specific data
        if (symbol.getSymbolType() == SymbolType.FUNCTION) {
            symbolInfo.put("isFunction", true);
        } else {
            symbolInfo.put("isFunction", false);
        }

        return symbolInfo;
    }
}
