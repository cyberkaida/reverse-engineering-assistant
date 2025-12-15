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
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.IncludeFilterUtil;

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
    public void registerTools() {
        registerSymbolsCountTool();
        registerSymbolsTool();
    }

    /**
     * Create the base properties schema
     */
    private Map<String, Object> createBasePropertiesSchema() {

        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
                "type", "string",
                "description", "Path in the Ghidra Project to the program to get symbols from"
        ));
        properties.put("includeExternal", Map.of(
                "type", "boolean",
                "description", "Whether to include external symbols",
                "default", false
        ));
        properties.put("include", IncludeFilterUtil.getIncludePropertyDefinition());

        return properties;
    }

    /**
     * Register a tool to get the count of symbols in a program
     */
    private void registerSymbolsCountTool() {
        // Define schema for the tool
        Map<String, Object> properties = this.createBasePropertiesSchema();

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-symbols-count")
            .title("Get Symbols Count")
            .description("Get the total count of symbols in the program (use this before calling get-symbols to plan pagination)")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            boolean includeExternal = getOptionalBoolean(request, "includeExternal", false);
            String include = IncludeFilterUtil.validate(getOptionalString(request, "include", null));

            logInfo("get-symbols-count: Counting symbols in " + program.getName() + " (include=" + include + ")");

            // Count the symbols
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);

            AtomicInteger count = new AtomicInteger(0);
            symbolIterator.forEach(symbol -> {
                // Skip external symbols if not included
                if (!includeExternal && symbol.isExternal()) {
                    return;
                }

                if (IncludeFilterUtil.shouldInclude(symbol.getName(), include)) {
                    count.incrementAndGet();
                }
            });

            // Create result data
            Map<String, Object> countData = new HashMap<>();
            countData.put("count", count.get());
            countData.put("includeExternal", includeExternal);
            countData.put("include", include);

            return createJsonResult(countData);
        });
    }

    /**
     * Register a tool to get symbols from a program with pagination
     */
    private void registerSymbolsTool() {
        // Define schema for the tool
        Map<String, Object> properties = this.createBasePropertiesSchema();

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

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-symbols")
            .title("Get Symbols")
            .description("Get symbols from the selected program with pagination (use get-symbols-count first to determine total count)")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            boolean includeExternal = getOptionalBoolean(request, "includeExternal", false);
            PaginationParams pagination = getPaginationParams(request, 200);
            String include = IncludeFilterUtil.validate(getOptionalString(request, "include", null));

            logInfo("get-symbols: Listing symbols in " + program.getName() + " (include=" + include + ")");

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

                // Skip symbols based on include filter
                if (!IncludeFilterUtil.shouldInclude(symbol.getName(), include)) {
                    return;
                }

                int index = currentIndex.getAndIncrement();

                // Skip symbols before the start index
                if (index < pagination.startIndex()) {
                    return;
                }

                // Stop after we've collected maxCount symbols
                if (symbolData.size() >= pagination.maxCount()) {
                    return;
                }

                // Collect symbol data
                symbolData.add(createSymbolInfo(symbol));
            });

            // Create pagination metadata
            Map<String, Object> paginationInfo = new HashMap<>();
            paginationInfo.put("startIndex", pagination.startIndex());
            paginationInfo.put("requestedCount", pagination.maxCount());
            paginationInfo.put("actualCount", symbolData.size());
            paginationInfo.put("nextStartIndex", pagination.startIndex() + symbolData.size());
            paginationInfo.put("totalProcessed", currentIndex.get());
            paginationInfo.put("includeExternal", includeExternal);
            paginationInfo.put("include", include);

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
        symbolInfo.put("address", AddressUtil.formatAddress(symbol.getAddress()));
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
