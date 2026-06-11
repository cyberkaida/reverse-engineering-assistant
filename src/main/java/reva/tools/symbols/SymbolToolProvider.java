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
import reva.util.SchemaUtil;
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
    public void registerTools() {
        registerSymbolsCountTool();
        registerSymbolsTool();
    }

    /**
     * Register a tool to get the count of symbols in a program
     */
    private void registerSymbolsCountTool() {
        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-symbols-count")
            .title("Get Symbols Count")
            .description("Get the total count of symbols in the program (use this before calling get-symbols to plan pagination)")
            .inputSchema(SchemaUtil.builder()
                .programPath()
                .booleanProperty("includeExternal",
                    "Whether to include external symbols in the count", false)
                .booleanProperty("filterDefaultNames",
                    "Whether to filter out default Ghidra generated names like FUN_, DAT_, etc.", true)
                .build())
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            boolean includeExternal = getOptionalBoolean(request, "includeExternal", false);
            boolean filterDefaultNames = getOptionalBoolean(request, "filterDefaultNames", true);

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
     */
    private void registerSymbolsTool() {
        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-symbols")
            .title("Get Symbols")
            .description("Get symbols from the selected program with pagination (use get-symbols-count first to determine total count)")
            .inputSchema(SchemaUtil.builder()
                .programPath()
                .booleanProperty("includeExternal",
                    "Whether to include external symbols in the result", false)
                .pagination(200)
                .booleanProperty("filterDefaultNames",
                    "Whether to filter out default Ghidra generated names like FUN_, DAT_, etc.", true)
                .build())
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            boolean includeExternal = getOptionalBoolean(request, "includeExternal", false);
            PaginationParams pagination = getPaginationParams(request, 200);
            boolean filterDefaultNames = getOptionalBoolean(request, "filterDefaultNames", true);

            // Get the symbols with pagination
            List<Map<String, Object>> symbolData = new ArrayList<>();
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);

            int currentIndex = 0;

            while (symbolIterator.hasNext()) {
                Symbol symbol = symbolIterator.next();

                // Skip external symbols if not included
                if (!includeExternal && symbol.isExternal()) {
                    continue;
                }

                // Skip default names if filtering is enabled
                if (filterDefaultNames && SymbolUtil.isDefaultSymbolName(symbol.getName())) {
                    continue;
                }

                int index = currentIndex++;

                // Skip symbols before the start index
                if (index < pagination.startIndex()) {
                    continue;
                }

                // Stop after we've collected maxCount symbols
                if (symbolData.size() >= pagination.maxCount()) {
                    break;
                }

                // Collect symbol data
                symbolData.add(createSymbolInfo(symbol));
            }

            // Create pagination metadata
            Map<String, Object> paginationInfo = paginationResult(pagination, "symbols", symbolData, currentIndex);
            paginationInfo.put("includeExternal", includeExternal);
            paginationInfo.put("filterDefaultNames", filterDefaultNames);
            return createJsonResult(paginationInfo);
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
