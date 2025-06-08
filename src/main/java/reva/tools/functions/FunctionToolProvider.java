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
package reva.tools.functions;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.RevaProgramManager;
import reva.tools.AbstractToolProvider;
import reva.tools.ProgramValidationException;
import reva.util.SimilarityComparator;
import reva.util.SymbolUtil;

/**
 * Tool provider for function-related operations.
 */
public class FunctionToolProvider extends AbstractToolProvider {
    /**
     * Constructor
     * @param server The MCP server
     */
    public FunctionToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() throws McpError {
        registerFunctionCountTool();
        registerFunctionsTool();
        registerFunctionsBySimilarityTool();
    }

    /**
     * Register a tool to count the functions in a program
     * @throws McpError if there's an error registering the tool
     */
    private void registerFunctionCountTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to get functions from"
        ));
        properties.put("filterDefaultNames", Map.of(
            "type", "boolean",
            "description", "Whether to filter out default Ghidra generated names like FUN_, DAT_, etc.",
            "default", true
        ));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-function-count",
            "Get the total count of functions in the program (use this before calling get-functions to plan pagination)",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(args);
            boolean filterDefaultNames = getOptionalBoolean(args, "filterDefaultNames", true);

            // Get the functions from the program
            List<Map<String, Object>> functionData = new ArrayList<>();

            AtomicInteger count = new AtomicInteger(0);

            // Iterate through all functions
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            functions.forEach(function -> {
                // Skip default Ghidra function names if filtering is enabled
                if (filterDefaultNames && SymbolUtil.isDefaultSymbolName(function.getName())) {
                    return;
                }
                
                count.incrementAndGet();
            });

            // Create result data
            Map<String, Object> countData = new HashMap<>();
            countData.put("count", count.get());

            return createJsonResult(countData);
        });
    }

    /**
     * Register a tool to list functions from a program
     * @throws McpError if there's an error registering the tool
     */
    private void registerFunctionsTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to get functions from"
        ));
        properties.put("filterDefaultNames", Map.of(
            "type", "boolean",
            "description", "Whether to filter out default Ghidra generated names like FUN_, DAT_, etc.",
            "default", true
        ));

        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (0-based)",
            "default", 0
        ));
        properties.put("maxCount", Map.of(
            "type", "integer",
            "description", "Maximum number of functions to return (recommended to use get-function-count first and request chunks of 100 at most)",
            "default", 100
        ));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-functions",
            "Get functions from the selected program (use get-function-count to determine the total count)",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(args);
            PaginationParams pagination = getPaginationParams(args);
            boolean filterDefaultNames = getOptionalBoolean(args, "filterDefaultNames", true);

            // Get the functions from the program
            List<Map<String, Object>> functionData = new ArrayList<>();

            AtomicInteger currentIndex = new AtomicInteger(0);

            // Iterate through all functions
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            functions.forEach(function -> {
                // Skip default Ghidra function names if filtering is enabled
                if (filterDefaultNames && SymbolUtil.isDefaultSymbolName(function.getName())) {
                    return;
                }
                
                int index = currentIndex.getAndIncrement();
                // Skip functions before the start index
                if (index < pagination.startIndex()) {
                    return;
                }

                // Stop after we've collected maxCount functions
                if (functionData.size() >= pagination.maxCount()) {
                    return;
                }

                functionData.add(createFunctionInfo(function));
            });

            // Add metadata about the filtering
            Map<String, Object> metadataInfo = new HashMap<>();
            metadataInfo.put("startIndex", pagination.startIndex());
            metadataInfo.put("requestedCount", pagination.maxCount());
            metadataInfo.put("actualCount", functionData.size());
            metadataInfo.put("nextStartIndex", pagination.startIndex() + functionData.size());
            metadataInfo.put("totalProcessed", currentIndex.get());
            metadataInfo.put("filterDefaultNames", filterDefaultNames);

            // Create combined result
            List<Object> resultData = new ArrayList<>();
            resultData.add(metadataInfo);
            resultData.addAll(functionData);
            return createMultiJsonResult(resultData);
        });
    }

    /**
     * Register a tool to get functions from a program with pagination, sorted by similarity to a given function name.
     * @throws McpError if there's an error registering the tool
     */
    private void registerFunctionsBySimilarityTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to get functions from"
        ));

        properties.put("searchString", Map.of(
            "type", "string",
            "description", "Function name to compare against for similarity (scored by longest common substring length between the search string and each function name in the program)"
        ));

        properties.put("filterDefaultNames", Map.of(
            "type", "boolean",
            "description", "Whether to filter out default Ghidra generated names like FUN_, DAT_, etc.",
            "default", true
        ));

        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (0-based)",
            "default", 0
        ));
        properties.put("maxCount", Map.of(
            "type", "integer",
            "description", "Maximum number of functions to return (recommended to use get-function-count first and request chunks of 100 at most)",
            "default", 100
        ));

        List<String> required = List.of("programPath", "searchString");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-functions-by-similarity",
            "Get functions from the selected program with pagination, sorted by similarity to a given function name (use get-function-count first to determine total count)",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(args);
            String searchString = getString(args, "searchString");
            PaginationParams pagination = getPaginationParams(args);
            boolean filterDefaultNames = getOptionalBoolean(args, "filterDefaultNames", true);

            if (searchString.trim().isEmpty()) {
                throw new IllegalArgumentException("Search string cannot be empty");
            }

            // Get functions and collect them for similarity sorting
            List<Map<String, Object>> similarFunctionData = new ArrayList<>();
            AtomicInteger currentIndex = new AtomicInteger(0);

            // Iterate through all functions and collect them
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            functions.forEach(function -> {
                // Skip default Ghidra function names if filtering is enabled
                if (filterDefaultNames && SymbolUtil.isDefaultSymbolName(function.getName())) {
                    return;
                }

                int index = currentIndex.getAndIncrement();

                // Collect function data
                Map<String, Object> functionInfo = createFunctionInfo(function);
                if (functionInfo != null) {
                    similarFunctionData.add(functionInfo);
                }
            });

            // Sort functions by similarity to search string
            Collections.sort(similarFunctionData, new SimilarityComparator<>(searchString, new SimilarityComparator.StringExtractor<Map<String, Object>>() {
                @Override
                public String extract(Map<String, Object> item) {
                    return (String) item.get("name");
                }
            }));

            // Apply pagination to sorted results
            List<Map<String, Object>> paginatedFunctionData = similarFunctionData.subList(
                pagination.startIndex(), 
                Math.min(pagination.startIndex() + pagination.maxCount(), similarFunctionData.size())
            );

            // Create pagination metadata
            Map<String, Object> paginationInfo = new HashMap<>();
            paginationInfo.put("searchString", searchString);
            paginationInfo.put("startIndex", pagination.startIndex());
            paginationInfo.put("requestedCount", pagination.maxCount());
            paginationInfo.put("actualCount", paginatedFunctionData.size());
            paginationInfo.put("nextStartIndex", pagination.startIndex() + paginatedFunctionData.size());
            paginationInfo.put("totalMatchingFunctions", similarFunctionData.size());
            paginationInfo.put("filterDefaultNames", filterDefaultNames);

            // Create combined result
            List<Object> resultData = new ArrayList<>();
            resultData.add(paginationInfo);
            resultData.addAll(paginatedFunctionData);
            return createMultiJsonResult(resultData);
        });
    }

    /**
     * Create a map of function information
     * @param function The function to extract information from
     * @return Map containing function properties
     */
    private Map<String, Object> createFunctionInfo(Function function) {
        Map<String, Object> functionInfo = new HashMap<>();

        // Basic information
        functionInfo.put("name", function.getName());
        functionInfo.put("address", "0x" + function.getEntryPoint().toString());

        // Get the function's body to determine the end address and size
        AddressSetView body = function.getBody();
        if (body != null && body.getMaxAddress() != null) {
            functionInfo.put("endAddress", "0x" + body.getMaxAddress().toString());
            functionInfo.put("sizeInBytes", body.getNumAddresses());
        } else {
            functionInfo.put("sizeInBytes", 0);
        }

        // Additional function metadata
        functionInfo.put("signature", function.getSignature().toString());
        functionInfo.put("returnType", function.getReturnType().toString());
        functionInfo.put("isExternal", function.isExternal());
        functionInfo.put("isThunk", function.isThunk());
        functionInfo.put("bodySize", function.getBody().getNumAddresses());

        // Add parameters info
        List<Map<String, String>> parameters = new ArrayList<>();
        for (int i = 0; i < function.getParameterCount(); i++) {
            Map<String, String> paramInfo = new HashMap<>();
            paramInfo.put("name", function.getParameter(i).getName());
            paramInfo.put("dataType", function.getParameter(i).getDataType().toString());
            parameters.add(paramInfo);
        }
        functionInfo.put("parameters", parameters);

        return functionInfo;
    }
}
