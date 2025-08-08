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

import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
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
        registerSetFunctionPrototypeTool();
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
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-function-count")
            .title("Get Function Count")
            .description("Get the total count of functions in the program (use this before calling get-functions to plan pagination)")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            boolean filterDefaultNames = getOptionalBoolean(request, "filterDefaultNames", true);

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
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-functions")
            .title("Get Functions")
            .description("Get functions from the selected program (use get-function-count to determine the total count)")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            PaginationParams pagination = getPaginationParams(request);
            boolean filterDefaultNames = getOptionalBoolean(request, "filterDefaultNames", true);

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
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-functions-by-similarity")
            .title("Get Functions by Similarity")
            .description("Get functions from the selected program with pagination, sorted by similarity to a given function name (use get-function-count first to determine total count)")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            String searchString = getString(request, "searchString");
            PaginationParams pagination = getPaginationParams(request);
            boolean filterDefaultNames = getOptionalBoolean(request, "filterDefaultNames", true);

            if (searchString.trim().isEmpty()) {
                return createErrorResult("Search string cannot be empty");
            }

            // Get functions and collect them for similarity sorting
            List<Map<String, Object>> similarFunctionData = new ArrayList<>();

            // Iterate through all functions and collect them
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            functions.forEach(function -> {
                // Skip default Ghidra function names if filtering is enabled
                if (filterDefaultNames && SymbolUtil.isDefaultSymbolName(function.getName())) {
                    return;
                }

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

    /**
     * Register a tool to set or update a function prototype using C-style signatures
     * @throws McpError if there's an error registering the tool
     */
    private void registerSetFunctionPrototypeTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("location", Map.of(
            "type", "string",
            "description", "Address or symbol name where the function is located"
        ));
        properties.put("signature", Map.of(
            "type", "string",
            "description", "C-style function signature (e.g., 'int main(int argc, char** argv)')"
        ));
        properties.put("createIfNotExists", Map.of(
            "type", "boolean",
            "description", "Create function if it doesn't exist at the location",
            "default", true
        ));

        List<String> required = List.of("programPath", "location", "signature");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("set-function-prototype")
            .title("Set Function Prototype")
            .description("Set or update a function prototype using C-style function signatures. Can create new functions or update existing ones.")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String location = getString(request, "location");
                String signature = getString(request, "signature");
                boolean createIfNotExists = getOptionalBoolean(request, "createIfNotExists", true);

                // Resolve the address from location
                Address address = getAddressFromArgs(request, program, "location");
                if (address == null) {
                    return createErrorResult("Invalid address or symbol: " + location);
                }

                FunctionManager functionManager = program.getFunctionManager();
                Function existingFunction = functionManager.getFunctionAt(address);

                // Parse the function signature using Ghidra's parser
                FunctionSignatureParser parser = new FunctionSignatureParser(
                    program.getDataTypeManager(), null);

                FunctionDefinitionDataType functionDef;
                try {
                    // Create original signature from existing function if it exists
                    FunctionDefinitionDataType originalSignature = null;
                    if (existingFunction != null) {
                        originalSignature = new FunctionDefinitionDataType(existingFunction.getName());
                        originalSignature.setReturnType(existingFunction.getReturnType());

                        // Convert parameters
                        List<ParameterDefinition> paramDefs = new ArrayList<>();
                        for (Parameter param : existingFunction.getParameters()) {
                            paramDefs.add(new ParameterDefinitionImpl(
                                param.getName(), param.getDataType(), param.getComment()));
                        }
                        originalSignature.setArguments(paramDefs.toArray(new ParameterDefinition[0]));
                        originalSignature.setVarArgs(existingFunction.hasVarArgs());
                    }

                    functionDef = parser.parse(originalSignature, signature);
                } catch (ParseException e) {
                    return createErrorResult("Failed to parse function signature: " + e.getMessage());
                } catch (CancelledException e) {
                    return createErrorResult("Function signature parsing was cancelled");
                }

                int txId = program.startTransaction("Set Function Prototype");
                try {
                    Function function = existingFunction;

                    // Create function if it doesn't exist and creation is allowed
                    if (function == null) {
                        if (!createIfNotExists) {
                            return createErrorResult("Function does not exist at " +
                                AddressUtil.formatAddress(address) + " and createIfNotExists is false");
                        }

                        // Create a new function with minimal body (just the entry point)
                        AddressSet body = new AddressSet(address, address);
                        function = functionManager.createFunction(
                            functionDef.getName(), address, body, SourceType.USER_DEFINED);

                        if (function == null) {
                            return createErrorResult("Failed to create function at " +
                                AddressUtil.formatAddress(address));
                        }
                    }

                    // Update function name if it's different
                    if (!function.getName().equals(functionDef.getName())) {
                        function.setName(functionDef.getName(), SourceType.USER_DEFINED);
                    }

                    // Convert ParameterDefinitions to Variables (Parameters extend Variable)
                    List<Variable> parameters = new ArrayList<>();
                    ParameterDefinition[] paramDefs = functionDef.getArguments();
                    for (ParameterDefinition paramDef : paramDefs) {
                        parameters.add(new ParameterImpl(
                            paramDef.getName(),
                            paramDef.getDataType(),
                            program));
                    }

                    // Update the function signature
                    // First update return type separately
                    function.setReturnType(functionDef.getReturnType(), SourceType.USER_DEFINED);

                    // Then update parameters
                    function.replaceParameters(parameters,
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                        true, SourceType.USER_DEFINED);

                    // Set varargs if needed
                    if (functionDef.hasVarArgs() != function.hasVarArgs()) {
                        function.setVarArgs(functionDef.hasVarArgs());
                    }

                    program.endTransaction(txId, true);

                    // Return updated function information
                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("created", existingFunction == null);
                    result.put("function", createFunctionInfo(function));
                    result.put("address", AddressUtil.formatAddress(address));
                    result.put("parsedSignature", functionDef.toString());

                    return createJsonResult(result);

                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    return createErrorResult("Failed to set function prototype: " + e.getMessage());
                }

            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                return createErrorResult("Unexpected error: " + e.getMessage());
            }
        });
    }
}
