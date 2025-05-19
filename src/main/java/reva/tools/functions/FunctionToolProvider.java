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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.RevaProgramManager;
import reva.tools.AbstractToolProvider;
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
        registerFunctionsTool();
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

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-functions",
            "Get functions from the selected program",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get the program path from the request
            String programPath = (String) args.get("programPath");
            if (programPath == null) {
                return createErrorResult("No program path provided");
            }

            // Get the program from the path
            Program program = RevaProgramManager.getProgramByPath(programPath);
            if (program == null) {
                return createErrorResult("Failed to find Program: " + programPath);
            }

            // Get the filter parameter
            boolean filterDefaultNames = (Boolean) args.getOrDefault("filterDefaultNames", true);

            // Get the functions from the program
            List<Map<String, Object>> functionData = new ArrayList<>();

            // Iterate through all functions
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            functions.forEach(function -> {
                // Skip default Ghidra function names if filtering is enabled
                if (filterDefaultNames && SymbolUtil.isDefaultSymbolName(function.getName())) {
                    return;
                }

                functionData.add(createFunctionInfo(function));
            });

            // Add metadata about the filtering
            Map<String, Object> metadataInfo = new HashMap<>();
            metadataInfo.put("count", functionData.size());
            metadataInfo.put("filterDefaultNames", filterDefaultNames);

            // Create combined result
            List<Object> resultData = new ArrayList<>();
            resultData.add(metadataInfo);
            resultData.addAll(functionData);
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
