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
package reva.tools.decompiler;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.RevaProgramManager;
import reva.tools.AbstractToolProvider;

/**
 * Tool provider for function decompilation operations.
 */
public class DecompilerToolProvider extends AbstractToolProvider {
    /**
     * Constructor
     * @param server The MCP server
     */
    public DecompilerToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() throws McpError {
        registerGetDecompiledFunctionTool();
    }

    /**
     * Register a tool to get decompiled and disassembled code for a function
     * @throws McpError if there's an error registering the tool
     */
    private void registerGetDecompiledFunctionTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the function"
        ));
        properties.put("functionName", Map.of(
            "type", "string",
            "description", "Name of the function to decompile, this should be the name in Ghidra, not the mangled name."
        ));

        List<String> required = List.of("programPath", "functionName");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-decompiled-function",
            "Get decompiled and disassembled code for a function",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get the program path and function name from the request
            String programPath = (String) args.get("programPath");
            String functionName = (String) args.get("functionName");

            if (programPath == null) {
                return createErrorResult("No program path provided");
            }

            if (functionName == null) {
                return createErrorResult("No function name provided");
            }

            // Get the program from the path
            Program program = RevaProgramManager.getProgramByPath(programPath);
            if (program == null) {
                return createErrorResult("Failed to find program: " + programPath);
            }

            Map<String, Object> resultData = new HashMap<>();
            resultData.put("programName", program.getName());
            resultData.put("functionName", functionName);

            // Get the function by name
            FunctionManager functionManager = program.getFunctionManager();
            Function function = null;

            // First try an exact match
            FunctionIterator functions = functionManager.getFunctions(true);
            while (functions.hasNext()) {
                Function f = functions.next();
                if (f.getName().equals(functionName)) {
                    function = f;
                    break;
                }
            }

            // If no exact match, try case-insensitive
            if (function == null) {
                functions = functionManager.getFunctions(true);
                while (functions.hasNext()) {
                    Function f = functions.next();
                    if (f.getName().equalsIgnoreCase(functionName)) {
                        function = f;
                        break;
                    }
                }
            }

            if (function == null) {
                return createErrorResult("Function not found: " + functionName + " in program " + program.getName() +
                    ". Check you are not using the mangled name and the namespace is correct.");
            }

            // Add function details
            resultData.put("address", "0x" + function.getEntryPoint().toString());

            // Get function metadata
            Map<String, String> metadata = new HashMap<>();
            metadata.put("signature", function.getSignature().toString());
            metadata.put("returnType", function.getReturnType().toString());
            metadata.put("callingConvention", function.getCallingConventionName());
            metadata.put("isExternal", Boolean.toString(function.isExternal()));
            metadata.put("isThunk", Boolean.toString(function.isThunk()));

            // Get parameters info
            List<Map<String, String>> parameters = new ArrayList<>();
            for (int i = 0; i < function.getParameterCount(); i++) {
                Map<String, String> paramInfo = new HashMap<>();
                paramInfo.put("name", function.getParameter(i).getName());
                paramInfo.put("dataType", function.getParameter(i).getDataType().toString());
                paramInfo.put("ordinal", Integer.toString(i));
                parameters.add(paramInfo);
            }
            metadata.put("parameterCount", Integer.toString(function.getParameterCount()));
            resultData.put("metadata", metadata);
            resultData.put("parameters", parameters);

            // Get function bounds
            AddressSetView body = function.getBody();
            resultData.put("startAddress", "0x" + function.getEntryPoint().toString());
            resultData.put("endAddress", "0x" + body.getMaxAddress().toString());
            resultData.put("sizeInBytes", body.getNumAddresses());

            // Get disassembly
            StringBuilder disassembly = new StringBuilder();
            Listing listing = program.getListing();
            InstructionIterator instructions = listing.getInstructions(body, true);

            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                disassembly.append("0x").append(instruction.getAddress()).append(": ");
                disassembly.append(instruction.toString()).append("\n");
            }
            resultData.put("disassembly", disassembly.toString());

            // Get decompilation using DecompInterface
            try {
                DecompInterface decompiler = new DecompInterface();
                decompiler.toggleCCode(true);
                decompiler.toggleSyntaxTree(true);
                decompiler.setSimplificationStyle("decompile");

                // Initialize and open the decompiler on the current program
                boolean decompInitialized = decompiler.openProgram(program);
                if (!decompInitialized) {
                    resultData.put("decompilationError", "Failed to initialize decompiler");
                    resultData.put("decompilation", "");
                } else {
                    // Decompile the function
                    DecompileResults decompileResults = decompiler.decompileFunction(function, 0, TaskMonitor.DUMMY);

                    if (decompileResults.decompileCompleted()) {
                        // Get the decompiled code as C
                        DecompiledFunction decompiledFunction = decompileResults.getDecompiledFunction();
                        String decompCode = decompiledFunction.getC();
                        resultData.put("decompilation", decompCode);

                        // Get additional details like high-level function signature
                        resultData.put("decompSignature", decompiledFunction.getSignature());
                    } else {
                        resultData.put("decompilationError", "Decompilation failed: " +
                            decompileResults.getErrorMessage());
                        resultData.put("decompilation", "");
                    }

                    // Clean up
                    decompiler.dispose();
                }
            } catch (Exception e) {
                logError("Error during decompilation", e);
                resultData.put("decompilationError", "Exception during decompilation: " + e.getMessage());
                resultData.put("decompilation", "");
            }

            return createJsonResult(resultData);
        });
    }
}
