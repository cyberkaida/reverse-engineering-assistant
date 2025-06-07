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
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.regex.Matcher;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.data.DataType;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.RevaProgramManager;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.DataTypeParserUtil;
import reva.util.DecompilationDiffUtil;

/**
 * Tool provider for function decompilation operations.
 */
public class DecompilerToolProvider extends AbstractToolProvider {

    // Track which functions have been read by the LLM to enforce read-before-modify pattern
    private final Map<String, Long> readDecompilationTracker = new ConcurrentHashMap<>();
    /**
     * Constructor
     * @param server The MCP server
     */
    public DecompilerToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() throws McpError {
        registerGetDecompilationTool();
        registerSearchDecompilationTool();
        registerRenameVariablesTool();
        registerChangeVariableDataTypesTool();
    }

    /**
     * Register a tool to get decompiled code for a function with line range support (Claude Code style)
     * @throws McpError if there's an error registering the tool
     */
    private void registerGetDecompilationTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the function"
        ));
        properties.put("functionNameOrAddress", Map.of(
            "type", "string",
            "description", "Function name, address, or symbol to decompile (e.g. 'main', '0x00401000', or 'start'). For addresses pointing inside a function, the containing function will be decompiled."
        ));
        properties.put("offset", Map.of(
            "type", "integer",
            "description", "Line number to start reading from (1-based). Defaults to 1.",
            "default", 1
        ));
        properties.put("limit", Map.of(
            "type", "integer",
            "description", "Number of lines to return. Defaults to 50 lines to conserve context. Use smaller chunks (10-20 lines) for initial exploration, then expand as needed.",
            "default", 50
        ));
        properties.put("includeDisassembly", Map.of(
            "type", "boolean",
            "description", "Whether to include assembly listing alongside decompilation for sync",
            "default", false
        ));

        List<String> required = List.of("programPath", "functionNameOrAddress");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-decompilation",
            "Get decompiled code for a function with line range support. Defaults to 50 lines to conserve context - start with small chunks (10-20 lines) then expand as needed using offset/limit.",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get the program path and function name/address from the request
            String programPath = (String) args.get("programPath");
            String functionNameOrAddress = (String) args.get("functionNameOrAddress");
            int offset = args.containsKey("offset") ? ((Number) args.get("offset")).intValue() : 1;
            Integer limit = args.containsKey("limit") ? ((Number) args.get("limit")).intValue() : 50; // Default to 50 lines for context conservation
            boolean includeDisassembly = args.containsKey("includeDisassembly") ? (Boolean) args.get("includeDisassembly") : false;

            if (programPath == null) {
                return createErrorResult("No program path provided");
            }

            if (functionNameOrAddress == null) {
                return createErrorResult("No function name or address provided");
            }

            // Get the program from the path
            Program program = RevaProgramManager.getProgramByPath(programPath);
            if (program == null) {
                return createErrorResult("Failed to find program: " + programPath);
            }

            Map<String, Object> resultData = new HashMap<>();
            resultData.put("programName", program.getName());

            Function function = null;

            // First try to resolve as address or symbol
            Address address = AddressUtil.resolveAddressOrSymbol(program, functionNameOrAddress);
            if (address != null) {
                // Get the containing function for this address
                function = AddressUtil.getContainingFunction(program, address);
                if (function != null) {
                    resultData.put("functionName", function.getName());
                    resultData.put("resolvedFrom", "address/symbol");
                    resultData.put("inputAddress", AddressUtil.formatAddress(address));
                }
            }

            // If not found by address, try by function name
            if (function == null) {
                FunctionManager functionManager = program.getFunctionManager();

                // First try an exact match
                FunctionIterator functions = functionManager.getFunctions(true);
                while (functions.hasNext()) {
                    Function f = functions.next();
                    if (f.getName().equals(functionNameOrAddress)) {
                        function = f;
                        resultData.put("functionName", function.getName());
                        resultData.put("resolvedFrom", "name-exact");
                        break;
                    }
                }

                // If no exact match, try case-insensitive
                if (function == null) {
                    functions = functionManager.getFunctions(true);
                    while (functions.hasNext()) {
                        Function f = functions.next();
                        if (f.getName().equalsIgnoreCase(functionNameOrAddress)) {
                            function = f;
                            resultData.put("functionName", function.getName());
                            resultData.put("resolvedFrom", "name-case-insensitive");
                            break;
                        }
                    }
                }
            }

            if (function == null) {
                return createErrorResult("Function not found: " + functionNameOrAddress + " in program " + program.getName() +
                    ". Tried as address/symbol and function name. Check you are not using the mangled name and the namespace is correct.");
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
                        // Get the decompiled code and markup
                        DecompiledFunction decompiledFunction = decompileResults.getDecompiledFunction();
                        ClangTokenGroup markup = decompileResults.getCCodeMarkup();

                        // Get synchronized decompilation with optional assembly listing
                        Map<String, Object> syncedContent = getSynchronizedContent(program, markup, decompiledFunction.getC(),
                            offset, limit, includeDisassembly);

                        // Add content to results
                        resultData.putAll(syncedContent);

                        // Get additional details like high-level function signature
                        resultData.put("decompSignature", decompiledFunction.getSignature());

                        // Track that this function's decompilation has been read
                        String functionKey = programPath + ":" + function.getName();
                        readDecompilationTracker.put(functionKey, System.currentTimeMillis());

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

    /**
     * Register a tool to search decompilation across all functions
     * @throws McpError if there's an error registering the tool
     */
    private void registerSearchDecompilationTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to search"
        ));
        properties.put("pattern", Map.of(
            "type", "string",
            "description", "Regular expression pattern to search for in decompiled functions"
        ));
        properties.put("maxResults", Map.of(
            "type", "integer",
            "description", "Maximum number of search results to return",
            "default", 50
        ));
        properties.put("caseSensitive", Map.of(
            "type", "boolean",
            "description", "Whether the search should be case sensitive",
            "default", false
        ));

        List<String> required = List.of("programPath", "pattern");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "search-decompilation",
            "Search for patterns across all function decompilations in a program. Returns function names and line numbers where patterns match.",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get arguments from the request
            String programPath = (String) args.get("programPath");
            String pattern = (String) args.get("pattern");
            int maxResults = args.containsKey("maxResults") ? ((Number) args.get("maxResults")).intValue() : 50;
            boolean caseSensitive = args.containsKey("caseSensitive") ? (Boolean) args.get("caseSensitive") : false;

            // Validate arguments
            if (programPath == null) {
                return createErrorResult("No program path provided");
            }
            if (pattern == null || pattern.trim().isEmpty()) {
                return createErrorResult("No search pattern provided");
            }

            // Get the program from the path
            Program program = RevaProgramManager.getProgramByPath(programPath);
            if (program == null) {
                return createErrorResult("Failed to find program: " + programPath);
            }

            // Perform the search
            List<Map<String, Object>> searchResults = searchDecompilationInProgram(program, pattern, maxResults, caseSensitive);

            // Create result data
            Map<String, Object> resultData = new HashMap<>();
            resultData.put("programName", program.getName());
            resultData.put("pattern", pattern);
            resultData.put("caseSensitive", caseSensitive);
            resultData.put("resultsCount", searchResults.size());
            resultData.put("maxResults", maxResults);
            resultData.put("results", searchResults);

            return createJsonResult(resultData);
        });
    }

    /**
     * Register a tool to rename variables in a decompiled function
     * @throws McpError if there's an error registering the tool
     */
    private void registerRenameVariablesTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the function"
        ));
        properties.put("functionNameOrAddress", Map.of(
            "type", "string",
            "description", "Function name, address, or symbol to rename variables in (e.g. 'main', '0x00401000', or 'start'). For addresses pointing inside a function, the containing function will be used."
        ));
        properties.put("variableMappings", Map.of(
            "type", "object",
            "description", "Mapping of old variable names to new variable names. Only rename the variables that need to be changed.",
            "additionalProperties", Map.of("type", "string")
        ));

        List<String> required = List.of("programPath", "functionNameOrAddress", "variableMappings");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "rename-variables",
            "Rename variables in a decompiled function",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get arguments from the request
            String programPath = (String) args.get("programPath");
            String functionNameOrAddress = (String) args.get("functionNameOrAddress");
            @SuppressWarnings("unchecked")
            Map<String, String> mappings = (Map<String, String>) args.get("variableMappings");

            // Validate arguments
            if (programPath == null) {
                return createErrorResult("No program path provided");
            }
            if (functionNameOrAddress == null) {
                return createErrorResult("No function name or address provided");
            }
            if (mappings == null || mappings.isEmpty()) {
                return createErrorResult("No variable mappings provided");
            }

            // Get the program from the path
            Program program = RevaProgramManager.getProgramByPath(programPath);
            if (program == null) {
                return createErrorResult("Failed to find program: " + programPath);
            }

            Function function = null;

            // First try to resolve as address or symbol
            Address address = AddressUtil.resolveAddressOrSymbol(program, functionNameOrAddress);
            if (address != null) {
                // Get the containing function for this address
                function = AddressUtil.getContainingFunction(program, address);
            }

            // If not found by address, try by function name
            if (function == null) {
                FunctionManager functionManager = program.getFunctionManager();

                // First try an exact match
                FunctionIterator functions = functionManager.getFunctions(true);
                while (functions.hasNext()) {
                    Function f = functions.next();
                    if (f.getName().equals(functionNameOrAddress)) {
                        function = f;
                        break;
                    }
                }

                // If no exact match, try case-insensitive
                if (function == null) {
                    functions = functionManager.getFunctions(true);
                    while (functions.hasNext()) {
                        Function f = functions.next();
                        if (f.getName().equalsIgnoreCase(functionNameOrAddress)) {
                            function = f;
                            break;
                        }
                    }
                }
            }

            if (function == null) {
                return createErrorResult("Function not found: " + functionNameOrAddress + " in program " + program.getName() +
                    ". Tried as address/symbol and function name. Check you are not using the mangled name and the namespace is correct.");
            }

            // Validate that the LLM has read the decompilation for this function first
            String functionKey = programPath + ":" + function.getName();
            if (!hasReadDecompilation(functionKey)) {
                return createErrorResult("You must read the decompilation for function '" + function.getName() +
                    "' using get-decompilation tool before making variable changes. This ensures you understand the current state of the code.");
            }

            // Initialize the decompiler
            DecompInterface decompiler = new DecompInterface();
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            decompiler.setSimplificationStyle("decompile");

            boolean decompInitialized = decompiler.openProgram(program);
            if (!decompInitialized) {
                return createErrorResult("Failed to initialize decompiler");
            }

            // Decompile the function to get the "before" state
            DecompileResults decompileResults = decompiler.decompileFunction(function, 0, TaskMonitor.DUMMY);
            if (!decompileResults.decompileCompleted()) {
                decompiler.dispose();
                return createErrorResult("Decompilation failed: " + decompileResults.getErrorMessage());
            }

            // Capture the original decompilation for diff comparison
            String beforeDecompilation = decompileResults.getDecompiledFunction().getC();

            // Track if we actually renamed any variables
            boolean anyRenamed = false;

            // Process variable mappings
            try {
                int transactionId = program.startTransaction("Rename Variables");

                // Get the high function from the decompile results
                HighFunction highFunction = decompileResults.getHighFunction();

                // Process variables using a manual approach since HighFunction.getSymbols() isn't available
                Iterator<HighSymbol> localVars = highFunction.getLocalSymbolMap().getSymbols();
                while (localVars.hasNext()) {
                    HighSymbol symbol = localVars.next();
                    String oldName = symbol.getName();
                    String newName = mappings.get(oldName);

                    if (newName != null) {
                        try {
                            // Update the variable name in the database using HighFunctionDBUtil
                            HighFunctionDBUtil.updateDBVariable(symbol, newName, null, SourceType.USER_DEFINED);
                            anyRenamed = true;
                            logInfo("Renamed local variable " + oldName + " to " + newName);
                        }
                        catch (DuplicateNameException | InvalidInputException e) {
                            logError("Failed to rename local variable " + oldName + " to " + newName, e);
                        }
                    }
                }

                // Also check global variables
                Iterator<HighSymbol> globalVars = highFunction.getGlobalSymbolMap().getSymbols();
                while (globalVars.hasNext()) {
                    HighSymbol symbol = globalVars.next();
                    String oldName = symbol.getName();
                    String newName = mappings.get(oldName);

                    if (newName != null) {
                        try {
                            // Update the variable name in the database using HighFunctionDBUtil
                            HighFunctionDBUtil.updateDBVariable(symbol, newName, null, SourceType.USER_DEFINED);
                            anyRenamed = true;
                            logInfo("Renamed global variable " + oldName + " to " + newName);
                        }
                        catch (DuplicateNameException | InvalidInputException e) {
                            logError("Failed to rename global variable " + oldName + " to " + newName, e);
                        }
                    }
                }

                program.endTransaction(transactionId, true);
            }
            catch (Exception e) {
                logError("Error during variable renaming", e);
                return createErrorResult("Failed to rename variables: " + e.getMessage());
            }
            finally {
                decompiler.dispose();
            }

            if (!anyRenamed) {
                return createErrorResult("No matching variables found to rename");
            }

            // Now get the updated decompilation and create diff
            Map<String, Object> resultData = new HashMap<>();
            resultData.put("programName", program.getName());
            resultData.put("functionName", function.getName());
            resultData.put("address", "0x" + function.getEntryPoint().toString());
            resultData.put("variablesRenamed", true);

            // Get updated decompilation
            DecompInterface newDecompiler = new DecompInterface();
            newDecompiler.toggleCCode(true);
            newDecompiler.toggleSyntaxTree(true);
            newDecompiler.setSimplificationStyle("decompile");
            newDecompiler.openProgram(program);

            try {
                DecompileResults newResults = newDecompiler.decompileFunction(function, 0, TaskMonitor.DUMMY);
                if (newResults.decompileCompleted()) {
                    DecompiledFunction decompiledFunction = newResults.getDecompiledFunction();
                    String afterDecompilation = decompiledFunction.getC();

                    // Create diff showing only changed parts
                    DecompilationDiffUtil.DiffResult diff = DecompilationDiffUtil.createDiff(beforeDecompilation, afterDecompilation);
                    if (diff.hasChanges()) {
                        resultData.put("changes", DecompilationDiffUtil.toMap(diff));
                    } else {
                        resultData.put("changes", Map.of("hasChanges", false, "summary", "No changes detected in decompilation"));
                    }
                } else {
                    resultData.put("decompilationError", "Decompilation failed after renaming: " +
                        newResults.getErrorMessage());
                }
            }
            catch (Exception e) {
                logError("Error during final decompilation", e);
                resultData.put("decompilationError", "Exception during decompilation: " + e.getMessage());
            }
            finally {
                newDecompiler.dispose();
            }

            return createJsonResult(resultData);
        });
    }

    /**
     * Register a tool to change variable data types in a decompiled function
     * @throws McpError if there's an error registering the tool
     */
    private void registerChangeVariableDataTypesTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the function"
        ));
        properties.put("functionNameOrAddress", Map.of(
            "type", "string",
            "description", "Function name, address, or symbol to change variable data types in (e.g. 'main', '0x00401000', or 'start'). For addresses pointing inside a function, the containing function will be used."
        ));
        properties.put("datatypeMappings", Map.of(
            "type", "object",
            "description", "Mapping of variable names to new data type strings (e.g., 'char*', 'int[10]'). Only change the variables that need new data types.",
            "additionalProperties", Map.of("type", "string")
        ));
        properties.put("archiveName", Map.of(
            "type", "string",
            "description", "Optional name of the data type archive to search for data types. If not provided, all archives will be searched.",
            "default", ""
        ));

        List<String> required = List.of("programPath", "functionNameOrAddress", "datatypeMappings");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "change-variable-datatypes",
            "Change data types of variables in a decompiled function",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get arguments from the request
            String programPath = (String) args.get("programPath");
            String functionNameOrAddress = (String) args.get("functionNameOrAddress");
            @SuppressWarnings("unchecked")
            Map<String, String> mappings = (Map<String, String>) args.get("datatypeMappings");
            String archiveName = args.containsKey("archiveName") ?
                (String) args.get("archiveName") : "";

            // Validate arguments
            if (programPath == null) {
                return createErrorResult("No program path provided");
            }
            if (functionNameOrAddress == null) {
                return createErrorResult("No function name or address provided");
            }
            if (mappings == null || mappings.isEmpty()) {
                return createErrorResult("No datatype mappings provided");
            }

            // Get the program from the path
            Program program = RevaProgramManager.getProgramByPath(programPath);
            if (program == null) {
                return createErrorResult("Failed to find program: " + programPath);
            }

            Function function = null;

            // First try to resolve as address or symbol
            Address address = AddressUtil.resolveAddressOrSymbol(program, functionNameOrAddress);
            if (address != null) {
                // Get the containing function for this address
                function = AddressUtil.getContainingFunction(program, address);
            }

            // If not found by address, try by function name
            if (function == null) {
                FunctionManager functionManager = program.getFunctionManager();

                // First try an exact match
                FunctionIterator functions = functionManager.getFunctions(true);
                while (functions.hasNext()) {
                    Function f = functions.next();
                    if (f.getName().equals(functionNameOrAddress)) {
                        function = f;
                        break;
                    }
                }

                // If no exact match, try case-insensitive
                if (function == null) {
                    functions = functionManager.getFunctions(true);
                    while (functions.hasNext()) {
                        Function f = functions.next();
                        if (f.getName().equalsIgnoreCase(functionNameOrAddress)) {
                            function = f;
                            break;
                        }
                    }
                }
            }

            if (function == null) {
                return createErrorResult("Function not found: " + functionNameOrAddress + " in program " + program.getName() +
                    ". Tried as address/symbol and function name. Check you are not using the mangled name and the namespace is correct.");
            }

            // Validate that the LLM has read the decompilation for this function first
            String functionKey = programPath + ":" + function.getName();
            if (!hasReadDecompilation(functionKey)) {
                return createErrorResult("You must read the decompilation for function '" + function.getName() +
                    "' using get-decompilation tool before making datatype changes. This ensures you understand the current state of the code.");
            }

            // Initialize the decompiler
            DecompInterface decompiler = new DecompInterface();
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            decompiler.setSimplificationStyle("decompile");

            boolean decompInitialized = decompiler.openProgram(program);
            if (!decompInitialized) {
                return createErrorResult("Failed to initialize decompiler");
            }

            // Decompile the function to get the "before" state
            DecompileResults decompileResults = decompiler.decompileFunction(function, 0, TaskMonitor.DUMMY);
            if (!decompileResults.decompileCompleted()) {
                decompiler.dispose();
                return createErrorResult("Decompilation failed: " + decompileResults.getErrorMessage());
            }

            // Capture the original decompilation for diff comparison
            String beforeDecompilation = decompileResults.getDecompiledFunction().getC();

            // Track if we actually changed any data types
            boolean anyChanged = false;
            List<String> errors = new ArrayList<>();

            // Process variable mappings
            int transactionId = program.startTransaction("Change Variable Data Types");
            boolean transactionSuccess = false;
            try {
                // Get the high function from the decompile results
                HighFunction highFunction = decompileResults.getHighFunction();

                // Process local variables
                Iterator<HighSymbol> localVars = highFunction.getLocalSymbolMap().getSymbols();
                while (localVars.hasNext()) {
                    HighSymbol symbol = localVars.next();
                    String varName = symbol.getName();
                    String newDataTypeString = mappings.get(varName);

                    if (newDataTypeString != null) {
                        try {
                            // Parse the new data type string
                            DataType newDataType = DataTypeParserUtil.parseDataTypeObjectFromString(
                                newDataTypeString, archiveName);

                            if (newDataType == null) {
                                errors.add("Could not find data type: " + newDataTypeString + " for variable " + varName);
                                continue;
                            }

                            // Update the variable data type in the database using HighFunctionDBUtil
                            HighFunctionDBUtil.updateDBVariable(symbol, null, newDataType, SourceType.USER_DEFINED);
                            anyChanged = true;
                            logInfo("Changed data type of local variable " + varName + " to " + newDataTypeString);
                        }
                        catch (DuplicateNameException | InvalidInputException e) {
                            errors.add("Failed to change data type of local variable " + varName + " to " + newDataTypeString + ": " + e.getMessage());
                        }
                        catch (Exception e) {
                            errors.add("Error parsing data type " + newDataTypeString + " for variable " + varName + ": " + e.getMessage());
                        }
                    }
                }

                // Process global variables
                Iterator<HighSymbol> globalVars = highFunction.getGlobalSymbolMap().getSymbols();
                while (globalVars.hasNext()) {
                    HighSymbol symbol = globalVars.next();
                    String varName = symbol.getName();
                    String newDataTypeString = mappings.get(varName);

                    if (newDataTypeString != null) {
                        try {
                            // Parse the new data type string
                            DataType newDataType = DataTypeParserUtil.parseDataTypeObjectFromString(
                                newDataTypeString, archiveName);

                            if (newDataType == null) {
                                errors.add("Could not find data type: " + newDataTypeString + " for variable " + varName);
                                continue;
                            }

                            // Update the variable data type in the database using HighFunctionDBUtil
                            HighFunctionDBUtil.updateDBVariable(symbol, null, newDataType, SourceType.USER_DEFINED);
                            anyChanged = true;
                            logInfo("Changed data type of global variable " + varName + " to " + newDataTypeString);
                        }
                        catch (DuplicateNameException | InvalidInputException e) {
                            errors.add("Failed to change data type of global variable " + varName + " to " + newDataTypeString + ": " + e.getMessage());
                        }
                        catch (Exception e) {
                            errors.add("Error parsing data type " + newDataTypeString + " for variable " + varName + ": " + e.getMessage());
                        }
                    }
                }

                transactionSuccess = true;
            }
            catch (Exception e) {
                logError("Error during variable data type changes", e);
                return createErrorResult("Failed to change variable data types: " + e.getMessage());
            }
            finally {
                program.endTransaction(transactionId, transactionSuccess);
                decompiler.dispose();
            }

            if (!anyChanged && errors.isEmpty()) {
                return createErrorResult("No matching variables found to change data types");
            }

            // Now get the updated decompilation and create diff
            Map<String, Object> resultData = new HashMap<>();
            resultData.put("programName", program.getName());
            resultData.put("functionName", function.getName());
            resultData.put("address", "0x" + function.getEntryPoint().toString());
            resultData.put("dataTypesChanged", anyChanged);

            if (!errors.isEmpty()) {
                resultData.put("errors", errors);
            }

            // Get updated decompilation
            DecompInterface newDecompiler = new DecompInterface();
            newDecompiler.toggleCCode(true);
            newDecompiler.toggleSyntaxTree(true);
            newDecompiler.setSimplificationStyle("decompile");
            newDecompiler.openProgram(program);

            try {
                DecompileResults newResults = newDecompiler.decompileFunction(function, 0, TaskMonitor.DUMMY);
                if (newResults.decompileCompleted()) {
                    DecompiledFunction decompiledFunction = newResults.getDecompiledFunction();
                    String afterDecompilation = decompiledFunction.getC();

                    // Create diff showing only changed parts
                    DecompilationDiffUtil.DiffResult diff = DecompilationDiffUtil.createDiff(beforeDecompilation, afterDecompilation);
                    if (diff.hasChanges()) {
                        resultData.put("changes", DecompilationDiffUtil.toMap(diff));
                    } else {
                        resultData.put("changes", Map.of("hasChanges", false, "summary", "No changes detected in decompilation"));
                    }
                } else {
                    resultData.put("decompilationError", "Decompilation failed after changing data types: " +
                        newResults.getErrorMessage());
                }
            }
            catch (Exception e) {
                logError("Error during final decompilation", e);
                resultData.put("decompilationError", "Exception during decompilation: " + e.getMessage());
            }
            finally {
                newDecompiler.dispose();
            }

            return createJsonResult(resultData);
        });
    }

    /**
     * Get synchronized decompilation content with optional assembly listing
     * @param program The program
     * @param markup The Clang token markup from decompilation
     * @param fullDecompCode The full decompiled C code
     * @param offset Line number to start from (1-based)
     * @param limit Number of lines to return (null for all)
     * @param includeDisassembly Whether to include synchronized assembly
     * @return Map containing synchronized content
     */
    private Map<String, Object> getSynchronizedContent(Program program, ClangTokenGroup markup,
            String fullDecompCode, int offset, Integer limit, boolean includeDisassembly) {
        Map<String, Object> result = new HashMap<>();

        try {
            // Convert markup to lines
            List<ClangLine> clangLines = DecompilerUtils.toLines(markup);
            String[] decompLines = fullDecompCode.split("\n");

            // Calculate range
            int totalLines = decompLines.length;
            int startIdx = Math.max(0, offset - 1); // Convert to 0-based
            int endIdx = limit != null ? Math.min(totalLines, startIdx + limit) : totalLines;

            result.put("totalLines", totalLines);
            result.put("offset", offset);
            if (limit != null) {
                result.put("limit", limit);
            }

            if (includeDisassembly) {
                // Create synchronized content with assembly mapping
                List<Map<String, Object>> syncedLines = new ArrayList<>();

                for (int i = startIdx; i < endIdx; i++) {
                    Map<String, Object> lineInfo = new HashMap<>();
                    int lineNumber = i + 1;

                    // Add decompiled line
                    String decompLine = i < decompLines.length ? decompLines[i] : "";
                    lineInfo.put("lineNumber", lineNumber);
                    lineInfo.put("decompilation", decompLine);

                    // Find corresponding assembly instructions
                    List<String> assemblyLines = getAssemblyForDecompLine(program, clangLines, lineNumber);
                    lineInfo.put("assembly", assemblyLines);

                    syncedLines.add(lineInfo);
                }

                result.put("synchronizedContent", syncedLines);
            } else {
                // Just return ranged decompilation
                StringBuilder rangedDecomp = new StringBuilder();
                for (int i = startIdx; i < endIdx; i++) {
                    if (i < decompLines.length) {
                        rangedDecomp.append(String.format("%4d\t%s\n", i + 1, decompLines[i]));
                    }
                }
                result.put("decompilation", rangedDecomp.toString());
            }

        } catch (Exception e) {
            logError("Error creating synchronized content", e);
            // Fallback to simple line range
            result.put("decompilation", applyLineRange(fullDecompCode, offset, limit));
            result.put("totalLines", fullDecompCode.split("\n").length);
            result.put("offset", offset);
            if (limit != null) {
                result.put("limit", limit);
            }
        }

        return result;
    }

    /**
     * Get assembly instructions corresponding to a decompiled line
     * @param program The program
     * @param clangLines List of ClangLine objects
     * @param lineNumber The line number (1-based)
     * @return List of assembly instruction strings
     */
    private List<String> getAssemblyForDecompLine(Program program, List<ClangLine> clangLines, int lineNumber) {
        List<String> assemblyLines = new ArrayList<>();

        try {
            // Find the ClangLine for this line number
            ClangLine targetLine = null;
            for (ClangLine clangLine : clangLines) {
                if (clangLine.getLineNumber() == lineNumber) {
                    targetLine = clangLine;
                    break;
                }
            }

            if (targetLine != null) {
                // Get all tokens on this line
                List<ClangToken> tokens = targetLine.getAllTokens();

                // Find addresses associated with tokens on this line
                AddressSet lineAddresses = new AddressSet();
                for (ClangToken token : tokens) {
                    Address tokenAddr = token.getMinAddress();
                    if (tokenAddr != null) {
                        lineAddresses.add(tokenAddr);
                    }
                }

                // If no direct addresses, find closest address
                if (lineAddresses.isEmpty() && !tokens.isEmpty()) {
                    Address closestAddress = DecompilerUtils.getClosestAddress(program, tokens.get(0));
                    if (closestAddress != null) {
                        lineAddresses.add(closestAddress);
                    }
                }

                // Get assembly instructions for these addresses
                Listing listing = program.getListing();
                for (Address addr : lineAddresses.getAddresses(true)) {
                    Instruction instruction = listing.getInstructionAt(addr);
                    if (instruction != null) {
                        assemblyLines.add(String.format("0x%s: %s",
                            instruction.getAddress().toString(),
                            instruction.toString()));
                    }
                }
            }
        } catch (Exception e) {
            logError("Error mapping line to assembly", e);
        }

        return assemblyLines;
    }

    /**
     * Apply line range to text (Claude Code Read tool style)
     * @param text The full text
     * @param offset Line number to start from (1-based)
     * @param limit Number of lines to return (null for all)
     * @return Formatted text with line numbers
     */
    private String applyLineRange(String text, int offset, Integer limit) {
        String[] lines = text.split("\n");
        int startIdx = Math.max(0, offset - 1); // Convert to 0-based
        int endIdx = limit != null ? Math.min(lines.length, startIdx + limit) : lines.length;

        StringBuilder result = new StringBuilder();
        for (int i = startIdx; i < endIdx; i++) {
            if (i < lines.length) {
                result.append(String.format("%4d\t%s\n", i + 1, lines[i]));
            }
        }

        return result.toString();
    }

    /**
     * Search decompilation across all functions in a program
     * @param program The program to search
     * @param pattern Regular expression pattern
     * @param maxResults Maximum number of results
     * @param caseSensitive Whether search is case sensitive
     * @return List of search results
     */
    private List<Map<String, Object>> searchDecompilationInProgram(Program program, String pattern,
            int maxResults, boolean caseSensitive) {
        List<Map<String, Object>> results = new ArrayList<>();

        try {
            // Compile the regex pattern
            int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
            Pattern regex = Pattern.compile(pattern, flags);

            // Initialize decompiler
            DecompInterface decompiler = new DecompInterface();
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            decompiler.setSimplificationStyle("decompile");

            if (!decompiler.openProgram(program)) {
                return results; // Failed to initialize decompiler
            }

            try {
                // Iterate through all functions
                FunctionIterator functions = program.getFunctionManager().getFunctions(true);
                while (functions.hasNext() && results.size() < maxResults) {
                    Function function = functions.next();

                    // Skip external functions
                    if (function.isExternal()) {
                        continue;
                    }

                    try {
                        // Decompile the function
                        DecompileResults decompileResults = decompiler.decompileFunction(function, 0, TaskMonitor.DUMMY);

                        if (decompileResults.decompileCompleted()) {
                            DecompiledFunction decompiledFunction = decompileResults.getDecompiledFunction();
                            String decompCode = decompiledFunction.getC();

                            // Search each line
                            String[] lines = decompCode.split("\n");
                            for (int i = 0; i < lines.length && results.size() < maxResults; i++) {
                                String line = lines[i];
                                Matcher matcher = regex.matcher(line);

                                if (matcher.find()) {
                                    Map<String, Object> result = new HashMap<>();
                                    result.put("functionName", function.getName());
                                    result.put("functionAddress", "0x" + function.getEntryPoint().toString());
                                    result.put("lineNumber", i + 1);
                                    result.put("lineContent", line.trim());
                                    result.put("matchStart", matcher.start());
                                    result.put("matchEnd", matcher.end());
                                    result.put("matchedText", matcher.group());

                                    results.add(result);
                                }
                            }
                        }
                    } catch (Exception e) {
                        // Skip this function if decompilation fails
                        logError("Failed to decompile function: " + function.getName(), e);
                        continue;
                    }
                }
            } finally {
                decompiler.dispose();
            }

        } catch (PatternSyntaxException e) {
            logError("Invalid regex pattern: " + pattern, e);
        } catch (Exception e) {
            logError("Error during decompilation search", e);
        }

        return results;
    }

    /**
     * Check if the LLM has read the decompilation for a specific function
     * @param functionKey The function key (programPath:functionName)
     * @return true if decompilation has been read recently, false otherwise
     */
    private boolean hasReadDecompilation(String functionKey) {
        Long lastReadTime = readDecompilationTracker.get(functionKey);
        if (lastReadTime == null) {
            return false;
        }

        // Consider decompilation "read" if it was accessed within the last 30 minutes
        long thirtyMinutesAgo = System.currentTimeMillis() - (30 * 60 * 1000);
        return lastReadTime > thirtyMinutesAgo;
    }
}
