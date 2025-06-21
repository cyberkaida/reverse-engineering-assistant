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
package reva.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import reva.util.AddressUtil;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import reva.plugin.RevaProgramManager;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.Content;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;

/**
 * Base implementation of the ToolProvider interface.
 * Provides common functionality for all tool providers.
 */
public abstract class AbstractToolProvider implements ToolProvider {
    protected static final ObjectMapper JSON = new ObjectMapper();
    protected final McpSyncServer server;
    protected final List<Tool> registeredTools = new ArrayList<>();

    /**
     * Constructor
     * @param server The MCP server to register tools with
     */
    public AbstractToolProvider(McpSyncServer server) {
        this.server = server;
    }

    @Override
    public void programOpened(Program program) {
        // Default implementation does nothing
    }

    @Override
    public void programClosed(Program program) {
        // Default implementation does nothing
    }

    @Override
    public void cleanup() {
        // Default implementation does nothing
    }

    /**
     * Create a JSON schema for a tool
     * @param properties The schema properties, with property name as key
     * @param required List of required property names
     * @return A JsonSchema object
     */
    protected JsonSchema createSchema(Map<String, Object> properties, List<String> required) {
        return new JsonSchema("object", properties, required, false, null, null);
    }

    /**
     * Helper method to create an error result
     * @param errorMessage The error message
     * @return CallToolResult with error flag set
     */
    protected McpSchema.CallToolResult createErrorResult(String errorMessage) {
        return new McpSchema.CallToolResult(
            List.of(new TextContent(errorMessage)),
            true
        );
    }

    /**
     * Helper method to create a success result with JSON content
     * @param data The data to serialize as JSON
     * @return CallToolResult with success flag set
     */
    protected McpSchema.CallToolResult createJsonResult(Object data) {
        try {
            return new McpSchema.CallToolResult(
                List.of(new TextContent(JSON.writeValueAsString(data))),
                false
            );
        } catch (JsonProcessingException e) {
            return createErrorResult("Error serializing result to JSON: " + e.getMessage());
        }
    }

    /**
     * Helper method to create a success result with multiple JSON contents
     * @param dataList List of objects to serialize as separate JSON contents
     * @return CallToolResult with success flag set
     */
    protected McpSchema.CallToolResult createMultiJsonResult(List<Object> dataList) {
        try {
            List<Content> contents = new ArrayList<>();
            for (Object data : dataList) {
                contents.add(new TextContent(JSON.writeValueAsString(data)));
            }
            return new McpSchema.CallToolResult(contents, false);
        } catch (JsonProcessingException e) {
            return createErrorResult("Error serializing results to JSON: " + e.getMessage());
        }
    }

    /**
     * Register a tool with the MCP server
     * @param tool The tool to register
     * @param handler The handler function for the tool
     * @throws McpError if there's an error registering the tool
     */
    protected void registerTool(Tool tool, java.util.function.BiFunction<io.modelcontextprotocol.server.McpSyncServerExchange, CallToolRequest, McpSchema.CallToolResult> handler) throws McpError {
        // Wrap the handler with safe execution
        java.util.function.BiFunction<io.modelcontextprotocol.server.McpSyncServerExchange, CallToolRequest, McpSchema.CallToolResult> safeHandler = 
            (exchange, request) -> {
                try {
                    return handler.apply(exchange, request);
                } catch (IllegalArgumentException e) {
                    return createErrorResult(e.getMessage());
                } catch (ProgramValidationException e) {
                    return createErrorResult(e.getMessage());
                } catch (Exception e) {
                    logError("Unexpected error in tool execution", e);
                    return createErrorResult("Tool execution failed: " + e.getMessage());
                }
            };
        
        SyncToolSpecification toolSpec = SyncToolSpecification.builder()
            .tool(tool)
            .callHandler(safeHandler)
            .build();
        server.addTool(toolSpec);
        registeredTools.add(tool);
        logInfo("Registered tool: " + tool.name());
    }

    /**
     * Log an error message
     * @param message The message to log
     */
    protected void logError(String message) {
        Msg.error(this, message);
    }

    /**
     * Log an error message with an exception
     * @param message The message to log
     * @param e The exception that caused the error
     */
    protected void logError(String message, Exception e) {
        Msg.error(this, message, e);
    }

    /**
     * Log an informational message
     * @param message The message to log
     */
    protected void logInfo(String message) {
        Msg.info(this, message);
    }

    /**
     * Get a required string parameter from CallToolRequest
     * @param request The CallToolRequest
     * @param key The parameter key
     * @return The string value
     * @throws IllegalArgumentException if the parameter is missing
     */
    protected String getString(CallToolRequest request, String key) {
        return getString(request.arguments(), key);
    }

    /**
     * Get a required string parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @return The string value
     * @throws IllegalArgumentException if the parameter is missing
     */
    protected String getString(Map<String, Object> args, String key) {
        Object value = args.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Missing required parameter: " + key);
        }
        // Convert non-string values to string for flexibility
        return value.toString();
    }

    /**
     * Get an optional string parameter from CallToolRequest
     * @param request The CallToolRequest
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The string value or default
     */
    protected String getOptionalString(CallToolRequest request, String key, String defaultValue) {
        return getOptionalString(request.arguments(), key, defaultValue);
    }

    /**
     * Get an optional string parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The string value or default
     */
    protected String getOptionalString(Map<String, Object> args, String key, String defaultValue) {
        Object value = args.get(key);
        if (value == null) {
            return defaultValue;
        }
        // Convert non-string values to string for flexibility
        return value.toString();
    }

    /**
     * Get a required integer parameter from CallToolRequest
     * @param request The CallToolRequest
     * @param key The parameter key
     * @return The integer value
     * @throws IllegalArgumentException if the parameter is missing or not a number
     */
    protected int getInt(CallToolRequest request, String key) {
        return getInt(request.arguments(), key);
    }

    /**
     * Get a required integer parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @return The integer value
     * @throws IllegalArgumentException if the parameter is missing or not a number
     */
    protected int getInt(Map<String, Object> args, String key) {
        Object value = args.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Missing required parameter: " + key);
        }
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        // Try to parse string representations of numbers
        if (value instanceof String) {
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Parameter '" + key + "' must be a number, got: " + value);
            }
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be a number");
    }

    /**
     * Get an optional integer parameter from CallToolRequest
     * @param request The CallToolRequest
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The integer value or default
     */
    protected int getOptionalInt(CallToolRequest request, String key, int defaultValue) {
        return getOptionalInt(request.arguments(), key, defaultValue);
    }

    /**
     * Get an optional integer parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The integer value or default
     */
    protected int getOptionalInt(Map<String, Object> args, String key, int defaultValue) {
        Object value = args.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        // Try to parse string representations of numbers
        if (value instanceof String) {
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Parameter '" + key + "' must be a number, got: " + value);
            }
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be a number");
    }

    /**
     * Get an optional integer parameter from arguments that can be null.
     * Unlike getOptionalInt(), this method can return null when the parameter is not provided
     * or when explicitly set to null, allowing distinction between "not provided" and "provided with default".
     * @param args The arguments map
     * @param key The parameter key
     * @param defaultValue The default value if not present (can be null)
     * @return The Integer value, default, or null
     */
    protected Integer getOptionalInteger(Map<String, Object> args, String key, Integer defaultValue) {
        Object value = args.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        // Try to parse string representations of numbers
        if (value instanceof String) {
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Parameter '" + key + "' must be a number, got: " + value);
            }
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be a number");
    }

    /**
     * Get a required boolean parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @return The boolean value
     * @throws IllegalArgumentException if the parameter is missing or not a valid boolean
     */
    protected boolean getBoolean(Map<String, Object> args, String key) {
        Object value = args.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Missing required parameter: " + key);
        }
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        // Handle string representations of booleans
        if (value instanceof String) {
            String strValue = ((String) value).toLowerCase();
            if ("true".equals(strValue)) {
                return true;
            } else if ("false".equals(strValue)) {
                return false;
            }
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be a boolean or 'true'/'false' string");
    }

    /**
     * Get an optional boolean parameter from CallToolRequest
     * @param request The CallToolRequest
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The boolean value or default
     */
    protected boolean getOptionalBoolean(CallToolRequest request, String key, boolean defaultValue) {
        return getOptionalBoolean(request.arguments(), key, defaultValue);
    }

    /**
     * Get an optional boolean parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The boolean value or default
     */
    protected boolean getOptionalBoolean(Map<String, Object> args, String key, boolean defaultValue) {
        Object value = args.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        // Handle string representations of booleans
        if (value instanceof String) {
            String strValue = ((String) value).toLowerCase();
            if ("true".equals(strValue)) {
                return true;
            } else if ("false".equals(strValue)) {
                return false;
            }
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be a boolean or 'true'/'false' string");
    }

    /**
     * Get an optional map parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The map value or default
     */
    @SuppressWarnings("unchecked")
    protected Map<String, Object> getOptionalMap(Map<String, Object> args, String key, Map<String, Object> defaultValue) {
        Object value = args.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Map) {
            return (Map<String, Object>) value;
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be an object");
    }

    /**
     * Get a required list parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @return The list value
     * @throws IllegalArgumentException if the parameter is missing or not a list
     */
    @SuppressWarnings("unchecked")
    protected List<String> getStringList(Map<String, Object> args, String key) {
        Object value = args.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Missing required parameter: " + key);
        }
        if (value instanceof List) {
            return (List<String>) value;
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be a list");
    }

    /**
     * Get an optional list parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The list value or default
     */
    @SuppressWarnings("unchecked")
    protected List<String> getOptionalStringList(Map<String, Object> args, String key, List<String> defaultValue) {
        Object value = args.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof List) {
            return (List<String>) value;
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be a list");
    }

    /**
     * Get an optional generic list parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The list value or default
     */
    @SuppressWarnings("unchecked")
    protected <T> List<T> getOptionalList(Map<String, Object> args, String key, List<T> defaultValue) {
        Object value = args.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof List) {
            return (List<T>) value;
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be a list");
    }

    /**
     * Get a required string map parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @return The map value
     * @throws IllegalArgumentException if the parameter is missing or not a map
     */
    @SuppressWarnings("unchecked")
    protected Map<String, String> getStringMap(Map<String, Object> args, String key) {
        Object value = args.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Missing required parameter: " + key);
        }
        if (value instanceof Map) {
            return (Map<String, String>) value;
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be an object");
    }

    /**
     * Get an optional string map parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The map value or default
     */
    @SuppressWarnings("unchecked")
    protected Map<String, String> getOptionalStringMap(Map<String, Object> args, String key, Map<String, String> defaultValue) {
        Object value = args.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Map) {
            return (Map<String, String>) value;
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be an object");
    }

    /**
     * Get a validated program by path. This method ensures the program exists and is in a valid state.
     * @param programPath The path to the program
     * @return A valid Program object
     * @throws ProgramValidationException if the program is not found, invalid, or in an invalid state
     */
    protected Program getValidatedProgram(String programPath) throws ProgramValidationException {
        if (programPath == null || programPath.trim().isEmpty()) {
            throw new ProgramValidationException("Program path cannot be null or empty");
        }

        Program program = RevaProgramManager.getProgramByPath(programPath);
        if (program == null) {
            throw new ProgramValidationException("Program not found: " + programPath);
        }

        if (program.isClosed()) {
            throw new ProgramValidationException("Program is closed: " + programPath);
        }

        return program;
    }

    /**
     * Get a validated program from MCP CallToolRequest. Handles parameter extraction and validation in one call.
     * @param request The CallToolRequest from MCP tool call
     * @return A valid Program object
     * @throws IllegalArgumentException if programPath parameter is missing or invalid
     * @throws ProgramValidationException if the program is not found, invalid, or in an invalid state
     */
    protected Program getProgramFromArgs(CallToolRequest request) throws IllegalArgumentException, ProgramValidationException {
        String programPath = getString(request, "programPath");
        return getValidatedProgram(programPath);
    }

    /**
     * Get a validated program from MCP arguments. Handles parameter extraction and validation in one call.
     * @param args The arguments map from MCP tool call
     * @return A valid Program object
     * @throws IllegalArgumentException if programPath parameter is missing or invalid
     * @throws ProgramValidationException if the program is not found, invalid, or in an invalid state
     */
    protected Program getProgramFromArgs(Map<String, Object> args) throws IllegalArgumentException, ProgramValidationException {
        String programPath = getString(args, "programPath");
        return getValidatedProgram(programPath);
    }


    /**
     * Simple record to hold pagination parameters
     */
    protected record PaginationParams(int startIndex, int maxCount) {}

    /**
     * Get pagination parameters from CallToolRequest with common defaults
     * @param request The CallToolRequest
     * @param defaultMaxCount Default maximum count (varies by tool type)
     * @return PaginationParams object
     */
    protected PaginationParams getPaginationParams(CallToolRequest request, int defaultMaxCount) {
        int startIndex = getOptionalInt(request, "startIndex", 0);
        int maxCount = getOptionalInt(request, "maxCount", defaultMaxCount);
        return new PaginationParams(startIndex, maxCount);
    }

    /**
     * Get pagination parameters from arguments with common defaults
     * @param args The arguments map
     * @param defaultMaxCount Default maximum count (varies by tool type)
     * @return PaginationParams object
     */
    protected PaginationParams getPaginationParams(Map<String, Object> args, int defaultMaxCount) {
        int startIndex = getOptionalInt(args, "startIndex", 0);
        int maxCount = getOptionalInt(args, "maxCount", defaultMaxCount);
        return new PaginationParams(startIndex, maxCount);
    }

    /**
     * Get pagination parameters from CallToolRequest with standard default (100)
     * @param request The CallToolRequest
     * @return PaginationParams object
     */
    protected PaginationParams getPaginationParams(CallToolRequest request) {
        return getPaginationParams(request, 100);
    }

    /**
     * Get pagination parameters from arguments with standard default (100)
     * @param args The arguments map
     * @return PaginationParams object
     */
    protected PaginationParams getPaginationParams(Map<String, Object> args) {
        return getPaginationParams(args, 100);
    }

    /**
     * Get and resolve an address from MCP CallToolRequest
     * @param request The CallToolRequest
     * @param program The program to resolve the address in
     * @param addressKey The key for the address parameter (usually "addressOrSymbol")
     * @return Resolved Address object
     * @throws IllegalArgumentException if address parameter is missing or address cannot be resolved
     */
    protected Address getAddressFromArgs(CallToolRequest request, Program program, String addressKey) throws IllegalArgumentException {
        return getAddressFromArgs(request.arguments(), program, addressKey);
    }

    /**
     * Get and resolve an address from MCP arguments
     * @param args The arguments map
     * @param program The program to resolve the address in
     * @param addressKey The key for the address parameter (usually "addressOrSymbol")
     * @return Resolved Address object
     * @throws IllegalArgumentException if address parameter is missing or address cannot be resolved
     */
    protected Address getAddressFromArgs(Map<String, Object> args, Program program, String addressKey) throws IllegalArgumentException {
        String addressString = getString(args, addressKey);
        Address address = AddressUtil.resolveAddressOrSymbol(program, addressString);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address or symbol: " + addressString);
        }
        return address;
    }

    /**
     * Get and resolve an address from MCP arguments using standard "address" key
     * @param args The arguments map
     * @param program The program to resolve the address in
     * @return Resolved Address object
     * @throws IllegalArgumentException if address parameter is missing or address cannot be resolved
     */
    protected Address getAddressFromArgs(Map<String, Object> args, Program program) throws IllegalArgumentException {
        return getAddressFromArgs(args, program, "address");
    }

    /**
     * Helper method to get a function from arguments by name or address
     * @param args The arguments map
     * @param program The program to search in
     * @param paramName The parameter name containing the function name or address
     * @return The resolved function
     * @throws IllegalArgumentException if the function cannot be found
     */
    protected Function getFunctionFromArgs(Map<String, Object> args, Program program, String paramName) throws IllegalArgumentException {
        String functionNameOrAddress = getString(args, paramName);
        if (functionNameOrAddress == null) {
            throw new IllegalArgumentException("No " + paramName + " provided");
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
            throw new IllegalArgumentException("Function not found: " + functionNameOrAddress);
        }

        return function;
    }

    /**
     * Helper method to get a function from arguments by name or address (using default parameter name)
     * @param args The arguments map
     * @param program The program to search in
     * @return The resolved function
     * @throws IllegalArgumentException if the function cannot be found
     */
    protected Function getFunctionFromArgs(Map<String, Object> args, Program program) throws IllegalArgumentException {
        return getFunctionFromArgs(args, program, "functionNameOrAddress");
    }

    /**
     * Helper method to resolve a symbol name to an address
     * @param args The arguments map
     * @param program The program to search in
     * @param paramName The parameter name containing the symbol name
     * @return The resolved address from the symbol
     * @throws IllegalArgumentException if the symbol cannot be found
     */
    protected Address getAddressFromSymbolArgs(Map<String, Object> args, Program program, String paramName) throws IllegalArgumentException {
        String symbolName = getString(args, paramName);
        if (symbolName == null) {
            throw new IllegalArgumentException("No " + paramName + " provided");
        }

        // Find the symbol
        SymbolTable symbolTable = program.getSymbolTable();
        List<Symbol> symbols = symbolTable.getLabelOrFunctionSymbols(symbolName, null);

        if (symbols.isEmpty()) {
            throw new IllegalArgumentException("Symbol not found: " + symbolName);
        }

        // Use the first matching symbol's address
        Symbol symbol = symbols.get(0);
        return symbol.getAddress();
    }

    /**
     * Helper method to resolve a symbol name to an address (using default parameter name)
     * @param args The arguments map
     * @param program The program to search in
     * @return The resolved address from the symbol
     * @throws IllegalArgumentException if the symbol cannot be found
     */
    protected Address getAddressFromSymbolArgs(Map<String, Object> args, Program program) throws IllegalArgumentException {
        return getAddressFromSymbolArgs(args, program, "symbolName");
    }
}
