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

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
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
    protected void registerTool(Tool tool, java.util.function.BiFunction<io.modelcontextprotocol.server.McpSyncServerExchange, java.util.Map<String, Object>, McpSchema.CallToolResult> handler) throws McpError {
        SyncToolSpecification toolSpec = new SyncToolSpecification(tool, handler);
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
     * Get a required string parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @return The string value
     * @throws IllegalArgumentException if the parameter is missing or not a string
     */
    protected String getString(Map<String, Object> args, String key) {
        Object value = args.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Missing required parameter: " + key);
        }
        if (!(value instanceof String)) {
            throw new IllegalArgumentException("Parameter '" + key + "' must be a string");
        }
        return (String) value;
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
        if (!(value instanceof String)) {
            throw new IllegalArgumentException("Parameter '" + key + "' must be a string");
        }
        return (String) value;
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
        throw new IllegalArgumentException("Parameter '" + key + "' must be a number");
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
        throw new IllegalArgumentException("Parameter '" + key + "' must be a number");
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
        throw new IllegalArgumentException("Parameter '" + key + "' must be a boolean");
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
}
