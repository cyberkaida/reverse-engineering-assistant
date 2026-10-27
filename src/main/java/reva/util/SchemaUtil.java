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
package reva.util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.modelcontextprotocol.spec.McpSchema;

/**
 * Utility methods for creating MCP JSON schemas.
 */
public class SchemaUtil {
    /**
     * Create a string property schema
     * @param description Description of the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> stringProperty(String description) {
        return Map.of(
            "type", "string",
            "description", description
        );
    }

    /**
     * Create a string property schema (alias for consistency)
     * @param description Description of the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> createStringProperty(String description) {
        return stringProperty(description);
    }

    /**
     * Create a string property schema with a default value
     * @param description Description of the property
     * @param defaultValue Default value for the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> stringPropertyWithDefault(String description, String defaultValue) {
        return Map.of(
            "type", "string",
            "description", description,
            "default", defaultValue
        );
    }

    /**
     * Create an optional string property schema (alias)
     * @param description Description of the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> createOptionalStringProperty(String description) {
        return stringProperty(description);
    }

    /**
     * Create a boolean property schema
     * @param description Description of the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> booleanProperty(String description) {
        return Map.of(
            "type", "boolean",
            "description", description
        );
    }

    /**
     * Create an optional boolean property schema (alias)
     * @param description Description of the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> createOptionalBooleanProperty(String description) {
        return booleanProperty(description);
    }

    /**
     * Create a boolean property schema with a default value
     * @param description Description of the property
     * @param defaultValue Default value for the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> booleanPropertyWithDefault(String description, boolean defaultValue) {
        return Map.of(
            "type", "boolean",
            "description", description,
            "default", defaultValue
        );
    }

    /**
     * Create an integer property schema
     * @param description Description of the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> integerProperty(String description) {
        return Map.of(
            "type", "integer",
            "description", description
        );
    }

    /**
     * Create a number property schema
     * @param description Description of the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> createNumberProperty(String description) {
        return integerProperty(description);
    }

    /**
     * Create an optional number property schema
     * @param description Description of the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> createOptionalNumberProperty(String description) {
        return integerProperty(description);
    }

    /**
     * Create an integer property schema with a default value
     * @param description Description of the property
     * @param defaultValue Default value for the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> integerPropertyWithDefault(String description, int defaultValue) {
        return Map.of(
            "type", "integer",
            "description", description,
            "default", defaultValue
        );
    }

    /**
     * Create an object property schema
     * @param description Description of the property
     * @param properties Properties of the object
     * @return Map representation of the property schema
     */
    public static Map<String, Object> createOptionalObjectProperty(String description, Map<String, Object> properties) {
        Map<String, Object> schema = new HashMap<>();
        schema.put("type", "object");
        schema.put("description", description);
        schema.put("properties", properties);
        return schema;
    }

    /**
     * Create a JSON schema object
     * @param properties Map of property names to property schemas
     * @param required List of required property names
     * @return JsonSchema object
     */
    public static McpSchema.JsonSchema createSchema(Map<String, Object> properties, List<String> required) {
        return new McpSchema.JsonSchema("object", optionalProgramPath(properties), optionalRequired(required),
            false, null, null);
    }

    /** Sentence appended to every programPath description. */
    public static final String PROGRAM_PATH_OPTIONAL = "Optional when exactly one program is open.";

    /**
     * A missing programPath resolves to the only open program in the handlers, and the MCP
     * server validates required properties before a handler runs, so programPath is never
     * required in a schema.
     */
    public static List<String> optionalRequired(List<String> required) {
        if (required == null || !required.contains("programPath")) {
            return required;
        }
        List<String> out = new java.util.ArrayList<>(required);
        out.remove("programPath");
        return out;
    }

    /** Append {@link #PROGRAM_PATH_OPTIONAL} to the programPath property's description. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> optionalProgramPath(Map<String, Object> properties) {
        if (properties == null || !(properties.get("programPath") instanceof Map)) {
            return properties;
        }
        Map<String, Object> prop = new java.util.LinkedHashMap<>((Map<String, Object>) properties.get("programPath"));
        Object desc = prop.get("description");
        String text = desc == null ? "" : desc.toString();
        if (!text.contains(PROGRAM_PATH_OPTIONAL) && !text.startsWith("Optional")) {
            String sep = text.isEmpty() ? "" : endsWithPunctuation(text) ? " " : ". ";
            prop.put("description", text + sep + PROGRAM_PATH_OPTIONAL);
        }
        Map<String, Object> out = new java.util.LinkedHashMap<>(properties);
        out.put("programPath", prop);
        return out;
    }

    private static boolean endsWithPunctuation(String text) {
        String trimmed = text.stripTrailing();
        return !trimmed.isEmpty() && ".!?;:".indexOf(trimmed.charAt(trimmed.length() - 1)) >= 0;
    }

    /**
     * Create a schema builder to fluently build a schema
     * @return A new schema builder
     */
    public static SchemaBuilder builder() {
        return new SchemaBuilder();
    }

    /**
     * Builder class for creating schemas
     */
    public static class SchemaBuilder {
        private final Map<String, Object> properties = new HashMap<>();
        private final List<String> required = new java.util.ArrayList<>();

        private SchemaBuilder() {
            // Private constructor to force use of SchemaUtil.builder()
        }

        /**
         * Add a string property
         * @param name Property name
         * @param description Property description
         * @return This builder for method chaining
         */
        public SchemaBuilder stringProperty(String name, String description) {
            properties.put(name, SchemaUtil.stringProperty(description));
            return this;
        }

        /**
         * Add a string property with a default value
         * @param name Property name
         * @param description Property description
         * @param defaultValue Default value
         * @return This builder for method chaining
         */
        public SchemaBuilder stringProperty(String name, String description, String defaultValue) {
            properties.put(name, SchemaUtil.stringPropertyWithDefault(description, defaultValue));
            return this;
        }

        /**
         * Add a boolean property
         * @param name Property name
         * @param description Property description
         * @return This builder for method chaining
         */
        public SchemaBuilder booleanProperty(String name, String description) {
            properties.put(name, SchemaUtil.booleanProperty(description));
            return this;
        }

        /**
         * Add a boolean property with a default value
         * @param name Property name
         * @param description Property description
         * @param defaultValue Default value
         * @return This builder for method chaining
         */
        public SchemaBuilder booleanProperty(String name, String description, boolean defaultValue) {
            properties.put(name, SchemaUtil.booleanPropertyWithDefault(description, defaultValue));
            return this;
        }

        /**
         * Add an integer property
         * @param name Property name
         * @param description Property description
         * @return This builder for method chaining
         */
        public SchemaBuilder integerProperty(String name, String description) {
            properties.put(name, SchemaUtil.integerProperty(description));
            return this;
        }

        /**
         * Add an integer property with a default value
         * @param name Property name
         * @param description Property description
         * @param defaultValue Default value
         * @return This builder for method chaining
         */
        public SchemaBuilder integerProperty(String name, String description, int defaultValue) {
            properties.put(name, SchemaUtil.integerPropertyWithDefault(description, defaultValue));
            return this;
        }

        /**
         * Add a required property
         * @param name Property name
         * @return This builder for method chaining
         */
        public SchemaBuilder required(String name) {
            required.add(name);
            return this;
        }

        /**
         * Add the canonical programPath string property. It is NOT in the schema's required
     * list: the MCP layer validates required properties before the handler runs, and a
     * missing programPath resolves to the only open program in the handler.
         * @return This builder for method chaining
         */
        public SchemaBuilder programPath() {
            properties.put("programPath", SchemaUtil.stringProperty(
                "Path in the Ghidra Project to the program."));
            return this;
        }

        /**
         * Add the standard optional pagination parameters (startIndex and maxCount).
         * @param defaultMaxCount Default page size for maxCount
         * @return This builder for method chaining
         */
        public SchemaBuilder pagination(int defaultMaxCount) {
            properties.put("startIndex", SchemaUtil.integerPropertyWithDefault(
                "Starting index for pagination", 0));
            properties.put("maxCount", SchemaUtil.integerPropertyWithDefault(
                "Maximum number of results to return", defaultMaxCount));
            return this;
        }

        /**
         * Add a string property and mark it required in one call.
         * @param name Property name
         * @param description Property description
         * @return This builder for method chaining
         */
        public SchemaBuilder requiredStringProperty(String name, String description) {
            properties.put(name, SchemaUtil.stringProperty(description));
            required.add(name);
            return this;
        }

        /**
         * Build the schema
         * @return JsonSchema object
         */
        public McpSchema.JsonSchema build() {
            return SchemaUtil.createSchema(properties, required);
        }
    }
}
