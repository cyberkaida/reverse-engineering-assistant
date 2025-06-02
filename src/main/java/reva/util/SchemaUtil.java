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
        return new McpSchema.JsonSchema("object", properties, required, false, null, null);
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
         * Build the schema
         * @return JsonSchema object
         */
        public McpSchema.JsonSchema build() {
            return SchemaUtil.createSchema(properties, required);
        }
    }
}
