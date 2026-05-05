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

import static org.junit.Assert.*;

import java.util.List;
import java.util.Map;

import org.junit.Test;

import io.modelcontextprotocol.spec.McpSchema;

/**
 * Unit tests for SchemaUtil – property builders, schema factory and the
 * fluent SchemaBuilder inner class.
 */
public class SchemaUtilTest {

    // ========== stringProperty ==========

    @Test
    public void testStringProperty_TypeIsString() {
        Map<String, Object> prop = SchemaUtil.stringProperty("A description");
        assertEquals("string", prop.get("type"));
    }

    @Test
    public void testStringProperty_DescriptionIsSet() {
        Map<String, Object> prop = SchemaUtil.stringProperty("My description");
        assertEquals("My description", prop.get("description"));
    }

    @Test
    public void testStringProperty_AliasCreateStringProperty() {
        Map<String, Object> via1 = SchemaUtil.stringProperty("desc");
        Map<String, Object> via2 = SchemaUtil.createStringProperty("desc");
        assertEquals(via1, via2);
    }

    @Test
    public void testStringProperty_AliasCreateOptionalStringProperty() {
        Map<String, Object> via1 = SchemaUtil.stringProperty("desc");
        Map<String, Object> via2 = SchemaUtil.createOptionalStringProperty("desc");
        assertEquals(via1, via2);
    }

    // ========== stringPropertyWithDefault ==========

    @Test
    public void testStringPropertyWithDefault_TypeAndDescription() {
        Map<String, Object> prop = SchemaUtil.stringPropertyWithDefault("desc", "default_val");
        assertEquals("string", prop.get("type"));
        assertEquals("desc", prop.get("description"));
    }

    @Test
    public void testStringPropertyWithDefault_DefaultValueIncluded() {
        Map<String, Object> prop = SchemaUtil.stringPropertyWithDefault("desc", "my_default");
        assertEquals("my_default", prop.get("default"));
    }

    @Test
    public void testStringPropertyWithDefault_EmptyDefault() {
        Map<String, Object> prop = SchemaUtil.stringPropertyWithDefault("desc", "");
        assertEquals("", prop.get("default"));
    }

    // ========== booleanProperty ==========

    @Test
    public void testBooleanProperty_TypeIsBoolean() {
        Map<String, Object> prop = SchemaUtil.booleanProperty("enable feature");
        assertEquals("boolean", prop.get("type"));
    }

    @Test
    public void testBooleanProperty_DescriptionIsSet() {
        Map<String, Object> prop = SchemaUtil.booleanProperty("enable feature");
        assertEquals("enable feature", prop.get("description"));
    }

    @Test
    public void testBooleanProperty_AliasCreateOptionalBooleanProperty() {
        Map<String, Object> via1 = SchemaUtil.booleanProperty("desc");
        Map<String, Object> via2 = SchemaUtil.createOptionalBooleanProperty("desc");
        assertEquals(via1, via2);
    }

    // ========== booleanPropertyWithDefault ==========

    @Test
    public void testBooleanPropertyWithDefault_TrueDefault() {
        Map<String, Object> prop = SchemaUtil.booleanPropertyWithDefault("desc", true);
        assertEquals(true, prop.get("default"));
        assertEquals("boolean", prop.get("type"));
    }

    @Test
    public void testBooleanPropertyWithDefault_FalseDefault() {
        Map<String, Object> prop = SchemaUtil.booleanPropertyWithDefault("desc", false);
        assertEquals(false, prop.get("default"));
    }

    // ========== integerProperty ==========

    @Test
    public void testIntegerProperty_TypeIsInteger() {
        Map<String, Object> prop = SchemaUtil.integerProperty("a count");
        assertEquals("integer", prop.get("type"));
    }

    @Test
    public void testIntegerProperty_DescriptionIsSet() {
        Map<String, Object> prop = SchemaUtil.integerProperty("a count");
        assertEquals("a count", prop.get("description"));
    }

    @Test
    public void testIntegerProperty_AliasCreateNumberProperty() {
        Map<String, Object> via1 = SchemaUtil.integerProperty("desc");
        Map<String, Object> via2 = SchemaUtil.createNumberProperty("desc");
        assertEquals(via1, via2);
    }

    @Test
    public void testIntegerProperty_AliasCreateOptionalNumberProperty() {
        Map<String, Object> via1 = SchemaUtil.integerProperty("desc");
        Map<String, Object> via2 = SchemaUtil.createOptionalNumberProperty("desc");
        assertEquals(via1, via2);
    }

    // ========== integerPropertyWithDefault ==========

    @Test
    public void testIntegerPropertyWithDefault_TypeAndDescription() {
        Map<String, Object> prop = SchemaUtil.integerPropertyWithDefault("page size", 50);
        assertEquals("integer", prop.get("type"));
        assertEquals("page size", prop.get("description"));
    }

    @Test
    public void testIntegerPropertyWithDefault_DefaultValueIncluded() {
        Map<String, Object> prop = SchemaUtil.integerPropertyWithDefault("page size", 50);
        assertEquals(50, prop.get("default"));
    }

    @Test
    public void testIntegerPropertyWithDefault_ZeroDefault() {
        Map<String, Object> prop = SchemaUtil.integerPropertyWithDefault("offset", 0);
        assertEquals(0, prop.get("default"));
    }

    @Test
    public void testIntegerPropertyWithDefault_NegativeDefault() {
        Map<String, Object> prop = SchemaUtil.integerPropertyWithDefault("sentinel", -1);
        assertEquals(-1, prop.get("default"));
    }

    // ========== createOptionalObjectProperty ==========

    @Test
    public void testCreateOptionalObjectProperty_TypeIsObject() {
        Map<String, Object> inner = Map.of("name", SchemaUtil.stringProperty("item name"));
        Map<String, Object> prop = SchemaUtil.createOptionalObjectProperty("wrapper", inner);
        assertEquals("object", prop.get("type"));
    }

    @Test
    public void testCreateOptionalObjectProperty_DescriptionAndProperties() {
        Map<String, Object> inner = Map.of("key", SchemaUtil.stringProperty("a key"));
        Map<String, Object> prop = SchemaUtil.createOptionalObjectProperty("my object", inner);
        assertEquals("my object", prop.get("description"));
        assertEquals(inner, prop.get("properties"));
    }

    // ========== createSchema ==========

    @Test
    public void testCreateSchema_NotNull() {
        Map<String, Object> props = Map.of("field", SchemaUtil.stringProperty("a field"));
        List<String> required = List.of("field");
        McpSchema.JsonSchema schema = SchemaUtil.createSchema(props, required);
        assertNotNull(schema);
    }

    @Test
    public void testCreateSchema_TypeIsObject() {
        McpSchema.JsonSchema schema = SchemaUtil.createSchema(Map.of(), List.of());
        assertEquals("object", schema.type());
    }

    @Test
    public void testCreateSchema_RequiredListPreserved() {
        Map<String, Object> props = Map.of(
            "a", SchemaUtil.stringProperty("field a"),
            "b", SchemaUtil.stringProperty("field b")
        );
        List<String> required = List.of("a");
        McpSchema.JsonSchema schema = SchemaUtil.createSchema(props, required);
        assertNotNull(schema.required());
        assertTrue(schema.required().contains("a"));
        assertFalse(schema.required().contains("b"));
    }

    @Test
    public void testCreateSchema_PropertiesPreserved() {
        Map<String, Object> props = Map.of("myField", SchemaUtil.stringProperty("test"));
        McpSchema.JsonSchema schema = SchemaUtil.createSchema(props, List.of());
        assertNotNull(schema.properties());
        assertTrue(schema.properties().containsKey("myField"));
    }

    // ========== SchemaBuilder ==========

    @Test
    public void testSchemaBuilder_EmptySchema() {
        McpSchema.JsonSchema schema = SchemaUtil.builder().build();
        assertNotNull(schema);
        assertEquals("object", schema.type());
    }

    @Test
    public void testSchemaBuilder_AddStringProperty() {
        McpSchema.JsonSchema schema = SchemaUtil.builder()
            .stringProperty("name", "The name")
            .build();
        assertNotNull(schema.properties());
        assertTrue(schema.properties().containsKey("name"));
        @SuppressWarnings("unchecked")
        Map<String, Object> prop = (Map<String, Object>) schema.properties().get("name");
        assertEquals("string", prop.get("type"));
        assertEquals("The name", prop.get("description"));
    }

    @Test
    public void testSchemaBuilder_AddStringPropertyWithDefault() {
        McpSchema.JsonSchema schema = SchemaUtil.builder()
            .stringProperty("language", "Language code", "en")
            .build();
        @SuppressWarnings("unchecked")
        Map<String, Object> prop = (Map<String, Object>) schema.properties().get("language");
        assertEquals("en", prop.get("default"));
    }

    @Test
    public void testSchemaBuilder_AddBooleanProperty() {
        McpSchema.JsonSchema schema = SchemaUtil.builder()
            .booleanProperty("includeDetails", "Include extra details")
            .build();
        assertTrue(schema.properties().containsKey("includeDetails"));
        @SuppressWarnings("unchecked")
        Map<String, Object> prop = (Map<String, Object>) schema.properties().get("includeDetails");
        assertEquals("boolean", prop.get("type"));
    }

    @Test
    public void testSchemaBuilder_AddBooleanPropertyWithDefault() {
        McpSchema.JsonSchema schema = SchemaUtil.builder()
            .booleanProperty("verbose", "Enable verbose", true)
            .build();
        @SuppressWarnings("unchecked")
        Map<String, Object> prop = (Map<String, Object>) schema.properties().get("verbose");
        assertEquals(true, prop.get("default"));
    }

    @Test
    public void testSchemaBuilder_AddIntegerProperty() {
        McpSchema.JsonSchema schema = SchemaUtil.builder()
            .integerProperty("limit", "Max results")
            .build();
        assertTrue(schema.properties().containsKey("limit"));
        @SuppressWarnings("unchecked")
        Map<String, Object> prop = (Map<String, Object>) schema.properties().get("limit");
        assertEquals("integer", prop.get("type"));
    }

    @Test
    public void testSchemaBuilder_AddIntegerPropertyWithDefault() {
        McpSchema.JsonSchema schema = SchemaUtil.builder()
            .integerProperty("pageSize", "Page size", 100)
            .build();
        @SuppressWarnings("unchecked")
        Map<String, Object> prop = (Map<String, Object>) schema.properties().get("pageSize");
        assertEquals(100, prop.get("default"));
    }

    @Test
    public void testSchemaBuilder_AddRequired() {
        McpSchema.JsonSchema schema = SchemaUtil.builder()
            .stringProperty("programPath", "Program path")
            .required("programPath")
            .build();
        assertNotNull(schema.required());
        assertTrue(schema.required().contains("programPath"));
    }

    @Test
    public void testSchemaBuilder_MultipleRequiredFields() {
        McpSchema.JsonSchema schema = SchemaUtil.builder()
            .stringProperty("programPath", "Program path")
            .stringProperty("functionName", "Function name")
            .required("programPath")
            .required("functionName")
            .build();
        assertTrue(schema.required().contains("programPath"));
        assertTrue(schema.required().contains("functionName"));
    }

    @Test
    public void testSchemaBuilder_OptionalFieldNotInRequired() {
        McpSchema.JsonSchema schema = SchemaUtil.builder()
            .stringProperty("required_field", "Must provide")
            .stringProperty("optional_field", "Optional")
            .required("required_field")
            .build();
        assertTrue(schema.required().contains("required_field"));
        assertFalse("Optional field should not be in required list",
            schema.required().contains("optional_field"));
    }

    @Test
    public void testSchemaBuilder_FluentChaining_ReturnsBuilder() {
        // Ensure each builder method returns the same builder (fluent API)
        SchemaUtil.SchemaBuilder builder = SchemaUtil.builder();
        SchemaUtil.SchemaBuilder b2 = builder.stringProperty("a", "desc");
        assertSame("stringProperty should return same builder", builder, b2);
        SchemaUtil.SchemaBuilder b3 = builder.booleanProperty("b", "desc");
        assertSame("booleanProperty should return same builder", builder, b3);
        SchemaUtil.SchemaBuilder b4 = builder.integerProperty("c", "desc");
        assertSame("integerProperty should return same builder", builder, b4);
        SchemaUtil.SchemaBuilder b5 = builder.required("a");
        assertSame("required should return same builder", builder, b5);
    }

    @Test
    public void testSchemaBuilder_MixedProperties() {
        McpSchema.JsonSchema schema = SchemaUtil.builder()
            .stringProperty("programPath", "Path to the program")
            .stringProperty("functionName", "Function name")
            .booleanProperty("includeContext", "Include context")
            .integerProperty("maxResults", "Max results", 50)
            .required("programPath")
            .required("functionName")
            .build();

        assertNotNull(schema);
        assertEquals(4, schema.properties().size());
        assertTrue(schema.required().contains("programPath"));
        assertTrue(schema.required().contains("functionName"));
        assertFalse(schema.required().contains("includeContext"));
        assertFalse(schema.required().contains("maxResults"));
    }
}
