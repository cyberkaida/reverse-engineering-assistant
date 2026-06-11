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
import java.util.Map;
import org.junit.Test;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;

public class SchemaUtilBuilderTest {

    @Test
    public void testProgramPathAddsRequiredProperty() {
        JsonSchema schema = SchemaUtil.builder().programPath().build();
        Map<String, Object> props = schema.properties();
        assertTrue("programPath property present", props.containsKey("programPath"));
        assertTrue("programPath is required", schema.required().contains("programPath"));
    }

    @Test
    public void testPaginationAddsOptionalStartIndexAndMaxCount() {
        JsonSchema schema = SchemaUtil.builder().pagination(100).build();
        Map<String, Object> props = schema.properties();
        assertTrue(props.containsKey("startIndex"));
        assertTrue(props.containsKey("maxCount"));
        assertFalse("pagination params are optional", schema.required().contains("startIndex"));
        assertFalse(schema.required().contains("maxCount"));
    }

    @Test
    public void testRequiredStringPropertyAddsBoth() {
        JsonSchema schema = SchemaUtil.builder()
            .requiredStringProperty("name", "the name").build();
        Map<String, Object> props = schema.properties();
        assertTrue(props.containsKey("name"));
        assertTrue(schema.required().contains("name"));
    }
}
