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
    public void testProgramPathAddsOptionalProperty() {
        JsonSchema schema = SchemaUtil.builder().programPath().build();
        Map<String, Object> props = schema.properties();
        assertTrue("programPath property present", props.containsKey("programPath"));
        assertFalse("programPath is optional: a missing one resolves to the only open program", schema.required().contains("programPath"));
    }

    @SuppressWarnings("unchecked")
    private static String programPathDescription(String description) {
        Map<String, Object> props = SchemaUtil.optionalProgramPath(
            Map.of("programPath", SchemaUtil.stringProperty(description)));
        return (String) ((Map<String, Object>) props.get("programPath")).get("description");
    }

    @Test
    public void optionalNoteGetsASentenceBreakAfterUnpunctuatedDescription() {
        assertEquals("Path to the program in the Ghidra Project. Optional when exactly one program is open.",
            programPathDescription("Path to the program in the Ghidra Project"));
    }

    @Test
    public void optionalNoteFollowsPunctuatedDescriptionWithASpace() {
        assertEquals("Path to the program. Optional when exactly one program is open.",
            programPathDescription("Path to the program."));
    }

    @Test
    public void optionalNoteAloneWhenDescriptionIsEmpty() {
        assertEquals("Optional when exactly one program is open.", programPathDescription(""));
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
