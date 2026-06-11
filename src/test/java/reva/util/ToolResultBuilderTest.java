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

public class ToolResultBuilderTest {

    @Test
    public void testBuildsEnvelopeWithProgramPathAndData() {
        Map<String, Object> result = ToolResultBuilder.create("/bin/example")
            .success(true)
            .put("items", List.of("a", "b"))
            .build();
        assertEquals("/bin/example", result.get("programPath"));
        assertEquals(Boolean.TRUE, result.get("success"));
        assertEquals(List.of("a", "b"), result.get("items"));
    }

    @Test
    public void testSuccessDefaultsTrue() {
        Map<String, Object> result = ToolResultBuilder.create("/p").build();
        assertEquals(Boolean.TRUE, result.get("success"));
    }

    @Test
    public void testPutAllMergesFields() {
        Map<String, Object> result = ToolResultBuilder.create("/p")
            .putAll(Map.of("x", 1, "y", 2)).build();
        assertEquals(1, result.get("x"));
        assertEquals(2, result.get("y"));
    }
}
