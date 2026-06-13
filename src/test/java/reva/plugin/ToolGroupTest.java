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
package reva.plugin;

import static org.junit.Assert.*;

import org.junit.Test;

public class ToolGroupTest {

    @Test
    public void hasSixGroups() {
        assertEquals(6, ToolGroup.values().length);
    }

    @Test
    public void optionNameUsesPrefix() {
        assertEquals("Enable Tool Group: Core Analysis", ToolGroup.CORE_ANALYSIS.getOptionName());
        assertEquals("Enable Tool Group: Scripting", ToolGroup.SCRIPTING.getOptionName());
    }

    @Test
    public void fromOptionNameRoundTrips() {
        for (ToolGroup group : ToolGroup.values()) {
            assertEquals(group, ToolGroup.fromOptionName(group.getOptionName()));
        }
    }

    @Test
    public void fromOptionNameReturnsNullForUnknown() {
        assertNull(ToolGroup.fromOptionName("Server Port"));
        assertNull(ToolGroup.fromOptionName(null));
    }
}
