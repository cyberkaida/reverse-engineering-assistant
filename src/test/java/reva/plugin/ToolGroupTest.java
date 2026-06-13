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

    @Test
    public void fromIdAcceptsFlexibleForms() {
        assertEquals(ToolGroup.SCRIPTING, ToolGroup.fromId("scripting"));
        assertEquals(ToolGroup.SCRIPTING, ToolGroup.fromId("SCRIPTING"));
        assertEquals(ToolGroup.ADVANCED_ANALYSIS, ToolGroup.fromId("advanced-analysis"));
        assertEquals(ToolGroup.ADVANCED_ANALYSIS, ToolGroup.fromId("advanced_analysis"));
        assertEquals(ToolGroup.CORE_ANALYSIS, ToolGroup.fromId("  Core Analysis  "));
        assertEquals(ToolGroup.DATA_AND_TYPES, ToolGroup.fromId("data-and-types"));
    }

    @Test
    public void fromIdReturnsNullForUnknownOrNull() {
        assertNull(ToolGroup.fromId("nope"));
        assertNull(ToolGroup.fromId(null));
        assertNull(ToolGroup.fromId(""));
    }

    @Test
    public void fromIdCanonicalIdRoundTripsForAllGroups() {
        for (ToolGroup group : ToolGroup.values()) {
            assertEquals(group, ToolGroup.fromId(group.canonicalId()));
        }
    }

    @Test
    public void canonicalIdIsLowercaseKebab() {
        assertEquals("core-analysis", ToolGroup.CORE_ANALYSIS.canonicalId());
        assertEquals("data-and-types", ToolGroup.DATA_AND_TYPES.canonicalId());
        assertEquals("scripting", ToolGroup.SCRIPTING.canonicalId());
    }
}
