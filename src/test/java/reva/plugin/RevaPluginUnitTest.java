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

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.plugintool.PluginInfo;

/**
 * Unit tests for RevaPlugin metadata and structure
 */
public class RevaPluginUnitTest {

    @Test
    public void testPluginAnnotation() {
        // Get the plugin info annotation
        PluginInfo info = RevaPlugin.class.getAnnotation(PluginInfo.class);

        assertNotNull("Plugin should have @PluginInfo annotation", info);
        assertEquals("Plugin status should be STABLE", PluginStatus.STABLE, info.status());
        assertEquals("Plugin package name should be ReVa", "ReVa", info.packageName());
        assertEquals("Plugin category should be ANALYSIS", PluginCategoryNames.ANALYSIS, info.category());
        assertEquals("Plugin short description should match",
            "Reverse Engineering Assistant (Tool)", info.shortDescription());
        assertEquals("Plugin description should match",
            "Tool-level ReVa plugin that connects to the application-level MCP server",
            info.description());
    }

    @Test
    public void testPluginInheritance() {
        // Verify the plugin extends the correct base class
        assertTrue("RevaPlugin should extend ProgramPlugin",
            ghidra.app.plugin.ProgramPlugin.class.isAssignableFrom(RevaPlugin.class));
    }

    @Test
    public void testPluginMethods() throws NoSuchMethodException {
        // Check for required method overrides
        assertNotNull("Should have init method",
            RevaPlugin.class.getDeclaredMethod("init"));

        assertNotNull("Should have cleanup method",
            RevaPlugin.class.getDeclaredMethod("cleanup"));

        assertNotNull("Should have programOpened method",
            RevaPlugin.class.getDeclaredMethod("programOpened", ghidra.program.model.listing.Program.class));

        assertNotNull("Should have programClosed method",
            RevaPlugin.class.getDeclaredMethod("programClosed", ghidra.program.model.listing.Program.class));
    }

    @Test
    public void testPluginFields() throws NoSuchFieldException {
        // Check for expected fields
        assertNotNull("Should have provider field",
            RevaPlugin.class.getDeclaredField("provider"));

        assertNotNull("Should have mcpService field",
            RevaPlugin.class.getDeclaredField("mcpService"));
    }
}