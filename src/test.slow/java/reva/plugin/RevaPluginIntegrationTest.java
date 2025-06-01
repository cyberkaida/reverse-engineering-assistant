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

import ghidra.program.model.listing.Program;
import reva.RevaIntegrationTestBase;
import reva.util.RevaInternalServiceRegistry;

/**
 * Integration tests for the RevaPlugin
 */
public class RevaPluginIntegrationTest extends RevaIntegrationTestBase {

    @Test
    public void testPluginLoadsSuccessfully() {
        assertNotNull("Plugin should be loaded", plugin);
        assertEquals("Plugin should have correct name", "RevaPlugin", plugin.getName());
    }

    @Test
    public void testPluginRegistersInServiceRegistry() {
        RevaPlugin registeredPlugin = RevaInternalServiceRegistry.getService(RevaPlugin.class);
        assertNotNull("Plugin should be registered in service registry", registeredPlugin);
        assertEquals("Registered plugin should be the same instance", plugin, registeredPlugin);
    }

    @Test
    public void testProgramCreation() {
        assertNotNull("Test program should be created", program);
        assertNotNull("Program memory should exist", program.getMemory());
        assertTrue("Program should have memory blocks", program.getMemory().getBlocks().length > 0);
    }
}