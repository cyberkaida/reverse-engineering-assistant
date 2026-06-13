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
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.util.HelpLocation;
import ghidra.util.bean.opteditor.OptionsVetoException;
import reva.plugin.config.ToolOptionsBackend;

/**
 * Test class for ConfigManager configuration change notifications
 */
public class ConfigChangeTest {

    @Mock
    private PluginTool mockTool;
    
    @Mock
    private ToolOptions mockToolOptions;

    @Mock
    private ToolOptions mockGroupOptions;

    private ConfigManager configManager;
    private AtomicBoolean changeNotified;
    private String lastChangedCategory;
    private String lastChangedName;
    private Object lastOldValue;
    private Object lastNewValue;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        
        // Initialize the mock tool with options
        setupMockTool();
        
        configManager = new ConfigManager(mockTool);
        changeNotified = new AtomicBoolean(false);
        
        // Add a test listener
        configManager.addConfigChangeListener(new ConfigChangeListener() {
            @Override
            public void onConfigChanged(String category, String name, Object oldValue, Object newValue) {
                changeNotified.set(true);
                lastChangedCategory = category;
                lastChangedName = name;
                lastOldValue = oldValue;
                lastNewValue = newValue;
            }
        });
    }
    
    private void setupMockTool() {
        // The "ReVa Server Options" and "ReVa Tool Groups" pages each get their OWN ToolOptions
        // mock, with getName() returning the real category. ToolOptionsBackend.optionsChanged()
        // uses options.getName() as the category, so using distinct mocks ensures tool-group
        // changes are reported under TOOL_GROUP_OPTIONS — a shared mock would mask routing bugs.
        when(mockTool.getOptions(eq(ConfigManager.SERVER_OPTIONS))).thenReturn(mockToolOptions);
        when(mockTool.getOptions(eq(ConfigManager.TOOL_GROUP_OPTIONS))).thenReturn(mockGroupOptions);
        when(mockToolOptions.getName()).thenReturn(ConfigManager.SERVER_OPTIONS);
        when(mockGroupOptions.getName()).thenReturn(ConfigManager.TOOL_GROUP_OPTIONS);

        // Server-option defaults (server page). No broad getBoolean stub here, so these
        // specific stubs are never overridden.
        when(mockToolOptions.getInt(eq(ConfigManager.SERVER_PORT), anyInt())).thenReturn(8080);
        when(mockToolOptions.getString(eq(ConfigManager.SERVER_HOST), anyString())).thenReturn("127.0.0.1");
        when(mockToolOptions.getBoolean(eq(ConfigManager.SERVER_ENABLED), anyBoolean())).thenReturn(true);
        when(mockToolOptions.getBoolean(eq(ConfigManager.API_KEY_ENABLED), anyBoolean())).thenReturn(false);
        when(mockToolOptions.getString(eq(ConfigManager.API_KEY), anyString())).thenReturn("");
        when(mockToolOptions.getBoolean(eq(ConfigManager.DEBUG_MODE), anyBoolean())).thenReturn(false);
        when(mockToolOptions.getInt(eq(ConfigManager.MAX_DECOMPILER_SEARCH_FUNCTIONS), anyInt())).thenReturn(1000);
        when(mockToolOptions.getInt(eq(ConfigManager.DECOMPILER_TIMEOUT_SECONDS), anyInt())).thenReturn(10);

        // Tool-group options default to enabled — broad stub scoped to the tool-group page ONLY.
        when(mockGroupOptions.getBoolean(anyString(), anyBoolean())).thenAnswer(inv -> inv.getArgument(1));
    }

    @Test
    public void testConfigChangeListenerNotification() throws Exception {
        // Reset the notification flag
        changeNotified.set(false);

        // Change the server port - this should call toolOptions.setInt()
        configManager.setServerPort(8955);

        // Manually trigger the optionsChanged callback since we're using mocks
        // Get the backend and trigger the Ghidra callback
        ToolOptionsBackend backend = (ToolOptionsBackend) configManager.getBackend();
        backend.optionsChanged(mockToolOptions, ConfigManager.SERVER_PORT, 8080, 8955);

        // Verify the listener was notified
        assertTrue("Config change listener should be notified", changeNotified.get());
        assertEquals("Category should be server options", ConfigManager.SERVER_OPTIONS, lastChangedCategory);
        assertEquals("Changed option should be server port", ConfigManager.SERVER_PORT, lastChangedName);
        assertEquals("Old value should be 8080", 8080, lastOldValue);
        assertEquals("New value should be 8955", 8955, lastNewValue);
    }
    
    @Test
    public void testConfigChangeListenerNotNotifiedForSameValue() throws Exception {
        // Reset the notification flag
        changeNotified.set(false);

        // Set the port to the same value it already has
        configManager.setServerPort(8080);

        // Manually trigger optionsChanged with same values (simulating Ghidra's behavior)
        // Note: Ghidra might still call optionsChanged even if values are the same
        ToolOptionsBackend backend = (ToolOptionsBackend) configManager.getBackend();
        backend.optionsChanged(mockToolOptions, ConfigManager.SERVER_PORT, 8080, 8080);

        // In this case, our listener should still be notified since Ghidra called optionsChanged
        // The "same value" optimization would happen at Ghidra's level, not ours
        assertTrue("Config change listener should be notified when Ghidra calls optionsChanged", changeNotified.get());
        assertEquals("Values should be the same", lastOldValue, lastNewValue);
    }
    
    @Test
    public void testServerEnabledConfigChange() throws Exception {
        // Reset the notification flag
        changeNotified.set(false);

        // Change the server enabled setting
        configManager.setServerEnabled(false);

        // Manually trigger the optionsChanged callback
        ToolOptionsBackend backend = (ToolOptionsBackend) configManager.getBackend();
        backend.optionsChanged(mockToolOptions, ConfigManager.SERVER_ENABLED, true, false);

        // Verify the listener was notified
        assertTrue("Config change listener should be notified", changeNotified.get());
        assertEquals("Category should be server options", ConfigManager.SERVER_OPTIONS, lastChangedCategory);
        assertEquals("Changed option should be server enabled", ConfigManager.SERVER_ENABLED, lastChangedName);
        assertEquals("Old value should be true", true, lastOldValue);
        assertEquals("New value should be false", false, lastNewValue);
    }
    
    @Test
    public void testToolGroupChangeReportsToolGroupCategory() throws Exception {
        // A change on the "ReVa Tool Groups" page must be reported to listeners under the
        // TOOL_GROUP_OPTIONS category (not SERVER_OPTIONS) so McpServerManager routes it as a
        // tool-group toggle. This guards the category-routing the separate page depends on.
        changeNotified.set(false);

        ToolOptionsBackend backend = (ToolOptionsBackend) configManager.getBackend();
        backend.optionsChanged(mockGroupOptions, ToolGroup.SCRIPTING.getDisplayName(), true, false);

        assertTrue("Config change listener should be notified", changeNotified.get());
        assertEquals("Tool-group changes must carry the tool-group category",
            ConfigManager.TOOL_GROUP_OPTIONS, lastChangedCategory);
        assertEquals("Changed option should be the group display name",
            ToolGroup.SCRIPTING.getDisplayName(), lastChangedName);
    }

    @Test
    public void testRemoveConfigChangeListener() throws Exception {
        // Create a test listener
        ConfigChangeListener testListener = mock(ConfigChangeListener.class);

        // Add and then remove the listener
        configManager.addConfigChangeListener(testListener);
        configManager.removeConfigChangeListener(testListener);

        // Make a config change and trigger the callback
        configManager.setServerPort(9000);
        ToolOptionsBackend backend = (ToolOptionsBackend) configManager.getBackend();
        backend.optionsChanged(mockToolOptions, ConfigManager.SERVER_PORT, 8080, 9000);

        // Verify the removed listener was not called
        verify(testListener, never()).onConfigChanged(anyString(), anyString(), any(), any());
    }
}