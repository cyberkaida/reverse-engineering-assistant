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
import static org.mockito.Mockito.*;

import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.options.ToolOptions;

/**
 * Test class for ConfigManager configuration change notifications
 */
public class ConfigChangeTest {

    @Mock
    private PluginTool mockTool;
    
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
        // Mock the options system
        ToolOptions mockOptions = mock(ToolOptions.class);
        when(mockTool.getOptions(anyString())).thenReturn(mockOptions);
        
        // Setup default return values for option getters
        when(mockOptions.getInt(eq(ConfigManager.SERVER_PORT), anyInt())).thenReturn(8080);
        when(mockOptions.getBoolean(eq(ConfigManager.SERVER_ENABLED), anyBoolean())).thenReturn(true);
        when(mockOptions.getBoolean(eq(ConfigManager.DEBUG_MODE), anyBoolean())).thenReturn(false);
        when(mockOptions.getInt(eq(ConfigManager.MAX_DECOMPILER_SEARCH_FUNCTIONS), anyInt())).thenReturn(1000);
        when(mockOptions.getInt(eq(ConfigManager.DECOMPILER_TIMEOUT_SECONDS), anyInt())).thenReturn(10);
    }

    @Test
    public void testConfigChangeListenerNotification() {
        // Reset the notification flag
        changeNotified.set(false);
        
        // Change the server port
        configManager.setServerPort(8955);
        
        // Verify the listener was notified
        assertTrue("Config change listener should be notified", changeNotified.get());
        assertEquals("Category should be server options", ConfigManager.SERVER_OPTIONS, lastChangedCategory);
        assertEquals("Changed option should be server port", ConfigManager.SERVER_PORT, lastChangedName);
        assertEquals("Old value should be 8080", 8080, lastOldValue);
        assertEquals("New value should be 8955", 8955, lastNewValue);
    }
    
    @Test
    public void testConfigChangeListenerNotNotifiedForSameValue() {
        // Set the port to the same value it already has
        configManager.setServerPort(8080);
        
        // Verify the listener was NOT notified since the value didn't change
        assertFalse("Config change listener should not be notified for same value", changeNotified.get());
    }
    
    @Test
    public void testServerEnabledConfigChange() {
        // Reset the notification flag
        changeNotified.set(false);
        
        // Change the server enabled setting
        configManager.setServerEnabled(false);
        
        // Verify the listener was notified
        assertTrue("Config change listener should be notified", changeNotified.get());
        assertEquals("Category should be server options", ConfigManager.SERVER_OPTIONS, lastChangedCategory);
        assertEquals("Changed option should be server enabled", ConfigManager.SERVER_ENABLED, lastChangedName);
        assertEquals("Old value should be true", true, lastOldValue);
        assertEquals("New value should be false", false, lastNewValue);
    }
    
    @Test
    public void testRemoveConfigChangeListener() {
        // Create a test listener
        ConfigChangeListener testListener = mock(ConfigChangeListener.class);
        
        // Add and then remove the listener
        configManager.addConfigChangeListener(testListener);
        configManager.removeConfigChangeListener(testListener);
        
        // Make a config change
        configManager.setServerPort(9000);
        
        // Verify the removed listener was not called
        verify(testListener, never()).onConfigChanged(anyString(), anyString(), any(), any());
    }
}