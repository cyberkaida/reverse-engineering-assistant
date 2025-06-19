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

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.framework.options.Options;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.bean.opteditor.OptionsVetoException;

/**
 * Configuration manager for the ReVa plugin.
 * Uses Ghidra's official OptionsChangeListener to detect configuration changes
 * from both programmatic updates and the Ghidra options dialog.
 */
public class ConfigManager implements OptionsChangeListener {
    // Configuration option categories
    public static final String SERVER_OPTIONS = "ReVa Server Options";

    // Option names
    public static final String SERVER_PORT = "Server Port";
    public static final String SERVER_ENABLED = "Server Enabled";
    public static final String DEBUG_MODE = "Debug Mode";
    public static final String MAX_DECOMPILER_SEARCH_FUNCTIONS = "Max Decompiler Search Functions";
    public static final String DECOMPILER_TIMEOUT_SECONDS = "Decompiler Timeout Seconds";

    // Default values
    private static final int DEFAULT_PORT = 8080;
    private static final boolean DEFAULT_SERVER_ENABLED = true;
    private static final boolean DEFAULT_DEBUG_MODE = false;
    private static final int DEFAULT_MAX_DECOMPILER_SEARCH_FUNCTIONS = 1000;
    private static final int DEFAULT_DECOMPILER_TIMEOUT_SECONDS = 10;

    private final PluginTool tool;
    private final ToolOptions toolOptions;
    private final Map<String, Object> cachedOptions = new HashMap<>();
    private final Set<ConfigChangeListener> configChangeListeners = ConcurrentHashMap.newKeySet();

    /**
     * Constructor
     * @param tool The plugin tool to get/save options from
     */
    public ConfigManager(PluginTool tool) {
        this.tool = tool;
        this.toolOptions = tool.getOptions(SERVER_OPTIONS);
        
        // Register options with Ghidra
        registerOptionsWithGhidra();
        
        // Add ourselves as listener to Ghidra's option change system
        toolOptions.addOptionsChangeListener(this);
        
        // Load initial values
        loadOptions();
    }

    /**
     * Register all options with Ghidra's options system
     */
    private void registerOptionsWithGhidra() {
        HelpLocation help = new HelpLocation("ReVa", "Configuration");
        
        toolOptions.registerOption(SERVER_PORT, DEFAULT_PORT, help,
            "Port number for the ReVa MCP server");
        toolOptions.registerOption(SERVER_ENABLED, DEFAULT_SERVER_ENABLED, help,
            "Whether the ReVa MCP server is enabled");
        toolOptions.registerOption(DEBUG_MODE, DEFAULT_DEBUG_MODE, help,
            "Whether debug mode is enabled");
        toolOptions.registerOption(MAX_DECOMPILER_SEARCH_FUNCTIONS, DEFAULT_MAX_DECOMPILER_SEARCH_FUNCTIONS, help,
            "Maximum number of functions before discouraging decompiler search");
        toolOptions.registerOption(DECOMPILER_TIMEOUT_SECONDS, DEFAULT_DECOMPILER_TIMEOUT_SECONDS, help,
            "Timeout in seconds for decompiler operations");
    }

    /**
     * Load options from the tool options and cache them
     */
    protected void loadOptions() {
        // Cache the options
        cachedOptions.put(SERVER_PORT, toolOptions.getInt(SERVER_PORT, DEFAULT_PORT));
        cachedOptions.put(SERVER_ENABLED, toolOptions.getBoolean(SERVER_ENABLED, DEFAULT_SERVER_ENABLED));
        cachedOptions.put(DEBUG_MODE, toolOptions.getBoolean(DEBUG_MODE, DEFAULT_DEBUG_MODE));
        cachedOptions.put(MAX_DECOMPILER_SEARCH_FUNCTIONS,
            toolOptions.getInt(MAX_DECOMPILER_SEARCH_FUNCTIONS, DEFAULT_MAX_DECOMPILER_SEARCH_FUNCTIONS));
        cachedOptions.put(DECOMPILER_TIMEOUT_SECONDS,
            toolOptions.getInt(DECOMPILER_TIMEOUT_SECONDS, DEFAULT_DECOMPILER_TIMEOUT_SECONDS));

        Msg.debug(this, "Loaded ReVa configuration settings");
    }

    /**
     * Ghidra's official options change callback.
     * This gets called whenever options change through ANY method:
     * - Ghidra options dialog
     * - Programmatic calls to toolOptions.setXXX()
     */
    @Override
    public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue) 
            throws OptionsVetoException {
        
        Msg.debug(this, "Option changed: " + optionName + " from " + oldValue + " to " + newValue);
        
        // Update our cache
        cachedOptions.put(optionName, newValue);
        
        // Notify our custom listeners
        notifyConfigChangeListeners(SERVER_OPTIONS, optionName, oldValue, newValue);
    }
    
    /**
     * Add a configuration change listener
     * @param listener The listener to add
     */
    public void addConfigChangeListener(ConfigChangeListener listener) {
        configChangeListeners.add(listener);
        Msg.debug(this, "Added config change listener: " + listener.getClass().getSimpleName());
    }
    
    /**
     * Remove a configuration change listener
     * @param listener The listener to remove
     */
    public void removeConfigChangeListener(ConfigChangeListener listener) {
        configChangeListeners.remove(listener);
        Msg.debug(this, "Removed config change listener: " + listener.getClass().getSimpleName());
    }
    
    /**
     * Notify all registered listeners about a configuration change
     * @param category The category of the changed option
     * @param name The name of the changed option
     * @param oldValue The old value
     * @param newValue The new value
     */
    private void notifyConfigChangeListeners(String category, String name, Object oldValue, Object newValue) {
        for (ConfigChangeListener listener : configChangeListeners) {
            try {
                listener.onConfigChanged(category, name, oldValue, newValue);
            } catch (Exception e) {
                Msg.error(this, "Error notifying config change listener: " + listener.getClass().getSimpleName(), e);
            }
        }
    }

    /**
     * Get the server port
     * @return The configured server port
     */
    public int getServerPort() {
        return (Integer) cachedOptions.getOrDefault(SERVER_PORT, DEFAULT_PORT);
    }

    /**
     * Set the server port
     * @param port The port number to use
     */
    public void setServerPort(int port) {
        toolOptions.setInt(SERVER_PORT, port);
        // optionsChanged() will be called automatically
    }

    /**
     * Check if the server is enabled
     * @return True if the server is enabled
     */
    public boolean isServerEnabled() {
        return (Boolean) cachedOptions.getOrDefault(SERVER_ENABLED, DEFAULT_SERVER_ENABLED);
    }

    /**
     * Set whether the server is enabled
     * @param enabled True to enable the server
     */
    public void setServerEnabled(boolean enabled) {
        toolOptions.setBoolean(SERVER_ENABLED, enabled);
        // optionsChanged() will be called automatically
    }

    /**
     * Check if debug mode is enabled
     * @return True if debug mode is enabled
     */
    public boolean isDebugMode() {
        return (Boolean) cachedOptions.getOrDefault(DEBUG_MODE, DEFAULT_DEBUG_MODE);
    }

    /**
     * Set whether debug mode is enabled
     * @param enabled True to enable debug mode
     */
    public void setDebugMode(boolean enabled) {
        toolOptions.setBoolean(DEBUG_MODE, enabled);
        // optionsChanged() will be called automatically
    }

    /**
     * Get the maximum number of functions to search in the decompiler
     * @return The configured maximum number of functions
     */
    public int getMaxDecompilerSearchFunctions() {
        return (Integer) cachedOptions.getOrDefault(MAX_DECOMPILER_SEARCH_FUNCTIONS, DEFAULT_MAX_DECOMPILER_SEARCH_FUNCTIONS);
    }

    /**
     * Set the maximum number of functions to search in the decompiler
     * @param maxFunctions The maximum number of functions
     */
    public void setMaxDecompilerSearchFunctions(int maxFunctions) {
        toolOptions.setInt(MAX_DECOMPILER_SEARCH_FUNCTIONS, maxFunctions);
        // optionsChanged() will be called automatically
    }

    /**
     * Get the decompiler timeout in seconds
     * @return The configured timeout in seconds
     */
    public int getDecompilerTimeoutSeconds() {
        return (Integer) cachedOptions.getOrDefault(DECOMPILER_TIMEOUT_SECONDS, DEFAULT_DECOMPILER_TIMEOUT_SECONDS);
    }

    /**
     * Set the decompiler timeout in seconds
     * @param timeoutSeconds The timeout in seconds
     */
    public void setDecompilerTimeoutSeconds(int timeoutSeconds) {
        toolOptions.setInt(DECOMPILER_TIMEOUT_SECONDS, timeoutSeconds);
        // optionsChanged() will be called automatically
    }
    
    /**
     * Clean up when the plugin is disposed
     */
    public void dispose() {
        if (toolOptions != null) {
            toolOptions.removeOptionsChangeListener(this);
        }
    }
}
