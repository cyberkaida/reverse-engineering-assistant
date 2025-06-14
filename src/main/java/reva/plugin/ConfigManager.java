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
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

/**
 * Configuration manager for the ReVa plugin.
 * Handles saving and loading configuration settings.
 */
public class ConfigManager {
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
    private final Map<String, Object> cachedOptions = new HashMap<>();
    private final Set<ConfigChangeListener> configChangeListeners = ConcurrentHashMap.newKeySet();

    /**
     * Constructor
     * @param tool The plugin tool to get/save options from
     */
    public ConfigManager(PluginTool tool) {
        this.tool = tool;
        loadOptions();
    }

    /**
     * Load options from the tool options
     */
    protected void loadOptions() {
        Options options = tool.getOptions(SERVER_OPTIONS);

        // Register options with default values if they don't exist
        options.registerOption(SERVER_PORT, DEFAULT_PORT, null,
            "Port number for the ReVa MCP server");
        options.registerOption(SERVER_ENABLED, DEFAULT_SERVER_ENABLED, null,
            "Whether the ReVa MCP server is enabled");
        options.registerOption(DEBUG_MODE, DEFAULT_DEBUG_MODE, null,
            "Whether debug mode is enabled");
        options.registerOption(MAX_DECOMPILER_SEARCH_FUNCTIONS, DEFAULT_MAX_DECOMPILER_SEARCH_FUNCTIONS, null,
            "Maximum number of functions before discouraging decompiler search");
        options.registerOption(DECOMPILER_TIMEOUT_SECONDS, DEFAULT_DECOMPILER_TIMEOUT_SECONDS, null,
            "Timeout in seconds for decompiler operations");

        // Cache the options
        cachedOptions.put(SERVER_PORT, options.getInt(SERVER_PORT, DEFAULT_PORT));
        cachedOptions.put(SERVER_ENABLED, options.getBoolean(SERVER_ENABLED, DEFAULT_SERVER_ENABLED));
        cachedOptions.put(DEBUG_MODE, options.getBoolean(DEBUG_MODE, DEFAULT_DEBUG_MODE));
        cachedOptions.put(MAX_DECOMPILER_SEARCH_FUNCTIONS,
            options.getInt(MAX_DECOMPILER_SEARCH_FUNCTIONS, DEFAULT_MAX_DECOMPILER_SEARCH_FUNCTIONS));
        cachedOptions.put(DECOMPILER_TIMEOUT_SECONDS,
            options.getInt(DECOMPILER_TIMEOUT_SECONDS, DEFAULT_DECOMPILER_TIMEOUT_SECONDS));

        Msg.debug(this, "Loaded ReVa configuration settings");
    }

    /**
     * Save an option value
     * @param category Option category
     * @param name Option name
     * @param value Option value
     */
    public void saveOption(String category, String name, Object value) {
        // Get old value for change notification
        Object oldValue = cachedOptions.get(name);
        
        Options options = tool.getOptions(category);

        if (value instanceof Integer) {
            options.setInt(name, (Integer) value);
        } else if (value instanceof Boolean) {
            options.setBoolean(name, (Boolean) value);
        } else if (value instanceof String) {
            options.setString(name, (String) value);
        }

        // Update cache
        cachedOptions.put(name, value);

        Msg.debug(this, "Saved option: " + category + "." + name + " = " + value);
        
        // Notify listeners if value actually changed
        if (oldValue == null || !oldValue.equals(value)) {
            notifyConfigChangeListeners(category, name, oldValue, value);
        }
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
        saveOption(SERVER_OPTIONS, SERVER_PORT, port);
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
        saveOption(SERVER_OPTIONS, SERVER_ENABLED, enabled);
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
        saveOption(SERVER_OPTIONS, DEBUG_MODE, enabled);
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
        saveOption(SERVER_OPTIONS, MAX_DECOMPILER_SEARCH_FUNCTIONS, maxFunctions);
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
        saveOption(SERVER_OPTIONS, DECOMPILER_TIMEOUT_SECONDS, timeoutSeconds);
    }
}
