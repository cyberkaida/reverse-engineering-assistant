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

import java.util.HashMap;
import java.util.Map;

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

    // Default values
    private static final int DEFAULT_PORT = 8080;
    private static final boolean DEFAULT_SERVER_ENABLED = true;
    private static final boolean DEFAULT_DEBUG_MODE = false;

    private final PluginTool tool;
    private final Map<String, Object> cachedOptions = new HashMap<>();

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

        // Cache the options
        cachedOptions.put(SERVER_PORT, options.getInt(SERVER_PORT, DEFAULT_PORT));
        cachedOptions.put(SERVER_ENABLED, options.getBoolean(SERVER_ENABLED, DEFAULT_SERVER_ENABLED));
        cachedOptions.put(DEBUG_MODE, options.getBoolean(DEBUG_MODE, DEFAULT_DEBUG_MODE));

        Msg.debug(this, "Loaded ReVa configuration settings");
    }

    /**
     * Save an option value
     * @param category Option category
     * @param name Option name
     * @param value Option value
     */
    public void saveOption(String category, String name, Object value) {
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
}
