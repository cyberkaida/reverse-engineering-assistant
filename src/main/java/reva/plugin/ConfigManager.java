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

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

import reva.plugin.config.ConfigurationBackend;
import reva.plugin.config.ConfigurationBackendListener;
import reva.plugin.config.FileBackend;
import reva.plugin.config.InMemoryBackend;
import reva.plugin.config.ToolOptionsBackend;

/**
 * Configuration manager for the ReVa plugin.
 * Supports both GUI mode (via ToolOptions) and headless mode (via file or in-memory).
 * The backend abstraction allows the same configuration API to work in different contexts.
 */
public class ConfigManager implements ConfigurationBackendListener {
    // Configuration option categories
    public static final String SERVER_OPTIONS = "ReVa Server Options";

    // Option names
    public static final String SERVER_PORT = "Server Port";
    public static final String SERVER_HOST = "Server Host";
    public static final String SERVER_ENABLED = "Server Enabled";
    public static final String API_KEY_ENABLED = "API Key Authentication Enabled";
    public static final String API_KEY = "API Key";
    public static final String DEBUG_MODE = "Debug Mode";
    public static final String MAX_DECOMPILER_SEARCH_FUNCTIONS = "Max Decompiler Search Functions";
    public static final String DECOMPILER_TIMEOUT_SECONDS = "Decompiler Timeout Seconds";
    public static final String IMPORT_ANALYSIS_TIMEOUT_SECONDS = "Import Analysis Timeout Seconds";
    public static final String WAIT_FOR_ANALYSIS_ON_IMPORT = "Wait For Analysis On Import";
    public static final String IMPORT_MAX_DEPTH = "Import Max Depth";

    // Default values
    private static final int DEFAULT_PORT = 8080;
    private static final String DEFAULT_HOST = "127.0.0.1";
    private static final boolean DEFAULT_SERVER_ENABLED = true;
    private static final boolean DEFAULT_API_KEY_ENABLED = false;
    private static final String DEFAULT_API_KEY = "";
    private static final boolean DEFAULT_DEBUG_MODE = false;
    private static final int DEFAULT_MAX_DECOMPILER_SEARCH_FUNCTIONS = 1000;
    private static final int DEFAULT_DECOMPILER_TIMEOUT_SECONDS = 10;
    private static final int DEFAULT_IMPORT_ANALYSIS_TIMEOUT_SECONDS = 600;
    private static final boolean DEFAULT_WAIT_FOR_ANALYSIS_ON_IMPORT = true;
    private static final int DEFAULT_IMPORT_MAX_DEPTH = 10;

    private final ConfigurationBackend backend;
    private final Map<String, Object> cachedOptions = new ConcurrentHashMap<>();
    private final Set<ConfigChangeListener> configChangeListeners = ConcurrentHashMap.newKeySet();

    /**
     * Constructor for GUI mode using PluginTool
     * @param tool The plugin tool to get/save options from
     */
    public ConfigManager(PluginTool tool) {
        ToolOptionsBackend toolBackend = new ToolOptionsBackend(tool, SERVER_OPTIONS);
        this.backend = toolBackend;

        // Register options with Ghidra
        registerOptionsWithGhidra(toolBackend);

        // Register as listener for backend changes
        backend.addChangeListener(this);

        // Load initial values
        loadOptions();
    }

    /**
     * Constructor for headless mode with file configuration
     * @param configFile The configuration file to load
     * @throws IOException if the file cannot be read
     */
    public ConfigManager(File configFile) throws IOException {
        this.backend = new FileBackend(configFile);

        // Register as listener for backend changes
        backend.addChangeListener(this);

        // Load initial values
        loadOptions();
    }

    /**
     * Constructor for headless mode with configuration file path
     * Convenience constructor for PyGhidra scripts that use string paths
     * @param configFilePath Path to the configuration file
     * @throws IOException if the file cannot be read
     */
    public ConfigManager(String configFilePath) throws IOException {
        this(new File(configFilePath));
    }

    /**
     * Constructor for headless mode with in-memory configuration (uses defaults)
     */
    public ConfigManager() {
        this.backend = new InMemoryBackend();

        // Register as listener for backend changes
        backend.addChangeListener(this);

        // Initialize with defaults
        loadOptions();
    }

    /**
     * Constructor for testing with custom backend
     * @param backend The configuration backend to use
     */
    protected ConfigManager(ConfigurationBackend backend) {
        this.backend = backend;

        // Register as listener for backend changes
        backend.addChangeListener(this);

        // Load initial values
        loadOptions();
    }

    /**
     * Register all options with Ghidra's options system (GUI mode only)
     */
    private void registerOptionsWithGhidra(ToolOptionsBackend toolBackend) {
        HelpLocation help = new HelpLocation("ReVa", "Configuration");

        var toolOptions = toolBackend.getToolOptions();

        toolOptions.registerOption(SERVER_PORT, DEFAULT_PORT, help,
            "Port number for the ReVa MCP server");
        toolOptions.registerOption(SERVER_HOST, DEFAULT_HOST, help,
            "Host interface for the ReVa MCP server (127.0.0.1 for localhost only, 0.0.0.0 for all interfaces)");
        toolOptions.registerOption(SERVER_ENABLED, DEFAULT_SERVER_ENABLED, help,
            "Whether the ReVa MCP server is enabled");
        toolOptions.registerOption(API_KEY_ENABLED, DEFAULT_API_KEY_ENABLED, help,
            "Whether API key authentication is required for MCP server access");

        // Only generate a new API key if one does not already exist
        String existingApiKey = toolOptions.getString(API_KEY, null);
        boolean isApiKeyMissing = (existingApiKey == null || existingApiKey.isEmpty());
        String apiKeyToRegister = isApiKeyMissing ? generateDefaultApiKey() : existingApiKey;
        toolOptions.registerOption(API_KEY, apiKeyToRegister, help,
            "API key required for MCP server access when authentication is enabled");

        // Ensure the generated key is actually set in the options
        if (isApiKeyMissing) {
            toolOptions.setString(API_KEY, apiKeyToRegister);
        }
        toolOptions.registerOption(DEBUG_MODE, DEFAULT_DEBUG_MODE, help,
            "Whether debug mode is enabled");
        toolOptions.registerOption(MAX_DECOMPILER_SEARCH_FUNCTIONS, DEFAULT_MAX_DECOMPILER_SEARCH_FUNCTIONS, help,
            "Maximum number of functions before discouraging decompiler search");
        toolOptions.registerOption(DECOMPILER_TIMEOUT_SECONDS, DEFAULT_DECOMPILER_TIMEOUT_SECONDS, help,
            "Timeout in seconds for decompiler operations");
        toolOptions.registerOption(IMPORT_ANALYSIS_TIMEOUT_SECONDS, DEFAULT_IMPORT_ANALYSIS_TIMEOUT_SECONDS, help,
            "Timeout in seconds for analyzing each imported file (default: 10 minutes)");
        toolOptions.registerOption(WAIT_FOR_ANALYSIS_ON_IMPORT, DEFAULT_WAIT_FOR_ANALYSIS_ON_IMPORT, help,
            "Whether to run auto-analysis after file import and wait for it to complete (default: true)");
        toolOptions.registerOption(IMPORT_MAX_DEPTH, DEFAULT_IMPORT_MAX_DEPTH, help,
            "Maximum depth to recurse into containers/archives when importing (default: 10)");
    }

    /**
     * Load options from the backend and cache them
     */
    protected void loadOptions() {
        // Cache the options
        cachedOptions.put(SERVER_PORT, backend.getInt(SERVER_OPTIONS, SERVER_PORT, DEFAULT_PORT));
        cachedOptions.put(SERVER_HOST, backend.getString(SERVER_OPTIONS, SERVER_HOST, DEFAULT_HOST));
        cachedOptions.put(SERVER_ENABLED, backend.getBoolean(SERVER_OPTIONS, SERVER_ENABLED, DEFAULT_SERVER_ENABLED));
        cachedOptions.put(API_KEY_ENABLED, backend.getBoolean(SERVER_OPTIONS, API_KEY_ENABLED, DEFAULT_API_KEY_ENABLED));

        // Get the API key (generate one if needed for in-memory backend)
        String apiKey = backend.getString(SERVER_OPTIONS, API_KEY, DEFAULT_API_KEY);
        if (apiKey == null || apiKey.isEmpty()) {
            apiKey = generateDefaultApiKey();
            backend.setString(SERVER_OPTIONS, API_KEY, apiKey);
        }
        cachedOptions.put(API_KEY, apiKey);

        cachedOptions.put(DEBUG_MODE, backend.getBoolean(SERVER_OPTIONS, DEBUG_MODE, DEFAULT_DEBUG_MODE));
        cachedOptions.put(MAX_DECOMPILER_SEARCH_FUNCTIONS,
            backend.getInt(SERVER_OPTIONS, MAX_DECOMPILER_SEARCH_FUNCTIONS, DEFAULT_MAX_DECOMPILER_SEARCH_FUNCTIONS));
        cachedOptions.put(DECOMPILER_TIMEOUT_SECONDS,
            backend.getInt(SERVER_OPTIONS, DECOMPILER_TIMEOUT_SECONDS, DEFAULT_DECOMPILER_TIMEOUT_SECONDS));
        cachedOptions.put(IMPORT_ANALYSIS_TIMEOUT_SECONDS,
            backend.getInt(SERVER_OPTIONS, IMPORT_ANALYSIS_TIMEOUT_SECONDS, DEFAULT_IMPORT_ANALYSIS_TIMEOUT_SECONDS));
        cachedOptions.put(WAIT_FOR_ANALYSIS_ON_IMPORT,
            backend.getBoolean(SERVER_OPTIONS, WAIT_FOR_ANALYSIS_ON_IMPORT, DEFAULT_WAIT_FOR_ANALYSIS_ON_IMPORT));
        cachedOptions.put(IMPORT_MAX_DEPTH,
            backend.getInt(SERVER_OPTIONS, IMPORT_MAX_DEPTH, DEFAULT_IMPORT_MAX_DEPTH));

        Msg.debug(this, "Loaded ReVa configuration settings");
    }

    /**
     * Backend configuration change callback
     */
    @Override
    public void onConfigurationChanged(String category, String name, Object oldValue, Object newValue) {
        Msg.debug(this, "Configuration changed: " + name + " from " + oldValue + " to " + newValue);

        // Update our cache
        cachedOptions.put(name, newValue);

        // Notify our custom listeners
        notifyConfigChangeListeners(SERVER_OPTIONS, name, oldValue, newValue);
    }

    /**
     * Get the configuration backend (package-private for testing)
     * @return The configuration backend
     */
    ConfigurationBackend getBackend() {
        return backend;
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
     * Get the server port (convenience method)
     * Alias for getServerPort() - useful for PyGhidra scripts
     * @return The configured server port
     */
    public int getPort() {
        return getServerPort();
    }

    /**
     * Set the server port
     * @param port The port number to use
     */
    public void setServerPort(int port) {
        backend.setInt(SERVER_OPTIONS, SERVER_PORT, port);
        // onConfigurationChanged() will be called automatically
    }

    /**
     * Find and set a random available port
     * This is useful for headless mode with stdio transport where port conflicts should be avoided
     * @return The port number that was selected
     * @throws IOException if no port is available
     */
    public int setRandomAvailablePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            int port = socket.getLocalPort();
            setServerPort(port);
            Msg.info(this, "Selected random available port: " + port);
            return port;
        }
    }

    /**
     * Get the server host
     * @return The configured server host
     */
    public String getServerHost() {
        return (String) cachedOptions.getOrDefault(SERVER_HOST, DEFAULT_HOST);
    }

    /**
     * Set the server host
     * @param host The host interface to bind to
     */
    public void setServerHost(String host) {
        backend.setString(SERVER_OPTIONS, SERVER_HOST, host);
        // onConfigurationChanged() will be called automatically
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
        backend.setBoolean(SERVER_OPTIONS, SERVER_ENABLED, enabled);
        // onConfigurationChanged() will be called automatically
    }

    /**
     * Check if API key authentication is enabled
     * @return True if API key authentication is enabled
     */
    public boolean isApiKeyEnabled() {
        return (Boolean) cachedOptions.getOrDefault(API_KEY_ENABLED, DEFAULT_API_KEY_ENABLED);
    }

    /**
     * Set whether API key authentication is enabled
     * @param enabled True to enable API key authentication
     */
    public void setApiKeyEnabled(boolean enabled) {
        backend.setBoolean(SERVER_OPTIONS, API_KEY_ENABLED, enabled);
        // onConfigurationChanged() will be called automatically
    }

    /**
     * Get the API key
     * @return The configured API key
     */
    public String getApiKey() {
        return (String) cachedOptions.getOrDefault(API_KEY, DEFAULT_API_KEY);
    }

    /**
     * Set the API key
     * @param apiKey The API key to use
     */
    public void setApiKey(String apiKey) {
        backend.setString(SERVER_OPTIONS, API_KEY, apiKey);
        // onConfigurationChanged() will be called automatically
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
        backend.setBoolean(SERVER_OPTIONS, DEBUG_MODE, enabled);
        // onConfigurationChanged() will be called automatically
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
        backend.setInt(SERVER_OPTIONS, MAX_DECOMPILER_SEARCH_FUNCTIONS, maxFunctions);
        // onConfigurationChanged() will be called automatically
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
        backend.setInt(SERVER_OPTIONS, DECOMPILER_TIMEOUT_SECONDS, timeoutSeconds);
        // onConfigurationChanged() will be called automatically
    }

    /**
     * Get the import analysis timeout in seconds
     * @return The configured timeout in seconds for analyzing imported files
     */
    public int getImportAnalysisTimeoutSeconds() {
        return (Integer) cachedOptions.getOrDefault(IMPORT_ANALYSIS_TIMEOUT_SECONDS, DEFAULT_IMPORT_ANALYSIS_TIMEOUT_SECONDS);
    }

    /**
     * Set the import analysis timeout in seconds
     * @param timeoutSeconds The timeout in seconds
     */
    public void setImportAnalysisTimeoutSeconds(int timeoutSeconds) {
        backend.setInt(SERVER_OPTIONS, IMPORT_ANALYSIS_TIMEOUT_SECONDS, timeoutSeconds);
        // onConfigurationChanged() will be called automatically
    }

    /**
     * Check if analysis should run after import and wait for completion
     * @return True if analysis should run and wait after import
     */
    public boolean isWaitForAnalysisOnImport() {
        return (Boolean) cachedOptions.getOrDefault(WAIT_FOR_ANALYSIS_ON_IMPORT, DEFAULT_WAIT_FOR_ANALYSIS_ON_IMPORT);
    }

    /**
     * Set whether analysis should run after import and wait for completion
     * @param wait True to run analysis and wait after import
     */
    public void setWaitForAnalysisOnImport(boolean wait) {
        backend.setBoolean(SERVER_OPTIONS, WAIT_FOR_ANALYSIS_ON_IMPORT, wait);
        // onConfigurationChanged() will be called automatically
    }

    /**
     * Get the maximum depth to recurse into containers/archives when importing
     * @return The maximum import depth
     */
    public int getImportMaxDepth() {
        return (Integer) cachedOptions.getOrDefault(IMPORT_MAX_DEPTH, DEFAULT_IMPORT_MAX_DEPTH);
    }

    /**
     * Set the maximum depth to recurse into containers/archives when importing
     * @param depth The maximum import depth
     */
    public void setImportMaxDepth(int depth) {
        backend.setInt(SERVER_OPTIONS, IMPORT_MAX_DEPTH, depth);
        // onConfigurationChanged() will be called automatically
    }

    /**
     * Generate a default API key with ReVa-UUID format
     * @return A new API key in the format "ReVa-{uuid}"
     */
    private String generateDefaultApiKey() {
        return "ReVa-" + UUID.randomUUID().toString();
    }

    /**
     * Clean up when the plugin is disposed
     */
    public void dispose() {
        if (backend != null) {
            backend.removeChangeListener(this);
            backend.dispose();
        }
    }
}
