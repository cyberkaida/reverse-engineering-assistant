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
package reva.plugin.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.util.Msg;

/**
 * Configuration backend that uses a properties file.
 * This is used in headless mode where configuration is loaded from a file.
 * Changes can be persisted back to the file if needed.
 */
public class FileBackend implements ConfigurationBackend {

    private final File configFile;
    private final Properties properties;
    private final Set<ConfigurationBackendListener> listeners = ConcurrentHashMap.newKeySet();
    private final boolean autoSave;

    /**
     * Constructor
     * @param configFile The configuration file to load/save
     * @param autoSave Whether to automatically save changes to the file
     * @throws IOException if the file cannot be read
     */
    public FileBackend(File configFile, boolean autoSave) throws IOException {
        this.configFile = configFile;
        this.autoSave = autoSave;
        this.properties = new Properties();

        // Load existing configuration if file exists
        if (configFile.exists()) {
            try (FileInputStream fis = new FileInputStream(configFile)) {
                properties.load(fis);
                Msg.info(this, "Loaded configuration from: " + configFile.getAbsolutePath());
            }
        } else {
            Msg.info(this, "Configuration file does not exist, using defaults: " + configFile.getAbsolutePath());
        }
    }

    /**
     * Constructor with autoSave disabled
     * @param configFile The configuration file to load
     * @throws IOException if the file cannot be read
     */
    public FileBackend(File configFile) throws IOException {
        this(configFile, false);
    }

    @Override
    public int getInt(String category, String name, int defaultValue) {
        String key = makeKey(category, name);
        String value = properties.getProperty(key);
        if (value != null) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                Msg.warn(this, "Invalid integer value for " + key + ": " + value);
            }
        }
        return defaultValue;
    }

    @Override
    public void setInt(String category, String name, int value) {
        String key = makeKey(category, name);
        String oldValueStr = properties.getProperty(key);
        Integer oldValue = null;
        if (oldValueStr != null) {
            try {
                oldValue = Integer.parseInt(oldValueStr);
            } catch (NumberFormatException e) {
                // Ignore parse error for old value
            }
        }

        properties.setProperty(key, String.valueOf(value));
        if (autoSave) {
            save();
        }
        notifyListeners(category, name, oldValue, value);
    }

    @Override
    public String getString(String category, String name, String defaultValue) {
        String key = makeKey(category, name);
        return properties.getProperty(key, defaultValue);
    }

    @Override
    public void setString(String category, String name, String value) {
        String key = makeKey(category, name);
        String oldValue = properties.getProperty(key);
        properties.setProperty(key, value);
        if (autoSave) {
            save();
        }
        notifyListeners(category, name, oldValue, value);
    }

    @Override
    public boolean getBoolean(String category, String name, boolean defaultValue) {
        String key = makeKey(category, name);
        String value = properties.getProperty(key);
        if (value != null) {
            return Boolean.parseBoolean(value);
        }
        return defaultValue;
    }

    @Override
    public void setBoolean(String category, String name, boolean value) {
        String key = makeKey(category, name);
        String oldValueStr = properties.getProperty(key);
        Boolean oldValue = null;
        if (oldValueStr != null) {
            oldValue = Boolean.parseBoolean(oldValueStr);
        }

        properties.setProperty(key, String.valueOf(value));
        if (autoSave) {
            save();
        }
        notifyListeners(category, name, oldValue, value);
    }

    @Override
    public boolean supportsChangeNotifications() {
        return true;
    }

    @Override
    public void addChangeListener(ConfigurationBackendListener listener) {
        listeners.add(listener);
    }

    @Override
    public void removeChangeListener(ConfigurationBackendListener listener) {
        listeners.remove(listener);
    }

    @Override
    public void dispose() {
        if (autoSave) {
            save();
        }
        listeners.clear();
        properties.clear();
    }

    /**
     * Save the current configuration to the file
     */
    public void save() {
        try (FileOutputStream fos = new FileOutputStream(configFile)) {
            properties.store(fos, "ReVa Configuration");
            Msg.debug(this, "Saved configuration to: " + configFile.getAbsolutePath());
        } catch (IOException e) {
            Msg.error(this, "Failed to save configuration to: " + configFile.getAbsolutePath(), e);
        }
    }

    /**
     * Create a property key from category and name
     * Format: category.name (e.g., "ReVa Server Options.Server Port" -> "reva.server.options.server.port")
     */
    private String makeKey(String category, String name) {
        // Convert to lowercase and replace spaces with dots for property key format
        String catKey = category.toLowerCase().replace(" ", ".");
        String nameKey = name.toLowerCase().replace(" ", ".");
        return catKey + "." + nameKey;
    }

    /**
     * Notify all listeners of a configuration change
     */
    private void notifyListeners(String category, String name, Object oldValue, Object newValue) {
        for (ConfigurationBackendListener listener : listeners) {
            try {
                listener.onConfigurationChanged(category, name, oldValue, newValue);
            } catch (Exception e) {
                Msg.error(this, "Error notifying configuration listener", e);
            }
        }
    }

    /**
     * Get the configuration file
     * @return The configuration file
     */
    public File getConfigFile() {
        return configFile;
    }
}
