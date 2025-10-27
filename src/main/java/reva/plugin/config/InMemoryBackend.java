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

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.util.Msg;

/**
 * In-memory configuration backend.
 * Stores configuration in memory with no persistence.
 * Used for headless mode with default settings or testing.
 */
public class InMemoryBackend implements ConfigurationBackend {

    private final Map<String, Object> storage = new HashMap<>();
    private final Set<ConfigurationBackendListener> listeners = ConcurrentHashMap.newKeySet();

    @Override
    public int getInt(String category, String name, int defaultValue) {
        String key = makeKey(category, name);
        Object value = storage.get(key);
        if (value instanceof Integer) {
            return (Integer) value;
        }
        return defaultValue;
    }

    @Override
    public void setInt(String category, String name, int value) {
        String key = makeKey(category, name);
        Object oldValue = storage.put(key, value);
        notifyListeners(category, name, oldValue, value);
    }

    @Override
    public String getString(String category, String name, String defaultValue) {
        String key = makeKey(category, name);
        Object value = storage.get(key);
        if (value instanceof String) {
            return (String) value;
        }
        return defaultValue;
    }

    @Override
    public void setString(String category, String name, String value) {
        String key = makeKey(category, name);
        Object oldValue = storage.put(key, value);
        notifyListeners(category, name, oldValue, value);
    }

    @Override
    public boolean getBoolean(String category, String name, boolean defaultValue) {
        String key = makeKey(category, name);
        Object value = storage.get(key);
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        return defaultValue;
    }

    @Override
    public void setBoolean(String category, String name, boolean value) {
        String key = makeKey(category, name);
        Object oldValue = storage.put(key, value);
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
        storage.clear();
        listeners.clear();
    }

    /**
     * Create a storage key from category and name
     */
    private String makeKey(String category, String name) {
        return category + ":" + name;
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
}
