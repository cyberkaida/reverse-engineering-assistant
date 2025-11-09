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

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.bean.opteditor.OptionsVetoException;

/**
 * Configuration backend that uses Ghidra's ToolOptions.
 * This is used in GUI mode where configuration is persisted to Ghidra's tool options.
 */
public class ToolOptionsBackend implements ConfigurationBackend, OptionsChangeListener {

    private final PluginTool tool;
    private final ToolOptions toolOptions;
    private final Set<ConfigurationBackendListener> listeners = ConcurrentHashMap.newKeySet();

    /**
     * Constructor
     * @param tool The plugin tool
     * @param category The options category (e.g., "ReVa Server Options")
     */
    public ToolOptionsBackend(PluginTool tool, String category) {
        this.tool = tool;
        this.toolOptions = tool.getOptions(category);

        // Register as listener for Ghidra's option changes
        toolOptions.addOptionsChangeListener(this);
    }

    @Override
    public int getInt(String category, String name, int defaultValue) {
        return toolOptions.getInt(name, defaultValue);
    }

    @Override
    public void setInt(String category, String name, int value) {
        toolOptions.setInt(name, value);
        // optionsChanged() will be called automatically by Ghidra
    }

    @Override
    public String getString(String category, String name, String defaultValue) {
        return toolOptions.getString(name, defaultValue);
    }

    @Override
    public void setString(String category, String name, String value) {
        toolOptions.setString(name, value);
        // optionsChanged() will be called automatically by Ghidra
    }

    @Override
    public boolean getBoolean(String category, String name, boolean defaultValue) {
        return toolOptions.getBoolean(name, defaultValue);
    }

    @Override
    public void setBoolean(String category, String name, boolean value) {
        toolOptions.setBoolean(name, value);
        // optionsChanged() will be called automatically by Ghidra
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
        if (toolOptions != null) {
            toolOptions.removeOptionsChangeListener(this);
        }
        listeners.clear();
    }

    /**
     * Ghidra's options change callback
     */
    @Override
    public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue)
            throws OptionsVetoException {

        Msg.debug(this, "ToolOptions changed: " + optionName + " from " + oldValue + " to " + newValue);

        // Notify our listeners
        // Note: We pass empty string as category since ToolOptions doesn't provide it
        for (ConfigurationBackendListener listener : listeners) {
            try {
                listener.onConfigurationChanged("", optionName, oldValue, newValue);
            } catch (Exception e) {
                Msg.error(this, "Error notifying configuration listener", e);
            }
        }
    }

    /**
     * Get the underlying ToolOptions (for registering options)
     * @return The ToolOptions instance
     */
    public ToolOptions getToolOptions() {
        return toolOptions;
    }
}
