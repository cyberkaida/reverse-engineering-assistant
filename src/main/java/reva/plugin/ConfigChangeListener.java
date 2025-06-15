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

/**
 * Interface for listening to configuration changes in the ReVa plugin.
 * Implementations can register with ConfigManager to receive notifications
 * when configuration values change.
 */
public interface ConfigChangeListener {
    
    /**
     * Called when a configuration option has changed.
     * 
     * @param category The category of the option that changed
     * @param name The name of the option that changed
     * @param oldValue The previous value of the option
     * @param newValue The new value of the option
     */
    void onConfigChanged(String category, String name, Object oldValue, Object newValue);
}