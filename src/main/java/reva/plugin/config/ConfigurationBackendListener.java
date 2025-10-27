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

/**
 * Listener interface for configuration backend changes.
 * Backends that support change notifications will call this when values change.
 */
public interface ConfigurationBackendListener {

    /**
     * Called when a configuration value changes
     * @param category The configuration category
     * @param name The configuration name
     * @param oldValue The previous value
     * @param newValue The new value
     */
    void onConfigurationChanged(String category, String name, Object oldValue, Object newValue);
}
