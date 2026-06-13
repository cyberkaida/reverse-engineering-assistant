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
 * Logical groupings of MCP tool providers that can be enabled/disabled as a unit
 * via configuration. The mapping from a group to its concrete tool providers lives
 * in {@code McpServerManager}; this enum owns only the user-facing identity and the
 * configuration option name.
 */
public enum ToolGroup {
    CORE_ANALYSIS("Core Analysis"),
    DATA_AND_TYPES("Data & Types"),
    ADVANCED_ANALYSIS("Advanced Analysis"),
    DIFF("Diff"),
    ANNOTATIONS("Annotations"),
    SCRIPTING("Scripting");

    private final String displayName;

    ToolGroup(String displayName) {
        this.displayName = displayName;
    }

    /**
     * @return the human-readable group name (e.g. "Core Analysis")
     */
    public String getDisplayName() {
        return displayName;
    }

    /**
     * @return the ConfigManager option name for this group's enable toggle
     */
    public String getOptionName() {
        return "Enable Tool Group: " + displayName;
    }

    /**
     * Resolve a group from its configuration option name.
     *
     * @param optionName the option name to look up
     * @return the matching group, or null if none matches
     */
    public static ToolGroup fromOptionName(String optionName) {
        if (optionName == null) {
            return null;
        }
        for (ToolGroup group : values()) {
            if (group.getOptionName().equals(optionName)) {
                return group;
            }
        }
        return null;
    }
}
