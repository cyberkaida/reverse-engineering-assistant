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

import java.util.Locale;

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
     * @return a stable lowercase-kebab identifier for this group (e.g. "core-analysis").
     *         Suitable for CLI flags and error messages.
     */
    public String canonicalId() {
        return name().toLowerCase(Locale.ROOT).replace('_', '-');
    }

    /**
     * Resolve a group from a flexible identifier: the enum name in any case with
     * '-', '_' or spaces as separators (e.g. "scripting", "SCRIPTING",
     * "advanced-analysis", "advanced_analysis", "Core Analysis").
     *
     * @param id the identifier to parse
     * @return the matching group, or null if none matches
     */
    public static ToolGroup fromId(String id) {
        if (id == null) {
            return null;
        }
        String norm = id.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
        if (norm.isEmpty()) {
            return null;
        }
        for (ToolGroup group : values()) {
            if (group.name().equals(norm)) {
                return group;
            }
        }
        return null;
    }

    /**
     * Resolve a group from its display name (the option label), or null if none matches.
     *
     * @param displayName the display name to look up
     * @return the matching group, or null
     */
    public static ToolGroup fromDisplayName(String displayName) {
        if (displayName == null) {
            return null;
        }
        for (ToolGroup group : values()) {
            if (group.getDisplayName().equals(displayName)) {
                return group;
            }
        }
        return null;
    }
}
