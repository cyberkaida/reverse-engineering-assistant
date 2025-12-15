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

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Utility class for handling the "include" filter parameter used across multiple tools.
 */
public final class IncludeFilterUtil {

    // Include parameter value: include all items
    public static final String INCLUDE_ALL = "all";

    // Include parameter value: include only user-named items (exclude FUN_*, DAT_*, LAB_*, etc.)
    public static final String INCLUDE_NAMED = "named";

    // Include parameter value: include only default Ghidra names (FUN_*, DAT_*, LAB_*, etc.)
    public static final String INCLUDE_UNNAMED = "unnamed";

    // Valid values for the include parameter
    public static final Set<String> VALID_VALUES = Set.of(INCLUDE_ALL, INCLUDE_NAMED, INCLUDE_UNNAMED);

    // Default value for the include parameter
    public static final String DEFAULT_VALUE = INCLUDE_NAMED;

    private IncludeFilterUtil() {
        // Utility class - prevent instantiation
    }

    /**
     * Validate and normalize the include parameter.
     *
     * @param include The include value from request (may be null or empty)
     * @return Validated and normalized include value (defaults to "named")
     * @throws IllegalArgumentException if include value is invalid
     */
    public static String validate(String include) {
        if (include == null || include.isEmpty()) {
            return DEFAULT_VALUE;
        }
        String normalized = include.toLowerCase().trim();
        if (!VALID_VALUES.contains(normalized)) {
            throw new IllegalArgumentException("Invalid 'include' value: '" + include + "'. Valid values: all, named, unnamed");
        }
        return normalized;
    }

    /**
     * Check if an item should be included based on its name and the include filter.
     *
     * Uses {@link SymbolUtil#isDefaultSymbolName(String)} to determine if a name
     * is a default Ghidra-generated name (FUN_*, DAT_*, LAB_*, etc.).
     *
     * @param name The item name to check (function name, symbol name, etc.)
     * @param include The include filter value ("all", "named", or "unnamed")
     * @return true if the item should be included, false otherwise
     */
    public static boolean shouldInclude(String name, String include) {
        if (INCLUDE_ALL.equals(include)) {
            return true;
        }
        boolean isDefault = SymbolUtil.isDefaultSymbolName(name);
        return INCLUDE_NAMED.equals(include) != isDefault;
    }

    /**
     * Return the "include" argument definition
     */
    public static Map<String, Object> getIncludePropertyDefinition() {
        return Map.of(
            "type", "string",
            "description", "Which items to include: 'all' (everything), 'named' (user-named only, excludes DAT_*, LAB_*, etc.), 'unnamed' (only default Ghidra names). Default: 'named'",
            "enum", List.of("all", "named", "unnamed"),
            "default", "named"
        );
    }
}
