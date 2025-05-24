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

import java.util.regex.Pattern;

/**
 * Utility methods for working with Ghidra symbols.
 */
public class SymbolUtil {
    // Regular expressions for Ghidra's default naming patterns
    private static final Pattern DEFAULT_NAME_PATTERN = Pattern.compile(
        "^(FUN|LAB|SUB|DAT|EXT|PTR|ARRAY)_[0-9a-fA-F]+$"
    );

    /**
     * Check if a symbol name appears to be a default Ghidra-generated name
     * @param name The symbol name to check
     * @return True if the name follows Ghidra's default naming patterns
     */
    public static boolean isDefaultSymbolName(String name) {
        if (name == null) {
            return false;
        }

        return DEFAULT_NAME_PATTERN.matcher(name).matches();
    }
}
