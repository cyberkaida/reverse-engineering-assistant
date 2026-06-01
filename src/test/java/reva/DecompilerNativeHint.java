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
package reva;

import java.util.Optional;

/**
 * Helper for integration tests: builds an actionable hint when a test failure is
 * likely caused by missing Ghidra native binaries.
 *
 * <p>Ghidra releases ship prebuilt {@code decompile} binaries for Linux and Windows
 * but not for macOS, so a fresh macOS install (especially Apple Silicon) has no
 * decompiler native until {@code buildNatives} is run. Without it, decompilation
 * silently yields nothing and decompiler integration tests fail with confusing
 * assertions ("Decompilation should not be empty"). This helper surfaces the fix.
 */
public final class DecompilerNativeHint {

    private DecompilerNativeHint() {
    }

    /**
     * Returns a hint to run {@code buildNatives}, but only when the failure was on
     * macOS and the decompiler native is missing — the one situation where the hint
     * is both relevant and actionable.
     *
     * @param osName the {@code os.name} system property (may be null)
     * @param decompileNativeAvailable whether Ghidra could locate the decompile native
     * @return a populated hint message, or empty when no hint is warranted
     */
    public static Optional<String> hintForFailure(String osName, boolean decompileNativeAvailable) {
        if (!isMac(osName) || decompileNativeAvailable) {
            return Optional.empty();
        }
        return Optional.of(
            "Ghidra's decompiler native binary was not found on macOS. Ghidra releases do not "
                + "ship a prebuilt decompiler for macOS, so this is likely why decompiler tests "
                + "are failing. Build the natives and re-run:\n"
                + "    gradle -p \"$GHIDRA_INSTALL_DIR/support/gradle\" buildNatives");
    }

    private static boolean isMac(String osName) {
        return osName != null && osName.toLowerCase().contains("mac");
    }
}
