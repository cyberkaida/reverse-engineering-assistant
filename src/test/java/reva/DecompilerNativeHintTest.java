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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Optional;

import org.junit.Test;

/**
 * Unit tests for {@link DecompilerNativeHint}, the helper that decides whether a
 * failing integration test should be annotated with a "run buildNatives" hint.
 */
public class DecompilerNativeHintTest {

    @Test
    public void macWithMissingNativeProducesBuildNativesHint() {
        Optional<String> hint = DecompilerNativeHint.hintForFailure("Mac OS X", false);
        assertTrue("Expected a hint on macOS when the decompile native is missing", hint.isPresent());
        assertTrue("Hint should mention the buildNatives task", hint.get().contains("buildNatives"));
        assertTrue("Hint should point at the Ghidra support/gradle directory",
            hint.get().contains("support/gradle"));
    }

    @Test
    public void macDetectionIsCaseInsensitive() {
        assertTrue("macOS should be recognized regardless of case",
            DecompilerNativeHint.hintForFailure("macOS", false).isPresent());
    }

    @Test
    public void macWithNativePresentProducesNoHint() {
        assertFalse("No hint should be emitted when the native is present",
            DecompilerNativeHint.hintForFailure("Mac OS X", true).isPresent());
    }

    @Test
    public void nonMacProducesNoHintEvenWhenNativeMissing() {
        assertFalse("Linux ships prebuilt natives; no buildNatives hint there",
            DecompilerNativeHint.hintForFailure("Linux", false).isPresent());
        assertFalse("Windows ships prebuilt natives; no buildNatives hint there",
            DecompilerNativeHint.hintForFailure("Windows 11", false).isPresent());
    }
}
