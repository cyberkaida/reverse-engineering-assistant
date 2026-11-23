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
package reva.decompiler;

/**
 * Outcome of one decompilation: a snapshot, or the error message the tools report. {@code cause} is the
 * caught exception of an EXCEPTION result, else null.
 */
public record DecompilationResult(DecompilationSnapshot snapshot, String errorMessage, FailureKind failureKind,
        Throwable cause) {

    /** Why a decompilation failed; null on success. */
    public enum FailureKind {
        /** The decompiler could not be opened on the program. */
        INIT_FAILED,
        /** The decompiler ran but did not produce a result ("Decompilation failed: ..."). */
        DECOMPILE_FAILED,
        /** The decompile was cancelled by the configured timeout. */
        TIMED_OUT,
        /** An exception was thrown while decompiling. */
        EXCEPTION
    }

    public boolean success() {
        return snapshot != null;
    }

    public static DecompilationResult success(DecompilationSnapshot s) {
        return new DecompilationResult(s, null, null, null);
    }

    public static DecompilationResult failure(String message) {
        return failure(FailureKind.DECOMPILE_FAILED, message);
    }

    public static DecompilationResult failure(FailureKind kind, String message) {
        return new DecompilationResult(null, message, kind, null);
    }

    /** An EXCEPTION result that keeps the exception the decompile threw. */
    public static DecompilationResult exception(String message, Throwable cause) {
        return new DecompilationResult(null, message, FailureKind.EXCEPTION, cause);
    }
}
