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
package reva.tools;

/**
 * A modifying call was refused because the program stayed busy for its whole
 * wait: another writer's transaction or running auto-analysis did not finish
 * in time, or the save lock could not be taken.
 * <p>
 * A run reports this as its {@code executionError} so the tool layer can mark
 * the result itself as busy ({@code busy: true}, {@code transaction:
 * "refused"}) instead of as a plain failure, and can tell the caller to wait
 * for the in-flight operation rather than retry at once. The message is the
 * reason the program was still busy (for example {@code "a transaction is
 * open (ReVa: Auto Analysis)"}), not instructions; the tool layer adds those.
 */
public class ProgramBusyException extends RuntimeException {

    public ProgramBusyException(String reason) {
        super(reason);
    }

    /** The reason the program was busy. */
    public String reason() {
        return getMessage();
    }
}
