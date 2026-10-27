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

import java.util.function.Predicate;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.listing.Program;

/**
 * Whether a program can currently accept a database-modifying transaction,
 * and a bounded wait until it can. One writer at a time: run-script's parent
 * transaction, the direct-write tools' short transactions and auto-analysis
 * all exclude each other, so a modifying call that finds the program busy
 * waits for the in-flight operation instead of failing at once — and only
 * reports a structured busy result, telling the caller to wait and retry,
 * when the deadline passes.
 *
 * <p>The save lock ({@code DomainObjectLockedException} thrown by
 * {@code startTransaction}) is not covered here: it is only observable by
 * attempting the transaction, so callers map that exception to the same
 * structured busy result.
 */
public final class DatabaseAvailability {

    /** Default time to wait for an in-flight writer to finish. */
    public static final long DEFAULT_DEADLINE_MS = 30_000;

    static final long DEFAULT_POLL_MS = 200;

    /** The outcome of an availability check or wait. */
    public record WaitOutcome(boolean modifiable, String reason) {
        static WaitOutcome ready() {
            return new WaitOutcome(true, null);
        }

        static WaitOutcome blocked(String reason) {
            return new WaitOutcome(false, reason);
        }
    }

    private DatabaseAvailability() {
    }

    /**
     * Whether auto-analysis is running on the program. Checks for an existing
     * manager first so that asking does not create one.
     */
    public static boolean isAutoAnalysisRunning(Program program) {
        return AutoAnalysisManager.hasAutoAnalysisManager(program)
            && AutoAnalysisManager.getAnalysisManager(program).isAnalyzing();
    }

    public static WaitOutcome check(Program program, Predicate<Program> analysisRunning) {
        TransactionInfo open = program.getCurrentTransactionInfo();
        if (open != null) {
            return WaitOutcome.blocked(
                "a transaction is open (" + open.getDescription() + ")");
        }
        if (analysisRunning.test(program)) {
            return WaitOutcome.blocked("auto-analysis is running");
        }
        return WaitOutcome.ready();
    }

    public static WaitOutcome check(Program program) {
        return check(program, DatabaseAvailability::isAutoAnalysisRunning);
    }

    /**
     * Polls {@link #check} until the program is modifiable or the deadline
     * passes. Returns the last outcome seen: modifiable, or busy with the
     * reason that still blocks.
     */
    public static WaitOutcome awaitModifiable(
            Program program, Predicate<Program> analysisRunning,
            long deadlineMs, long pollMs) {
        WaitOutcome outcome = check(program, analysisRunning);
        long deadline = System.currentTimeMillis() + deadlineMs;
        while (!outcome.modifiable() && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(pollMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return outcome;
            }
            outcome = check(program, analysisRunning);
        }
        return outcome;
    }

    public static WaitOutcome awaitModifiable(Program program) {
        return awaitModifiable(program, DatabaseAvailability::isAutoAnalysisRunning,
            DEFAULT_DEADLINE_MS, DEFAULT_POLL_MS);
    }
}