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

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import com.google.common.annotations.VisibleForTesting;

import ghidra.framework.data.DefaultCheckinHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Persist a Program the strongest way its DomainFile allows: save locally, then checkin
 *  when under version control. Shared by analyze (background job) and checkin-program. */
public final class ProgramPersistenceUtil {

    public enum PersistMode { AUTO, SAVE, NONE }
    public enum PersistAction { CHECKIN, ADD_TO_VC, SAVE, SKIP }

    /** How long {@link #persist} waits for an open transaction to end before giving up. */
    public static final long TRANSACTION_WAIT_MS = 10_000;
    /** How often {@link #awaitNoTransaction} rechecks for an open transaction. */
    public static final long TRANSACTION_POLL_MS = 100;

    public static final class PersistResult {
        public final PersistAction action;   // strongest step that SUCCEEDED
        public final boolean saved;
        public final String error;            // checkin-step error after successful save, or null
        PersistResult(PersistAction action, boolean saved, String error) {
            this.action = action; this.saved = saved; this.error = error;
        }
    }

    private static volatile Consumer<Program> postSaveHook = p -> { };

    /** Visible for testing: force a mutation between save and checkin. */
    @VisibleForTesting
    public static void setPostSaveHookForTesting(Consumer<Program> hook) {
        postSaveHook = hook == null ? p -> { } : hook;
    }

    private ProgramPersistenceUtil() {}

    /** Decide what {@link #persist} would do — pure, unit-testable. */
    public static PersistAction selectAction(DomainFile file, PersistMode mode) {
        if (mode == PersistMode.NONE || file == null || file.isReadOnly()) {
            return PersistAction.SKIP;
        }
        if (mode == PersistMode.SAVE) {
            return PersistAction.SAVE;
        }
        if (file.canCheckin()) {
            return PersistAction.CHECKIN;
        }
        // canCheckin() requires modifiedSinceCheckout(), which only counts SAVED
        // changes: a checked-out file whose modifications are still in memory
        // reports canCheckin()=false until a save bumps the local version. persist()
        // saves before the checkin step, so plan CHECKIN for that case too.
        if (file.isVersioned() && file.isCheckedOut() && file.isChanged()) {
            return PersistAction.CHECKIN;
        }
        if (file.canAddToRepository()) {
            return PersistAction.ADD_TO_VC;
        }
        return PersistAction.SAVE;
    }

    /** Wait for any open transaction on the program to end, polling every {@code pollMs}.
     *  Returns true as soon as no transaction is open, false when one is still open after
     *  {@code timeoutMs}. An interrupt restores the interrupt flag and reports the current
     *  state instead of waiting further. */
    public static boolean awaitNoTransaction(Program program, long timeoutMs, long pollMs) {
        long deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        while (true) {
            if (program.getCurrentTransactionInfo() == null) {
                return true;
            }
            long remainingNanos = deadlineNanos - System.nanoTime();
            if (remainingNanos <= 0) {
                return false;
            }
            long sleepMs = Math.min(pollMs, TimeUnit.NANOSECONDS.toMillis(remainingNanos));
            try {
                Thread.sleep(Math.max(1, sleepMs));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return program.getCurrentTransactionInfo() == null;
            }
        }
    }

    /** Return a SKIP result when a transaction stays open past the wait, else null.
     *  Package-visible so tests can exercise the refusal without the production wait. */
    static PersistResult refuseIfTransactionOpen(Program program, long timeoutMs, long pollMs) {
        if (awaitNoTransaction(program, timeoutMs, pollMs)) {
            return null;
        }
        TransactionInfo tx = program.getCurrentTransactionInfo();
        String description = tx != null ? tx.getDescription() : null;
        String name = description != null ? description : "unnamed";
        return new PersistResult(PersistAction.SKIP, false,
            "a transaction is still open after waiting " + timeoutMs + " ms (" + name
                + "): a script or another tool call is still writing; retry when it finishes");
    }

    /** Save the program, then checkin/addToVC when AUTO and the file is versioned.
     *  Save runs first and is reported even if a subsequent checkin fails. Before
     *  saving, waits up to {@link #TRANSACTION_WAIT_MS} for an open transaction to
     *  end; if one is still open, nothing is saved and the result is SKIP with an
     *  error. Run this OFF the Swing thread. */
    public static PersistResult persist(Program program, PersistMode mode, String message,
            boolean keepCheckedOut, TaskMonitor monitor) throws IOException, CancelledException {
        DomainFile file = program.getDomainFile();
        PersistAction planned = selectAction(file, mode);
        if (planned == PersistAction.SKIP) {
            return new PersistResult(PersistAction.SKIP, false, null);
        }

        PersistResult transactionOpen =
            refuseIfTransactionOpen(program, TRANSACTION_WAIT_MS, TRANSACTION_POLL_MS);
        if (transactionOpen != null) {
            return transactionOpen;
        }

        program.save(message, monitor);   // always save first → local durability
        program.flushEvents();             // ensure the SAVED event is processed

        if (planned == PersistAction.SAVE) {
            return new PersistResult(PersistAction.SAVE, true, null);
        }

        postSaveHook.accept(program);

        try {
            if (planned == PersistAction.CHECKIN) {
                DefaultCheckinHandler handler =
                    new DefaultCheckinHandler(message + "\n💜🐉✨ (ReVa)", keepCheckedOut, false);
                file.checkin(handler, monitor);
                return new PersistResult(PersistAction.CHECKIN, true, null);
            } else { // ADD_TO_VC
                file.addToVersionControl(message, !keepCheckedOut, monitor);
                return new PersistResult(PersistAction.ADD_TO_VC, true, null);
            }
        } catch (Exception e) {
            // Keep the successful local save; report the checkin failure.
            return new PersistResult(PersistAction.SAVE, true,
                "checkin failed after save: " + e.getMessage());
        }
    }
}
