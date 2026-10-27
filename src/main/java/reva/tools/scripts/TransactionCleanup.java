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
package reva.tools.scripts;

import java.util.function.Predicate;

import db.TerminatedTransactionException;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Ends transactions a script started and never ended. A transaction left
 * open blocks every later checkin and the final save, so the work of the
 * whole session would be lost. What the closed entries contain follows from
 * the run's own parent entry, which {@code PythonScriptExecutor} ends before
 * calling here: a clean run's transaction commits, while a failed or
 * cancelled one has been aborted already and its changes roll back.
 * (If the script ended an entry with commit=false, Ghidra aborts the whole
 * transaction regardless, and that is reported as a rollback.)
 */
final class TransactionCleanup {

    /** Upper bound on {@code endTransaction} attempts while walking down. */
    static final int MAX_END_ATTEMPTS = 64;

    /**
     * The transaction state before the script ran.
     *
     * @param transaction the transaction open before the run, or null
     * @param openEntries how many of its entries were open then
     */
    record Snapshot(TransactionInfo transaction, int openEntries) {
    }

    /**
     * What {@link #closeLeaked} did.
     *
     * @param ended transaction entries ended here
     * @param terminated true when the script left a transaction open that it
     *        had terminated (via {@code forceLock}); Ghidra refuses new
     *        entries then, so it could not be closed
     * @param rolledBack true when entries were ended but the transaction was
     *        already aborted (an entry was ended with commit=false), so its
     *        changes are rolled back rather than committed
     * @param leftOpenForAnalysis true when a transaction is open after the run
     *        but auto-analysis is running, so it was not touched
     */
    record Outcome(int ended, boolean terminated, boolean rolledBack,
            boolean leftOpenForAnalysis) {
        static final Outcome NONE = new Outcome(0, false, false, false);
    }

    private TransactionCleanup() {
    }

    /** Records the transaction state before a script run. */
    static Snapshot snapshot(Program program) {
        TransactionInfo tx = program.getCurrentTransactionInfo();
        return new Snapshot(tx, tx == null ? 0 : tx.getOpenSubTransactions().size());
    }

    /**
     * Closes transaction entries the script left open.
     * <p>
     * When the transaction that was open before the run is still open, only
     * the entries beyond the count recorded before are the script's: exactly
     * that many of the newest entries are ended, and the earlier ones (for
     * example a background analyze-program job's) stay untouched. When no
     * transaction was open before (or that one has since ended), every open
     * entry was opened during the run and all are ended, unless auto-analysis
     * is running: its background command holds an entry for its whole run,
     * so the transaction is left open and reported instead.
     *
     * @param program the program the script ran against
     * @param before the state recorded by {@link #snapshot} before the run
     * @param analysisRunning whether auto-analysis is running on the program
     * @return what was ended and what had to be left open
     */
    static Outcome closeLeaked(Program program, Snapshot before,
            Predicate<Program> analysisRunning) {
        TransactionInfo now = program.getCurrentTransactionInfo();
        if (now == null) {
            return Outcome.NONE;
        }

        int limit;
        if (before.transaction() != null && now == before.transaction()) {
            limit = now.getOpenSubTransactions().size() - before.openEntries();
            if (limit <= 0) {
                return Outcome.NONE;
            }
        } else {
            if (analysisRunning.test(program)) {
                return new Outcome(0, false, false, true);
            }
            limit = Integer.MAX_VALUE;
        }
        boolean aborted = now.getStatus() == TransactionInfo.Status.NOT_DONE_BUT_ABORTED;

        // TransactionInfo.getID() is the database transaction id, not the
        // per-call id endTransaction(int, boolean) expects, and Ghidra has no
        // public way to list the open per-call ids. So open one entry of our
        // own to learn the current id, then walk down from it.
        //
        // Depends on a Ghidra internal: within one open transaction the
        // per-call ids returned by startTransaction are consecutive
        // (DomainObjectDBTransaction.addEntry returns list.size() + baseId - 1).
        // Same code in Ghidra 12.1.3 and 12.2. If a future Ghidra breaks this,
        // TransactionCleanupTest.nestedLeakIsClosed fails. Walking down from
        // the newest id ends the newest entries first, so a limited walk
        // leaves the entries that were open before the run.
        //
        // Known limitation: Ghidra records no owner (thread or caller) for a
        // transaction entry, so entries another thread opened during the run
        // (a concurrent MCP tool call) are indistinguishable from the
        // script's and may be ended here and counted as the script's leak.
        // Concurrent writers to the program during a script run are not
        // supported.
        int probe;
        try {
            probe = program.startTransaction("ReVa: close leaked transaction");
        } catch (TerminatedTransactionException e) {
            // The open transaction was terminated (forceLock); Ghidra refuses
            // new entries, so the ids cannot be learned. Leave it rather
            // than turn the script's result into an exception.
            Msg.warn(TransactionCleanup.class,
                "Script left a terminated transaction open; cannot close it: "
                    + e.getMessage());
            return new Outcome(0, true, false, false);
        }
        program.endTransaction(probe, true);

        int ended = 0;
        int id = probe - 1;
        for (int attempt = 0;
                attempt < MAX_END_ATTEMPTS && ended < limit
                    && program.getCurrentTransactionInfo() != null;
                attempt++, id--) {
            try {
                program.endTransaction(id, true);
                ended++;
            } catch (IllegalStateException e) {
                // Entry already ended by the script, or not part of this
                // transaction ("Transaction not found"): not open, keep walking.
            }
        }
        boolean unfinished = limit == Integer.MAX_VALUE
            ? program.getCurrentTransactionInfo() != null
            : ended < limit;
        if (unfinished) {
            Msg.warn(TransactionCleanup.class,
                "Ended " + ended + " leaked transaction entries but stopped at "
                    + MAX_END_ATTEMPTS + " attempts; the program is still locked "
                    + "by an open transaction.");
        }
        return new Outcome(ended, false, aborted && ended > 0, false);
    }
}
