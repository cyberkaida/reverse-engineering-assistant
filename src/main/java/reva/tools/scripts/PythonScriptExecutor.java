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

import java.io.PrintWriter;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

import db.TerminatedTransactionException;
import generic.jar.ResourceFile;
import ghidra.framework.model.DomainObjectLockedException;
import ghidra.framework.model.TransactionInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import reva.tools.DatabaseAvailability;
import reva.tools.ProgramBusyException;

/**
 * Executes a Ghidra Python script and returns a structured result with
 * captured stdout/stderr (capped), duration, timeout flag, and any thrown
 * exception. The Ghidra-specific dance (provider lookup, bundle host refcount,
 * {@code GhidraState} construction, {@code script.execute}) is delegated to an
 * injected {@link ScriptRunner} so this class stays unit-testable without a
 * live PyGhidra runtime.
 */
public class PythonScriptExecutor {

    /**
     * Outcome of a script run. {@code executionError} is non-null when the
     * script (or runner) threw a non-{@link PyGhidraNotAvailableException}
     * exception, when PyGhidra caught a Python exception and wrote its
     * traceback to stderr, when the run was refused because the program was
     * still busy after the wait ({@link ProgramBusyException}), or when the
     * script aborted the run's transaction itself; the executor captures it so
     * the tool layer can return a normal result with {@code success: false}
     * rather than an MCP-level error.
     * {@link PyGhidraNotAvailableException} is always rethrown.
     * <p>
     * The whole run happens inside one parent transaction: a clean exit ends
     * the parent entry with commit=true, so every change the script made lands
     * as a single undo unit; an exception or a timeout ends it with
     * commit=false, which aborts the whole transaction and rolls every change
     * back. Scripts therefore need no transaction of their own, but may still
     * open one: their entries share the parent transaction, and a script that
     * ends one with commit=false aborts the whole unit (all-or-nothing); that
     * is detected before the parent entry is ended, so it is reported as a
     * failure even when the script leaves nothing open.
     * {@code parentCommitted} is true when the parent entry was ended with
     * commit=true, which is never the case once the run has been aborted.
     * <p>
     * {@code leakedTransactions} counts the transaction entries the script
     * left open that the executor ended after the run; 0 when none.
     * {@code transactionTerminated} is true when the script left open a
     * transaction it had terminated (forceLock), which cannot be closed.
     * {@code transactionRolledBack} is true when the transaction was aborted
     * — a failed run, a script that ended an entry with commit=false, or a
     * script that leaked entries into an already-aborted transaction — so the
     * changes are rolled back, not committed.
     * {@code transactionLeftOpen} is true when a transaction was still open
     * after the run while auto-analysis was running, so ReVa left it alone
     * (the analysis owns an entry).
     */
    public static record Result(
        String stdout,
        String stderr,
        boolean stdoutTruncated,
        boolean stderrTruncated,
        long durationMs,
        boolean timedOut,
        Throwable executionError,
        int leakedTransactions,
        boolean transactionTerminated,
        boolean transactionRolledBack,
        boolean transactionLeftOpen,
        boolean parentCommitted
    ) {}

    /**
     * Performs the actual script invocation. Production wires this to the
     * Ghidra script provider; tests inject a fake.
     */
    @FunctionalInterface
    public interface ScriptRunner {
        void run(
            ResourceFile scriptFile,
            Program program,
            PluginTool tool,
            PrintWriter outWriter,
            PrintWriter errWriter,
            TaskMonitor monitor
        ) throws PyGhidraNotAvailableException, Exception;
    }

    /** {@code executionError} message when the script aborted its own run. */
    static final String SCRIPT_ABORTED_MESSAGE =
        "The script ended a transaction with commit=false, which aborts the "
            + "whole run: its changes were rolled back.";

    /** {@code executionError} message when PyGhidra reports a Python traceback. */
    static final String PYTHON_RAISED_MESSAGE =
        "The script raised a Python exception; see stderr for the traceback.";

    /**
     * Exact marker PyGhidra writes to a script's error writer when a Python
     * exception escapes it. PyGhidra's own runner ({@code pyghidra/script.py})
     * catches the exception, filters the traceback and prints it with
     * {@code printerr}, then returns normally — so this marker in the captured
     * stderr, not a thrown Java exception, is what says the script failed.
     */
    public static final String PYTHON_TRACEBACK_MARKER =
        "Traceback (most recent call last)";

    /**
     * Whether captured stderr carries a Python traceback. The executor and the
     * run-script result builder share this one check so {@code success} and
     * {@code transaction} can never disagree about a Python failure.
     */
    public static boolean containsPythonTraceback(String stderr) {
        return stderr != null && stderr.contains(PYTHON_TRACEBACK_MARKER);
    }

    private final ScriptRunner runner;
    private final Predicate<Program> analysisRunning;
    private final long awaitMs;
    private final long pollMs;

    /**
     * Poll interval for the availability wait: the 200 ms default
     * {@link DatabaseAvailability} documents for its own wait.
     */
    private static final long DEFAULT_POLL_MS = 200;

    public PythonScriptExecutor(ScriptRunner runner) {
        this(runner, DatabaseAvailability::isAutoAnalysisRunning,
            DatabaseAvailability.DEFAULT_DEADLINE_MS, DEFAULT_POLL_MS);
    }

    /**
     * Tests substitute the auto-analysis check and shorten the wait for the
     * program to become modifiable.
     *
     * @param awaitMs how long {@link DatabaseAvailability#awaitModifiable}
     *        waits for an in-flight writer; 0 checks once without waiting
     * @param pollMs how often the wait rechecks
     */
    PythonScriptExecutor(ScriptRunner runner, Predicate<Program> analysisRunning,
            long awaitMs, long pollMs) {
        this.runner = Objects.requireNonNull(runner, "runner");
        this.analysisRunning = Objects.requireNonNull(analysisRunning, "analysisRunning");
        this.awaitMs = awaitMs;
        this.pollMs = pollMs;
    }

    public Result execute(
            ResourceFile scriptFile,
            Program program,
            PluginTool tool,
            int timeoutSeconds,
            int outputCapChars) throws PyGhidraNotAvailableException {

        if (timeoutSeconds <= 0) {
            throw new IllegalArgumentException(
                "timeoutSeconds must be positive, got: " + timeoutSeconds);
        }

        // One writer at a time: this run's parent transaction, the
        // direct-write tools' short transactions and auto-analysis all exclude
        // each other. Joining a transaction someone else holds would make this
        // run's undo unit and rollback depend on a stranger's, so wait for it
        // to finish — a sibling tool call is usually done in seconds — and
        // refuse only when the wait runs out.
        DatabaseAvailability.WaitOutcome availability = DatabaseAvailability
            .awaitModifiable(program, analysisRunning, awaitMs, pollMs);
        if (!availability.modifiable()) {
            return busyResult(availability.reason());
        }

        // Narrowing the race between the wait and the start below: if another
        // writer's transaction appeared in between, refuse rather than join
        // it. Joining would make this run's rollback abort that writer's
        // transaction.
        TransactionInfo appeared = program.getCurrentTransactionInfo();
        if (appeared != null) {
            return busyResult(
                "a transaction is open (" + appeared.getDescription() + ")");
        }

        CappedWriter outCap = new CappedWriter(outputCapChars);
        CappedWriter errCap = new CappedWriter(outputCapChars);
        PrintWriter outPw = new PrintWriter(outCap);
        PrintWriter errPw = new PrintWriter(errCap);

        TimeoutTaskMonitor monitor =
            TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);

        long start = System.currentTimeMillis();
        Throwable execError = null;
        // The run is one parent transaction. A clean exit commits every change
        // the script made as a single undo entry; an exception or a timeout
        // ends the parent entry with commit=false, which aborts the whole
        // transaction, so nothing the script did survives. Entries the script
        // leaked are closed only after the parent entry is gone, so
        // closeLeaked never touches it.
        TransactionCleanup.Snapshot before = TransactionCleanup.snapshot(program);
        int parentTx;
        try {
            parentTx = program.startTransaction("run-script: " + scriptFile.getName());
        } catch (DomainObjectLockedException e) {
            // A background save holds the program lock. Ghidra's own start
            // path normally waits it out, and the availability wait cannot
            // see it — the lock is only observable by attempting the
            // transaction — so a direct throw must not surface as an MCP
            // error.
            return busyResult(
                "another operation holds the program lock (" + e.getMessage() + ")");
        } catch (TerminatedTransactionException e) {
            // Not busy: a read-only or force-terminated program never becomes
            // modifiable, so this must not teach the caller to retry.
            return unmodifiableResult("Program cannot be modified: "
                + e.getMessage() + ". run-script needs a writable program; a "
                + "read-only or force-terminated program cannot take a "
                + "transaction.");
        }

        // Ownership. Ghidra records no owner (thread or caller) for a
        // transaction entry — TransactionInfo exposes only id, description,
        // status and the open entries' descriptions — so the best available
        // signal is the open-entry count: nothing was open before, hence more
        // than one open entry means a stranger's transaction appeared between
        // the checks above and our entry joined it. Nothing has run yet, so
        // our entry holds no changes: end it with commit=true, which leaves
        // the stranger's transaction intact (commit=false here would abort
        // it), and refuse.
        TransactionInfo afterStart = program.getCurrentTransactionInfo();
        if (afterStart != null && afterStart.getOpenSubTransactions().size() > 1) {
            try {
                program.endTransaction(parentTx, true);
            } catch (IllegalStateException e) {
                // Entry already gone; nothing left to release.
            }
            return busyResult("another writer opened a transaction while "
                + "run-script was starting (nothing ran)");
        }
        boolean success = false;
        boolean abortedByScript = false;
        TransactionCleanup.Outcome cleanup = TransactionCleanup.Outcome.NONE;
        try {
            runner.run(scriptFile, program, tool, outPw, errPw, monitor);
            success = !monitor.isCancelled();
        } catch (PyGhidraNotAvailableException e) {
            throw e;
        } catch (Exception e) {
            execError = e;
        } finally {
            // PyGhidra's runner swallows Python exceptions: it prints the
            // traceback to the error writer and returns normally, so the
            // writer must be flushed and inspected before the commit decision
            // — otherwise a failed script's partial edits would be committed.
            outPw.flush();
            errPw.flush();
            if (monitor.isCancelled()) {
                execError = new IllegalStateException(
                    "script timed out after " + timeoutSeconds + " seconds");
            }
            if (containsPythonTraceback(errCap.getCapturedString())) {
                success = false;
                if (execError == null) {
                    execError = new IllegalStateException(PYTHON_RAISED_MESSAGE);
                }
            }
            // In a finally so the entry is ended however run() exits: an
            // Error must not leave the program locked. The parent entry goes
            // first, so closeLeaked never ends it.
            //
            // Sample the status before ending the parent entry: a script that
            // ended an entry with commit=false aborted the whole transaction,
            // and ending the parent entry with commit=true would still be
            // rolled back — silently, unless it is reported as a failure.
            TransactionInfo stillOpen = program.getCurrentTransactionInfo();
            abortedByScript = stillOpen != null
                && stillOpen.getStatus() == TransactionInfo.Status.NOT_DONE_BUT_ABORTED;
            success = success && !abortedByScript;
            program.endTransaction(parentTx, success);
            cleanup = TransactionCleanup.closeLeaked(program, before, analysisRunning);
        }
        // A terminated transaction also reads as aborted here, but a forceLock
        // is reported through transactionTerminated and its outcome is not
        // necessarily a rollback.
        boolean scriptAborted = abortedByScript && !cleanup.terminated();
        if (scriptAborted && execError == null) {
            execError = new IllegalStateException(SCRIPT_ABORTED_MESSAGE);
        }
        long duration = System.currentTimeMillis() - start;

        return new Result(
            outCap.getCapturedString(),
            errCap.getCapturedString(),
            outCap.isTruncated(),
            errCap.isTruncated(),
            duration,
            monitor.isCancelled(),
            execError,
            cleanup.ended(),
            cleanup.terminated(),
            scriptAborted || cleanup.rolledBack(),
            cleanup.leftOpenForAnalysis(),
            success);
    }

    /**
     * Result of a run refused because the program was busy: nothing ran and
     * the caller may retry once the in-flight operation finishes. Carrying
     * {@link ProgramBusyException} lets the tool layer mark the result
     * {@code busy: true} / {@code transaction: "refused"} instead of a plain
     * failure.
     */
    private static Result busyResult(String reason) {
        return refusedResult(new ProgramBusyException(reason));
    }

    /** Result of a run refused for a reason that retrying cannot fix. */
    private static Result unmodifiableResult(String message) {
        return refusedResult(new IllegalStateException(message));
    }

    private static Result refusedResult(Throwable error) {
        return new Result("", "", false, false, 0, false,
            error, 0, false, false, false, false);
    }
}
