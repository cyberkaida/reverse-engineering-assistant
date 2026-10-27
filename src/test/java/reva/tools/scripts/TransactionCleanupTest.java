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

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;

import generic.jar.ResourceFile;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import reva.RevaHeadlessIntegrationTestBase;
import reva.tools.DatabaseAvailability;
import reva.tools.scripts.PythonScriptExecutor.Result;

/**
 * Leaked-transaction cleanup around a script run, against a real
 * {@code ProgramDB}. The runner is a stub standing in for a PyGhidra script
 * that owns (and here, mishandles) its transactions.
 */
public class TransactionCleanupTest extends RevaHeadlessIntegrationTestBase {

    private final ResourceFile scriptFile = mock(ResourceFile.class);

    private Result runScript(PythonScriptExecutor.ScriptRunner runner)
            throws Exception {
        return new PythonScriptExecutor(runner)
            .execute(scriptFile, program, null, 60, 1024);
    }

    @Test
    public void failedScriptRollsBackEverythingIncludingTheLeak() throws Exception {
        Address addr = program.getAddressFactory().getDefaultAddressSpace()
            .getAddress(0x01000010);
        Result r = runScript((f, p, t, out, err, monitor) -> {
            p.startTransaction("x");
            p.getSymbolTable().createLabel(addr, "leaked_label", SourceType.USER_DEFINED);
            throw new RuntimeException("script failed before endTransaction");
        });

        assertNull("no transaction may stay open",
            program.getCurrentTransactionInfo());
        assertEquals(1, r.leakedTransactions());
        assertNotNull("the script's failure is still reported", r.executionError());
        assertFalse("the parent entry was aborted", r.parentCommitted());
        assertTrue(r.transactionRolledBack());
        assertNull("a failed run rolls back: the leaked entry's edit is gone",
            program.getSymbolTable().getGlobalSymbol("leaked_label", addr));
    }

    @Test
    public void pythonTracebackRollsBackTheEditsMadeBeforeTheRaise() throws Exception {
        // A real PyGhidra script runner never throws for a Python exception:
        // pyghidra/script.py catches it and prints the traceback to the error
        // writer, returning normally. The label created before the raise must
        // not survive the run.
        Address addr = program.getAddressFactory().getDefaultAddressSpace()
            .getAddress(0x01000020);
        Result r = runScript((f, p, t, out, err, monitor) -> {
            p.getSymbolTable().createLabel(
                addr, "created_then_raised", SourceType.USER_DEFINED);
            err.print("Traceback (most recent call last):\n"
                + "  File \"<string>\", line 2, in <module>\n"
                + "    raise ValueError('intentional')\n"
                + "ValueError: intentional\n");
        });

        assertNull("no transaction may stay open",
            program.getCurrentTransactionInfo());
        assertFalse("the parent entry must not commit a failed script",
            r.parentCommitted());
        assertNotNull("the traceback is reported as the failure", r.executionError());
        assertNull("the traceback rolled the label back",
            program.getSymbolTable().getGlobalSymbol("created_then_raised", addr));
    }

    @Test
    public void nestedLeakIsClosed() throws Exception {
        // Pins the assumption that per-call transaction ids are consecutive.
        Result r = runScript((f, p, t, out, err, monitor) -> {
            p.startTransaction("outer");
            p.startTransaction("inner");
        });

        assertNull(program.getCurrentTransactionInfo());
        assertEquals(2, r.leakedTransactions());
    }

    @Test
    public void partiallyEndedNestedLeakIsClosed() throws Exception {
        Result r = runScript((f, p, t, out, err, monitor) -> {
            p.startTransaction("outer");
            int inner = p.startTransaction("inner");
            p.endTransaction(inner, true);
        });

        assertNull(program.getCurrentTransactionInfo());
        assertEquals(1, r.leakedTransactions());
    }

    @Test
    public void wellBehavedScriptReportsNoLeak() throws Exception {
        Result r = runScript((f, p, t, out, err, monitor) -> {
            int tx = p.startTransaction("ok");
            p.endTransaction(tx, true);
        });

        assertNull(program.getCurrentTransactionInfo());
        assertEquals(0, r.leakedTransactions());
    }

    @Test
    public void preexistingTransactionIsLeftAlone() {
        // run-script itself refuses to start while a transaction is open
        // (PythonScriptExecutorTest.busyProgramIsRefusedWithoutRunning), but
        // closeLeaked still protects a transaction another writer opened
        // before the snapshot: only entries beyond the count are ended.
        int outer = program.startTransaction("opened before the script");
        try {
            TransactionCleanup.Snapshot before =
                TransactionCleanup.snapshot(program);
            int tx = program.startTransaction("script");
            program.endTransaction(tx, true);

            TransactionCleanup.Outcome o =
                TransactionCleanup.closeLeaked(program, before, p -> false);

            assertEquals(0, o.ended());
            assertNotNull("a transaction open before the script stays open",
                program.getCurrentTransactionInfo());
        } finally {
            program.endTransaction(outer, true);
        }
        assertNull(program.getCurrentTransactionInfo());
    }

    @Test
    public void leakInsideOuterTransactionEndsOnlyTheLeak() {
        // As when a background analyze-program job holds "ReVa: Auto Analysis"
        // open: an entry opened after the snapshot joins that transaction and
        // only the extra entry may be ended.
        int outer = program.startTransaction("opened before the script");
        try {
            TransactionCleanup.Snapshot before =
                TransactionCleanup.snapshot(program);
            program.startTransaction("leaked");

            TransactionCleanup.Outcome o =
                TransactionCleanup.closeLeaked(program, before, p -> false);

            TransactionInfo tx = program.getCurrentTransactionInfo();
            assertNotNull("the outer transaction stays open", tx);
            assertEquals("only the outer entry is left",
                List.of("opened before the script"), tx.getOpenSubTransactions());
            assertEquals(1, o.ended());
        } finally {
            program.endTransaction(outer, true);
        }
        assertNull(program.getCurrentTransactionInfo());
    }

    @Test
    public void leaksInsideTwoOuterEntriesEndOnlyTheNewest() {
        int outerA = program.startTransaction("outer A");
        int outerB = program.startTransaction("outer B");
        try {
            TransactionCleanup.Snapshot before =
                TransactionCleanup.snapshot(program);
            program.startTransaction("leak 1");
            int ok = program.startTransaction("ended");
            program.endTransaction(ok, true);
            program.startTransaction("leak 2");

            TransactionCleanup.Outcome o =
                TransactionCleanup.closeLeaked(program, before, p -> false);

            assertEquals(2, o.ended());
            assertEquals(List.of("outer A", "outer B"),
                program.getCurrentTransactionInfo().getOpenSubTransactions());
        } finally {
            program.endTransaction(outerB, true);
            program.endTransaction(outerA, true);
        }
        assertNull(program.getCurrentTransactionInfo());
    }

    @Test
    public void leakInsideOuterIsEndedEvenWhileAnalysisRuns() {
        // AnalysisJobRunner's job is itself auto-analysis; the running-analysis
        // guard applies only when no transaction was open before the snapshot.
        int outer = program.startTransaction("ReVa: Auto Analysis");
        try {
            TransactionCleanup.Snapshot before =
                TransactionCleanup.snapshot(program);
            program.startTransaction("leaked");

            TransactionCleanup.Outcome o =
                TransactionCleanup.closeLeaked(program, before, p -> true);

            assertEquals(1, o.ended());
            assertFalse(o.leftOpenForAnalysis());
            assertEquals(List.of("ReVa: Auto Analysis"),
                program.getCurrentTransactionInfo().getOpenSubTransactions());
        } finally {
            program.endTransaction(outer, true);
        }
    }

    @Test
    public void abortedLeakIsReportedAsRolledBack() throws Exception {
        Result r = runScript((f, p, t, out, err, monitor) -> {
            p.startTransaction("leaked");
            int inner = p.startTransaction("inner");
            p.endTransaction(inner, false);
        });

        assertNull(program.getCurrentTransactionInfo());
        assertEquals(1, r.leakedTransactions());
        assertTrue(r.transactionRolledBack());
        assertFalse("the aborted run did not commit", r.parentCommitted());
        assertNotNull("the script's own abort is reported", r.executionError());
        Map<String, Object> out =
            ScriptToolProvider.buildRunResult(program, r, "inline", "<inline>");
        assertEquals("the group transaction aborted: report the rollback",
            "rolled back", out.get("transaction"));
        String stderr = (String) out.get("stderr");
        assertTrue(stderr, stderr.contains("rolled back"));
        assertFalse(stderr, stderr.contains("committed."));
    }

    @Test
    public void scriptAbortWithoutALeakIsReportedAsRolledBack() throws Exception {
        // The script ends its own entry with commit=false and leaves nothing
        // open. The parent entry then commits into an already-aborted
        // transaction: Ghidra rolls the whole thing back, so the run must be
        // reported as a failure, not as a committed run.
        Address addr = program.getAddressFactory().getDefaultAddressSpace()
            .getAddress(0x01000020);
        Result r = runScript((f, p, t, out, err, monitor) -> {
            int tx = p.startTransaction("script");
            p.getSymbolTable().createLabel(addr, "aborted_label", SourceType.USER_DEFINED);
            p.endTransaction(tx, false);
        });

        assertNull("the parent entry closed the transaction",
            program.getCurrentTransactionInfo());
        assertEquals(0, r.leakedTransactions());
        assertFalse("an aborted run did not commit", r.parentCommitted());
        assertTrue(r.transactionRolledBack());
        assertNotNull("the abort is reported as a failure", r.executionError());
        assertNull("the label was rolled back",
            program.getSymbolTable().getGlobalSymbol("aborted_label", addr));

        Map<String, Object> out =
            ScriptToolProvider.buildRunResult(program, r, "inline", "<inline>");
        assertEquals(Boolean.FALSE, out.get("success"));
        assertEquals("rolled back", out.get("transaction"));
        String stderr = (String) out.get("stderr");
        assertTrue(stderr, stderr.contains("rolled back"));
    }

    @Test
    public void runningAnalysisTransactionIsNotWalked() throws Exception {
        // Stands in for GUI auto-analysis the script's edits set off: its
        // background command holds a transaction entry while it runs. The
        // analysis starts with the script, so the pre-run availability check
        // sees it stopped and the run is not refused.
        AtomicBoolean analysisStarted = new AtomicBoolean();
        AtomicInteger analysisEntry = new AtomicInteger();
        Result r = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> {
                analysisStarted.set(true);
                analysisEntry.set(p.startTransaction("Auto Analysis"));
            },
            p -> analysisStarted.get(), 5_000, 20)
            .execute(scriptFile, program, null, 60, 1024);
        try {
            assertEquals(0, r.leakedTransactions());
            assertTrue(r.transactionLeftOpen());
            assertEquals(List.of("Auto Analysis"),
                program.getCurrentTransactionInfo().getOpenSubTransactions());

            Map<String, Object> out =
                ScriptToolProvider.buildRunResult(program, r, "inline", "<inline>");
            assertEquals(Boolean.TRUE, out.get("transactionOpen"));
            assertFalse(out.containsKey("transactionLeaked"));
            assertEquals("A transaction is still open while auto-analysis runs; "
                + "ReVa did not close it.", out.get("stderr"));
        } finally {
            program.endTransaction(analysisEntry.get(), true);
        }
        assertNull(program.getCurrentTransactionInfo());
    }

    @Test
    public void analysisCheckIsNotConsultedWhenNothingIsLeftOpen() throws Exception {
        // Only the pre-run availability check may ask: with nothing left open
        // after the run, closeLeaked has no reason to.
        AtomicInteger consulted = new AtomicInteger();
        Result r = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> { },
            p -> {
                consulted.incrementAndGet();
                return false;
            }, 0, 1)
            .execute(scriptFile, program, null, 60, 1024);
        assertNull(r.executionError());
        assertFalse(r.transactionLeftOpen());
        assertEquals(1, consulted.get());
    }

    @Test
    public void realAnalysisCheckIsFalseWithoutAManager() {
        assertFalse(DatabaseAvailability.isAutoAnalysisRunning(program));
    }

    @Test
    public void terminatedLeakDoesNotThrowFromExecute() throws Exception {
        // forceLock terminates the open transaction; Ghidra then refuses new
        // transactions, so the cleanup cannot probe. It must not turn the
        // script result into an exception.
        AtomicInteger leaked = new AtomicInteger();
        Result r = runScript((f, p, t, out, err, monitor) -> {
            leaked.set(p.startTransaction("x"));
            p.forceLock(false, "test");
            p.unlock();
        });
        try {
            assertNull(r.executionError());
            assertEquals(0, r.leakedTransactions());
            assertTrue("the unclosable terminated transaction is reported",
                r.transactionTerminated());
        } finally {
            program.endTransaction(leaked.get(), true);
        }
        assertNull(program.getCurrentTransactionInfo());
    }

    @Test
    public void closeLeakedIsNoOpWhenNothingIsOpen() {
        TransactionCleanup.Outcome o = TransactionCleanup.closeLeaked(
            program, TransactionCleanup.snapshot(program), p -> true);
        assertEquals(0, o.ended());
        assertFalse(o.terminated());
    }

    @Test
    public void leakBeyondBoundStopsAtBound() throws Exception {
        int leakedCount = TransactionCleanup.MAX_END_ATTEMPTS + 6;
        int[] ids = new int[leakedCount];
        Result r = runScript((f, p, t, out, err, monitor) -> {
            for (int i = 0; i < leakedCount; i++) {
                ids[i] = p.startTransaction("leak " + i);
            }
        });

        assertEquals(TransactionCleanup.MAX_END_ATTEMPTS, r.leakedTransactions());
        assertFalse(r.transactionTerminated());
        assertNotNull("entries past the bound stay open",
            program.getCurrentTransactionInfo());
        // The walk ends the newest entries first; the oldest six remain.
        for (int i = 5; i >= 0; i--) {
            program.endTransaction(ids[i], true);
        }
        assertNull(program.getCurrentTransactionInfo());
    }

    @Test
    public void buildRunResultReportsLeak() {
        Result r = new Result("", "Traceback (most recent call last):\n", false, false,
            5, false, null, 1, false, false, false, true);
        Map<String, Object> out =
            ScriptToolProvider.buildRunResult(program, r, "inline", "<inline>");

        assertEquals(Boolean.TRUE, out.get("transactionLeaked"));
        String stderr = (String) out.get("stderr");
        assertTrue(stderr, stderr.startsWith("Traceback (most recent call last):\n"));
        assertTrue(stderr, stderr.contains(
            "ReVa closed 1 transaction(s) the script left open; changes were "
            + "committed. Scripts must end every transaction they start (try/finally)."));
        assertEquals(Boolean.FALSE, out.get("success"));
    }

    @Test
    public void buildRunResultReportsTerminatedTransaction() {
        Result r = new Result("", "", false, false, 5, false, null, 0, true, false, false,
            true);
        Map<String, Object> out =
            ScriptToolProvider.buildRunResult(program, r, "inline", "<inline>");

        assertEquals(Boolean.TRUE, out.get("transactionTerminated"));
        assertFalse("transactionLeaked keeps its meaning: entries ReVa closed",
            out.containsKey("transactionLeaked"));
        assertEquals("ReVa could not close a transaction the script terminated "
            + "with forceLock; the program may stay locked until the session ends.",
            out.get("stderr"));
    }

    @Test
    public void buildRunResultOmitsLeakFlagWhenNone() {
        Result r = new Result("hi", "", false, false, 5, false, null, 0, false, false, false,
            true);
        Map<String, Object> out =
            ScriptToolProvider.buildRunResult(program, r, "inline", "<inline>");

        assertFalse(out.containsKey("transactionLeaked"));
        assertFalse(out.containsKey("transactionTerminated"));
        assertEquals("", out.get("stderr"));
        assertEquals(Boolean.TRUE, out.get("success"));
    }

    @Test
    public void runResultReportsTransactionState() {
        Result committed = new Result("", "", false, false, 5, false, null,
            0, false, false, false, true);
        assertEquals("committed", ScriptToolProvider
            .buildRunResult(program, committed, "inline", "<inline>")
            .get("transaction"));

        Result rolledBack = new Result("", "", false, false, 5, false, null,
            0, false, false, false, false);
        assertEquals("rolled back", ScriptToolProvider
            .buildRunResult(program, rolledBack, "inline", "<inline>")
            .get("transaction"));

        Result leftOpenForAnalysis = new Result("", "", false, false, 5, false, null,
            0, false, false, true, true);
        assertEquals("open", ScriptToolProvider
            .buildRunResult(program, leftOpenForAnalysis, "inline", "<inline>")
            .get("transaction"));

        // The script ended its own entry with commit=false: the parent entry
        // still committed, but Ghidra aborted the whole transaction, so the
        // reported outcome must be the rollback, not the parent's commit flag.
        Result abortedByScript = new Result("", "", false, false, 5, false, null,
            1, false, true, false, true);
        assertEquals("rolled back", ScriptToolProvider
            .buildRunResult(program, abortedByScript, "inline", "<inline>")
            .get("transaction"));
    }
}
