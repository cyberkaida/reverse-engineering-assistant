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

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Before;
import org.junit.Test;

import generic.jar.ResourceFile;
import ghidra.framework.model.TransactionInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import reva.tools.ProgramBusyException;
import reva.tools.scripts.PythonScriptExecutor.Result;
import reva.tools.scripts.PythonScriptExecutor.ScriptRunner;

/**
 * Unit tests for {@link PythonScriptExecutor}.
 *
 * The executor owns output capping, timing, and error capture; it delegates
 * the Ghidra-specific dance (provider lookup, bundle host refcount, GhidraState
 * construction, script.execute) to an injected {@link ScriptRunner}. These
 * tests inject a fake runner so we can verify the wrapper behavior without
 * needing a real PyGhidra runtime.
 */
public class PythonScriptExecutorTest {

    private ResourceFile scriptFile;
    private Program program;

    @Before
    public void setUp() {
        scriptFile = mock(ResourceFile.class);
        program = mock(Program.class);
    }

    @Test
    public void capturesStdoutFromRunner() throws Exception {
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> out.print("hello"));
        Result r = exec.execute(scriptFile, program, null, 60, 1024);
        assertEquals("hello", r.stdout());
        assertEquals("", r.stderr());
        assertFalse(r.stdoutTruncated());
        assertFalse(r.stderrTruncated());
        assertNull(r.executionError());
        assertFalse(r.timedOut());
    }

    @Test
    public void capturesStderrFromRunner() throws Exception {
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> err.print("oops"));
        Result r = exec.execute(scriptFile, program, null, 60, 1024);
        assertEquals("", r.stdout());
        assertEquals("oops", r.stderr());
    }

    @Test
    public void truncatesStdoutAtCap() throws Exception {
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> {
                for (int i = 0; i < 1000; i++) out.print("x");
                out.flush();
            });
        Result r = exec.execute(scriptFile, program, null, 60, 10);
        assertEquals(10, r.stdout().length());
        assertTrue(r.stdoutTruncated());
    }

    @Test
    public void truncatesStderrIndependently() throws Exception {
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> {
                out.print("short");
                for (int i = 0; i < 100; i++) err.print("y");
                err.flush();
            });
        Result r = exec.execute(scriptFile, program, null, 60, 5);
        assertEquals("short", r.stdout());
        assertFalse(r.stdoutTruncated());
        assertEquals(5, r.stderr().length());
        assertTrue(r.stderrTruncated());
    }

    @Test
    public void runnerRuntimeExceptionIsCapturedAsExecutionError() throws Exception {
        RuntimeException boom = new RuntimeException("script blew up");
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> { throw boom; });
        Result r = exec.execute(scriptFile, program, null, 60, 1024);
        assertSame(boom, r.executionError());
        // and the executor itself did not propagate it
    }

    @Test
    public void runnerCheckedExceptionIsCapturedAsExecutionError() throws Exception {
        Exception checked = new Exception("checked failure");
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> { throw checked; });
        Result r = exec.execute(scriptFile, program, null, 60, 1024);
        assertSame(checked, r.executionError());
    }

    @Test(expected = PyGhidraNotAvailableException.class)
    public void pyGhidraNotAvailableIsRethrownNotCaptured() throws Exception {
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> {
                throw new PyGhidraNotAvailableException("not wired");
            });
        exec.execute(scriptFile, program, null, 60, 1024);
    }

    @Test
    public void monitorCancelByRunnerReportsTimedOut() throws Exception {
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> {
                monitor.cancel();
            });
        Result r = exec.execute(scriptFile, program, null, 60, 1024);
        assertTrue(r.timedOut());
    }

    @Test
    public void timedOutIsFalseWhenMonitorNotCancelled() throws Exception {
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> { /* no-op */ });
        Result r = exec.execute(scriptFile, program, null, 60, 1024);
        assertFalse(r.timedOut());
    }

    @Test
    public void returnsPromptlyWhenScriptFinishesBeforeTimeout() throws Exception {
        // Regression guard: the executor schedules a TimeoutTaskMonitor that
        // fires after `timeoutSeconds`, but it must NOT wait for that monitor
        // — it must return as soon as the runner returns. If someone ever
        // rewrites this to await the timeout (e.g. join on a timer thread,
        // or block on a Future with the timeout deadline), the wall-clock
        // here jumps from milliseconds to ~60s and this test fails.
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> Thread.sleep(100));

        long startNs = System.nanoTime();
        Result r = exec.execute(scriptFile, program, null, 60, 1024);
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs);

        assertFalse("script finished before timeout, should not be flagged",
            r.timedOut());
        assertNull("no execution error expected", r.executionError());
        // Script slept 100ms; timeout was 60s. Generous slack for CI jitter,
        // but well below the timeout — the failure mode we care about is
        // "the executor blocked for the full timeout".
        assertTrue(
            "execute() returned in " + elapsedMs + "ms but timeout was 60s; "
            + "expected prompt return after runner completed",
            elapsedMs < 5_000);
    }

    @Test
    public void successCommitsParentTransactionOnce() throws Exception {
        when(program.startTransaction(anyString())).thenReturn(7);
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> out.print("ok"));
        Result r = exec.execute(scriptFile, program, null, 60, 1024);
        verify(program).startTransaction(argThat(s -> s.startsWith("run-script:")));
        verify(program).endTransaction(7, true);
        assertTrue(r.parentCommitted());
    }

    @Test
    public void exceptionRollsBackParentTransaction() throws Exception {
        when(program.startTransaction(anyString())).thenReturn(9);
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> {
                throw new RuntimeException("boom");
            });
        Result r = exec.execute(scriptFile, program, null, 60, 1024);
        verify(program).endTransaction(9, false);
        assertFalse(r.parentCommitted());
        assertNotNull(r.executionError());
    }

    @Test
    public void pythonTracebackInStderrRollsBackParentTransaction() throws Exception {
        // PyGhidra's runner catches Python exceptions, writes the traceback to
        // the error writer and returns normally: execError stays null. The
        // traceback must still abort the parent entry, or the failed script's
        // partial edits would be committed.
        when(program.startTransaction(anyString())).thenReturn(11);
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> {
                err.print("Traceback (most recent call last):\n"
                    + "  File \"<string>\", line 1, in <module>\n"
                    + "ValueError: intentional test failure\n");
                // intentionally no flush: the executor must flush before it
                // decides whether to commit
            });
        Result r = exec.execute(scriptFile, program, null, 60, 1024);

        verify(program).endTransaction(11, false);
        assertFalse("a Python traceback must not commit", r.parentCommitted());
        assertNotNull("the swallowed exception is still reported", r.executionError());
        assertTrue(r.executionError().getMessage().contains("Python exception"));
        assertTrue("the traceback is in the captured stderr: " + r.stderr(),
            r.stderr().contains("ValueError"));
    }

    @Test
    public void plainStderrWithoutTracebackStillCommits() throws Exception {
        when(program.startTransaction(anyString())).thenReturn(12);
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> {
                err.print("warning: deprecated API used\n");
                out.print("ok\n");
            });
        Result r = exec.execute(scriptFile, program, null, 60, 1024);

        verify(program).endTransaction(12, true);
        assertTrue(r.parentCommitted());
        assertNull(r.executionError());
    }

    @Test
    public void timeoutRollsBackParentTransaction() throws Exception {
        when(program.startTransaction(anyString())).thenReturn(3);
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> monitor.cancel());
        Result r = exec.execute(scriptFile, program, null, 60, 1024);
        verify(program).endTransaction(3, false);
        assertTrue(r.timedOut());
        assertNotNull(r.executionError());
        assertTrue(r.executionError().getMessage(), r.executionError().getMessage().contains("60"));
    }

    @Test
    public void lockedProgramIsRefusedAsBusyForTheSaveLock() throws Exception {
        // The availability wait cannot see the save lock — it is only
        // observable by attempting the transaction — so the catch still maps
        // it to the busy result the tool layer marks busy:true.
        when(program.startTransaction(anyString()))
            .thenThrow(new ghidra.framework.model.DomainObjectLockedException("save"));
        AtomicReference<Boolean> ran = new AtomicReference<>(false);
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> ran.set(true));
        Result r = exec.execute(scriptFile, program, null, 60, 1024);

        assertFalse("the script must not run while the program is locked", ran.get());
        assertNotNull("a lock must not escape as an MCP error", r.executionError());
        assertTrue(r.executionError() instanceof ProgramBusyException);
        String message = r.executionError().getMessage();
        assertTrue(message, message.contains("lock"));
        assertFalse(r.parentCommitted());
    }

    @Test
    public void readOnlyProgramIsRefusedAsUnmodifiable() throws Exception {
        when(program.startTransaction(anyString()))
            .thenThrow(new db.TerminatedTransactionException(
                "Transaction not permitted: read-only"));
        AtomicReference<Boolean> ran = new AtomicReference<>(false);
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> ran.set(true));
        Result r = exec.execute(scriptFile, program, null, 60, 1024);

        assertFalse("the script must not run against a read-only program", ran.get());
        assertNotNull("the refusal is a normal result, not an MCP error",
            r.executionError());
        String message = r.executionError().getMessage();
        assertTrue(message, message.contains("cannot be modified"));
        assertTrue(message, message.contains("read-only"));
    }

    @Test
    public void transactionAppearingBeforeStartIsRefused() throws Exception {
        TransactionInfo stranger = mock(TransactionInfo.class);
        when(stranger.getDescription()).thenReturn("ReVa: Auto Analysis");
        // availability check, then the re-check right before startTransaction
        when(program.getCurrentTransactionInfo()).thenReturn(null, stranger);
        AtomicReference<Boolean> ran = new AtomicReference<>(false);
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> ran.set(true));

        Result r = exec.execute(scriptFile, program, null, 60, 1024);

        assertFalse(ran.get());
        verify(program, never()).startTransaction(anyString());
        assertNotNull(r.executionError());
        assertTrue(r.executionError() instanceof ProgramBusyException);
        assertTrue(r.executionError().getMessage(),
            r.executionError().getMessage().contains("ReVa: Auto Analysis"));
    }

    @Test
    public void joinedStrangerTransactionIsReleasedAndRefused() throws Exception {
        // Nothing open at either check, but a stranger's transaction appeared
        // between the re-check and startTransaction, so our entry joined it.
        TransactionInfo joined = mock(TransactionInfo.class);
        when(joined.getOpenSubTransactions())
            .thenReturn(new java.util.ArrayList<>(java.util.List.of(
                "stranger", "run-script: test.py")));
        // busy check, re-check, cleanup snapshot, post-start check
        when(program.getCurrentTransactionInfo()).thenReturn(null, null, null, joined);
        when(program.startTransaction(anyString())).thenReturn(7);
        AtomicReference<Boolean> ran = new AtomicReference<>(false);
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> ran.set(true));

        Result r = exec.execute(scriptFile, program, null, 60, 1024);

        assertFalse("nothing runs when the start joined a stranger", ran.get());
        // Our empty entry is released with commit=true: commit=false would
        // abort the stranger's transaction.
        verify(program).endTransaction(7, true);
        verify(program, never()).endTransaction(7, false);
        assertNotNull(r.executionError());
        assertTrue(r.executionError() instanceof ProgramBusyException);
        assertTrue(r.executionError().getMessage().contains("another writer"));
        assertFalse(r.parentCommitted());
    }

    @Test
    public void waitDeadlineExpiredLeavesBusyResultWithoutRunning() throws Exception {
        // The writer never finishes: the bounded wait must end in the
        // structured busy result, not in a run stacked on top of it.
        TransactionInfo info = mock(TransactionInfo.class);
        when(info.getDescription()).thenReturn("ReVa: Auto Analysis");
        when(program.getCurrentTransactionInfo()).thenReturn(info);
        AtomicReference<Boolean> ran = new AtomicReference<>(false);
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> ran.set(true),
            p -> false, 120, 15);

        Result r = exec.execute(scriptFile, program, null, 60, 1024);

        assertFalse("a busy program must not run the script", ran.get());
        verify(program, never()).startTransaction(anyString());
        assertNotNull(r.executionError());
        assertTrue(r.executionError() instanceof ProgramBusyException);
        assertEquals("a transaction is open (ReVa: Auto Analysis)",
            r.executionError().getMessage());
        assertFalse(r.parentCommitted());
        assertFalse(r.transactionRolledBack());
    }

    @Test
    public void waitLetsTheRunProceedOnceTheWriterClears() throws Exception {
        when(program.startTransaction(anyString())).thenReturn(5);
        TransactionInfo busy = mock(TransactionInfo.class);
        when(busy.getDescription()).thenReturn("ReVa: Auto Analysis");
        // The first two availability checks see the sibling writer; the third
        // one, after two polls, does not.
        when(program.getCurrentTransactionInfo()).thenReturn(busy, busy, null);
        AtomicReference<Boolean> ran = new AtomicReference<>(false);
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> ran.set(true),
            p -> false, 5_000, 20);

        long startNs = System.nanoTime();
        Result r = exec.execute(scriptFile, program, null, 60, 1024);
        long waitedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs);

        assertTrue("the run must proceed once the writer finished", ran.get());
        verify(program).endTransaction(5, true);
        assertTrue(r.parentCommitted());
        assertNull(r.executionError());
        assertTrue("the wait must survive at least one poll interval, waited "
            + waitedMs + "ms", waitedMs >= 40);
    }

    @Test
    public void waitLetsTheRunProceedOnceAnalysisFinishes() throws Exception {
        when(program.startTransaction(anyString())).thenReturn(6);
        // No transaction open, but auto-analysis was running at the first
        // check and stopped by the second.
        AtomicInteger checks = new AtomicInteger();
        AtomicReference<Boolean> ran = new AtomicReference<>(false);
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> ran.set(true),
            p -> checks.getAndIncrement() == 0, 5_000, 20);

        Result r = exec.execute(scriptFile, program, null, 60, 1024);

        assertTrue("the run must proceed once analysis finished", ran.get());
        verify(program).endTransaction(6, true);
        assertTrue(r.parentCommitted());
        assertNull(r.executionError());
    }

    @Test
    public void programBusyExceptionCarriesTheReason() {
        ProgramBusyException e = new ProgramBusyException("auto-analysis is running");
        assertEquals("auto-analysis is running", e.reason());
        assertEquals("auto-analysis is running", e.getMessage());
    }

    @Test
    public void timeoutErrorOverridesPythonCancellationTraceback() throws Exception {
        when(program.startTransaction(anyString())).thenReturn(3);
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> {
                monitor.cancel();
                err.print("Traceback (most recent call last):\nCancelledException: cancelled\n");
            });
        Result r = exec.execute(scriptFile, program, null, 60, 1024);
        verify(program).endTransaction(3, false);
        assertTrue(r.timedOut());
        assertEquals("script timed out after 60 seconds", r.executionError().getMessage());
    }

    @Test
    public void durationIsNonNegative() throws Exception {
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> { /* fast no-op */ });
        Result r = exec.execute(scriptFile, program, null, 60, 1024);
        assertTrue("duration should be non-negative", r.durationMs() >= 0);
    }

    @Test
    public void runnerReceivesScriptFileAndProgram() throws Exception {
        AtomicReference<ResourceFile> seenFile = new AtomicReference<>();
        AtomicReference<Program> seenProgram = new AtomicReference<>();
        AtomicReference<PluginTool> seenTool = new AtomicReference<>();
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> {
                seenFile.set(f);
                seenProgram.set(p);
                seenTool.set(t);
            });
        exec.execute(scriptFile, program, null, 60, 1024);
        assertSame(scriptFile, seenFile.get());
        assertSame(program, seenProgram.get());
        assertNull(seenTool.get());
    }

    @Test(expected = NullPointerException.class)
    public void constructorRejectsNullRunner() {
        new PythonScriptExecutor(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void executeRejectsZeroTimeout() throws Exception {
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> {});
        exec.execute(scriptFile, program, null, 0, 1024);
    }

    @Test(expected = IllegalArgumentException.class)
    public void executeRejectsNegativeTimeout() throws Exception {
        PythonScriptExecutor exec = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> {});
        exec.execute(scriptFile, program, null, -1, 1024);
    }
}
