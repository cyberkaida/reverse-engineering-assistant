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
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Before;
import org.junit.Test;

import generic.jar.ResourceFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
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
