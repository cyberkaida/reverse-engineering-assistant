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

import generic.jar.ResourceFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;

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
     * exception; the executor captures it so the tool layer can return a
     * normal result with {@code success: false} rather than an MCP-level
     * error. {@link PyGhidraNotAvailableException} is always rethrown.
     */
    public static record Result(
        String stdout,
        String stderr,
        boolean stdoutTruncated,
        boolean stderrTruncated,
        long durationMs,
        boolean timedOut,
        Throwable executionError
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

    private final ScriptRunner runner;

    public PythonScriptExecutor(ScriptRunner runner) {
        this.runner = Objects.requireNonNull(runner, "runner");
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

        CappedWriter outCap = new CappedWriter(outputCapChars);
        CappedWriter errCap = new CappedWriter(outputCapChars);
        PrintWriter outPw = new PrintWriter(outCap);
        PrintWriter errPw = new PrintWriter(errCap);

        TimeoutTaskMonitor monitor =
            TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);

        long start = System.currentTimeMillis();
        Throwable execError = null;
        try {
            runner.run(scriptFile, program, tool, outPw, errPw, monitor);
        } catch (PyGhidraNotAvailableException e) {
            throw e;
        } catch (Exception e) {
            execError = e;
        }
        long duration = System.currentTimeMillis() - start;

        outPw.flush();
        errPw.flush();

        return new Result(
            outCap.getCapturedString(),
            errCap.getCapturedString(),
            outCap.isTruncated(),
            errCap.isTruncated(),
            duration,
            monitor.isCancelled(),
            execError);
    }
}
