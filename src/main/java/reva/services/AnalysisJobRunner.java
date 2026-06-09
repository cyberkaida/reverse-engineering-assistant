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
package reva.services;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.task.DummyCancellableTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;
import reva.util.ProgramPersistenceUtil;
import reva.util.ProgramPersistenceUtil.PersistMode;
import reva.util.ProgramPersistenceUtil.PersistResult;

/**
 * Runs one auto-analysis on a background worker thread, capturing live log output into the
 * job, persisting the program when finished, and transitioning the job through its lifecycle.
 *
 * <p>All Ghidra work (transactions, {@code startAnalysis}, persist) happens on the worker
 * thread, mirroring the proven off-Swing path of the synchronous {@code analyze-program}
 * tool and {@code checkin-program}.
 */
public class AnalysisJobRunner implements Runnable {

    private final AnalysisJobManager mgr;
    private final AnalysisJob job;
    private final AnalyzeRequest req;

    public AnalysisJobRunner(AnalysisJobManager mgr, AnalysisJob job, AnalyzeRequest req) {
        this.mgr = mgr;
        this.job = job;
        this.req = req;
    }

    @Override
    public void run() {
        Program program = req.program;

        AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(program);
        if (aam == null) {
            job.setError("Could not get analysis manager for program: " + job.getProgramPath());
            job.appendLog("Analysis failed: could not get analysis manager");
            job.markTerminal(JobStatus.FAILED);
            return;
        }
        aam.initializeOptions();

        Options analysisOpts = program.getOptions(Program.ANALYSIS_PROPERTIES);

        // Snapshot + apply analyzer overrides (per-call overrides do not persist).
        Map<String, Boolean> snapshot = new LinkedHashMap<>();
        if (!req.enableAnalyzers.isEmpty() || !req.disableAnalyzers.isEmpty()) {
            int overrideTx = program.startTransaction("ReVa: Apply analyzer overrides");
            try {
                for (String name : req.enableAnalyzers) {
                    if (analysisOpts.contains(name)) {
                        snapshot.put(name, analysisOpts.getBoolean(name, true));
                        analysisOpts.setBoolean(name, true);
                    }
                }
                for (String name : req.disableAnalyzers) {
                    if (analysisOpts.contains(name)) {
                        snapshot.put(name, analysisOpts.getBoolean(name, true));
                        analysisOpts.setBoolean(name, false);
                    }
                }
                program.endTransaction(overrideTx, true);
            } catch (Exception e) {
                program.endTransaction(overrideTx, false);
                job.setError(e.getMessage());
                job.appendLog("Analysis failed: " + e.getMessage());
                job.markTerminal(JobStatus.FAILED);
                return;
            }
        }

        TaskMonitor baseMonitor = (req.timeoutSeconds == -1)
            ? new DummyCancellableTaskMonitor()
            : TimeoutTaskMonitor.timeoutIn(req.timeoutSeconds, TimeUnit.SECONDS);
        JobLogTaskMonitor monitor = new JobLogTaskMonitor(baseMonitor, job, program);
        job.setMonitor(monitor);
        if (job.isCancelRequested()) {
            monitor.cancel();
        }

        long startMs = System.currentTimeMillis();
        boolean wasFullAnalysis = req.forceFullAnalysis || !GhidraProgramUtilities.isAnalyzed(program);
        job.appendLog("Starting " + (wasFullAnalysis ? "full" : "incremental") + " auto-analysis…");

        boolean cancelled;
        int analysisTx = program.startTransaction("ReVa: Auto Analysis");
        try {
            if (wasFullAnalysis) {
                aam.reAnalyzeAll(null);
            }
            aam.startAnalysis(monitor); // blocks; the manager's ticker pumps the message log meanwhile
            cancelled = monitor.isCancelled();
            if (!cancelled) {
                GhidraProgramUtilities.markProgramAnalyzed(program);
            }
            program.endTransaction(analysisTx, true);
        } catch (Exception e) {
            program.endTransaction(analysisTx, false);
            restoreAnalyzerOptions(program, analysisOpts, snapshot);
            job.setError(e.getMessage());
            job.appendLog("Analysis failed: " + e.getMessage());
            job.markTerminal(JobStatus.FAILED);
            return;
        }

        restoreAnalyzerOptions(program, analysisOpts, snapshot);

        long durationMs = System.currentTimeMillis() - startMs;
        boolean timedOut = cancelled && req.timeoutSeconds != -1 && !job.isCancelRequested();

        List<Map<String, Object>> analyzersRun = new ArrayList<>();
        for (String taskName : aam.getTimedTasks()) {
            analyzersRun.add(Map.of("name", taskName));
        }

        List<String> messages = new ArrayList<>();
        if (aam.getMessageLog() != null && aam.getMessageLog().hasMessages()) {
            for (String line : aam.getMessageLog().toString().split("\n")) {
                if (!line.isBlank()) {
                    messages.add(line);
                }
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", !cancelled);
        result.put("programPath", job.getProgramPath());
        result.put("analyzed", GhidraProgramUtilities.isAnalyzed(program));
        result.put("wasFullAnalysis", wasFullAnalysis);
        result.put("durationMs", durationMs);
        result.put("totalTaskTimeMs", aam.getTotalTimeInMillis());
        result.put("cancelled", cancelled);
        result.put("timedOut", timedOut);
        result.put("analyzersRun", analyzersRun);
        if (!messages.isEmpty()) {
            result.put("messages", messages);
        }
        if (timedOut) {
            result.put("error",
                "Analysis timed out after " + req.timeoutSeconds + " seconds. "
                    + "Increase timeoutSeconds or pass -1 for unlimited.");
        }

        // PERSIST (non-terminal). Analysis succeeded; a persistence failure is reported but
        // not fatal.
        job.toPersisting();
        job.appendLog("Persisting…");
        // Flush pending change events so isChanged() reflects committed transactions. On the
        // worker thread (headless/CLI mode) nothing else pumps this program's event queue, so
        // without an explicit flush the persist guard can read stale (not-changed) state.
        program.flushEvents();
        if (program.isChanged() && req.persistMode != PersistMode.NONE) {
            try {
                // Persist with a FRESH monitor, never the analysis monitor: on a TIMED_OUT or
                // CANCELLED run the analysis monitor is already cancelled (and a
                // TimeoutTaskMonitor can fire again mid-save), which would abort the save and
                // silently lose the partial-work durability guarantee. Wrap TaskMonitor.DUMMY
                // so "Saving…" progress still flows to the job log without any cancel risk.
                TaskMonitor persistMonitor = new JobLogTaskMonitor(TaskMonitor.DUMMY, job, program);
                PersistResult pr = ProgramPersistenceUtil.persist(
                    program, req.persistMode, "ReVa auto-analysis", true, persistMonitor);
                String persisted = persistedLabel(pr);
                result.put("persisted", persisted);
                result.put("saved", pr.saved);
                if (pr.error != null) {
                    result.put("persistError", pr.error);
                }
                job.appendLog("Persisted: " + persisted + (pr.error != null ? " (checkin error)" : ""));
            } catch (Exception e) {
                result.put("persisted", "failed");
                result.put("persistError", e.getMessage());
                job.appendLog("Persist failed: " + e.getMessage());
            }
        } else {
            result.put("persisted", "skipped");
        }

        job.setResult(result);

        JobStatus status;
        if (cancelled && job.isCancelRequested()) {
            status = JobStatus.CANCELLED;
        } else if (cancelled) {
            status = (req.timeoutSeconds != -1) ? JobStatus.TIMED_OUT : JobStatus.CANCELLED;
        } else {
            status = JobStatus.COMPLETED;
        }
        job.appendLog("Analysis " + status + " (" + durationMs + "ms)");
        job.markTerminal(status);
    }

    /** Map a {@link PersistResult} to the result-map label: checkin | add_to_vc | save. */
    private static String persistedLabel(PersistResult pr) {
        switch (pr.action) {
            case CHECKIN:
                return "checkin";
            case ADD_TO_VC:
                return "add_to_vc";
            case SAVE:
                return "save";
            default:
                return pr.action.name().toLowerCase();
        }
    }

    /** Restore analyzer options to their pre-run values, in a transaction. No-op if empty. */
    private void restoreAnalyzerOptions(Program program, Options analysisOpts,
            Map<String, Boolean> snapshot) {
        if (snapshot.isEmpty()) {
            return;
        }
        int tx = program.startTransaction("ReVa: Restore analyzer overrides");
        try {
            for (Map.Entry<String, Boolean> entry : snapshot.entrySet()) {
                analysisOpts.setBoolean(entry.getKey(), entry.getValue());
            }
            program.endTransaction(tx, true);
        } catch (Exception e) {
            program.endTransaction(tx, false);
            Msg.error(this, "Failed to restore analyzer options: " + e.getMessage(), e);
        }
    }

    /**
     * Task monitor that mirrors analyzer status messages into the job log and keeps the job's
     * live function count fresh. Modeled on {@code ProjectToolProvider.AnalysisProgressMonitor}.
     */
    static final class JobLogTaskMonitor extends WrappingTaskMonitor {
        private final AnalysisJob job;
        private final Program program;

        JobLogTaskMonitor(TaskMonitor delegate, AnalysisJob job, Program program) {
            super(delegate);
            this.job = job;
            this.program = program;
        }

        @Override
        public void setMessage(String message) {
            super.setMessage(message);
            job.appendLogDeduped(message);
            job.setFunctionCount(program.getFunctionManager().getFunctionCount());
        }
    }
}
