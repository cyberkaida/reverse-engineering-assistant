package reva.services;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.DummyCancellableTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;

/**
 * Runs one {@link DiffWork} on the background worker thread, mirroring messages into the job log,
 * honoring cancellation/timeout, and transitioning the job to a terminal status. Domain logic
 * lives in the supplied {@code DiffWork}; this class owns only the lifecycle.
 */
public class DiffJobRunner implements Runnable {

    private final DiffJob job;
    private final DiffWork work;
    private final int timeoutSeconds;

    public DiffJobRunner(DiffJob job, DiffWork work, int timeoutSeconds) {
        this.job = job;
        this.work = work;
        this.timeoutSeconds = timeoutSeconds;
    }

    @Override
    public void run() {
        // Use a cancellable base monitor for the -1 (no timeout) path so that
        // requestCancel() → monitor.cancel() → isCancelled() == true propagates correctly.
        // TaskMonitor.DUMMY (StubTaskMonitor) is a no-op stub whose cancel() does nothing,
        // so wrapping it would leave isCancelled() permanently false.
        TaskMonitor base = (timeoutSeconds == -1)
            ? new DummyCancellableTaskMonitor()
            : TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
        JobLogTaskMonitor monitor = new JobLogTaskMonitor(base, job);
        job.setMonitor(monitor);
        if (job.isCancelRequested()) {
            monitor.cancel();
        }

        long startMs = System.currentTimeMillis();
        job.appendLog("Starting " + job.getKind().name().toLowerCase().replace('_', ' ') + "…");

        try {
            Map<String, Object> result = work.run(monitor);
            long durationMs = System.currentTimeMillis() - startMs;
            if (monitor.isCancelled()) {
                terminalForCancel(durationMs);
                return;
            }
            job.setResult(result);
            job.appendLog("Diff " + JobStatus.COMPLETED + " (" + durationMs + "ms)");
            job.markTerminal(JobStatus.COMPLETED);
        } catch (CancelledException e) {
            terminalForCancel(System.currentTimeMillis() - startMs);
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            job.setError(msg);
            job.appendLog("Diff failed: " + msg);
            job.markTerminal(JobStatus.FAILED);
        }
    }

    private void terminalForCancel(long durationMs) {
        // Cancelled by the user → CANCELLED; cancelled by a timeout monitor (and not user-requested)
        // → TIMED_OUT, mirroring the analysis runner's disambiguation.
        JobStatus status = (timeoutSeconds != -1 && !job.isCancelRequested())
            ? JobStatus.TIMED_OUT
            : JobStatus.CANCELLED;
        job.appendLog("Diff " + status + " (" + durationMs + "ms)");
        job.markTerminal(status);
    }

    /** Mirrors VT/markup status messages into the job log. */
    static final class JobLogTaskMonitor extends WrappingTaskMonitor {
        private final DiffJob job;

        JobLogTaskMonitor(TaskMonitor delegate, DiffJob job) {
            super(delegate);
            this.job = job;
        }

        @Override
        public void setMessage(String message) {
            super.setMessage(message);
            job.appendLogDeduped(message);
        }
    }
}
