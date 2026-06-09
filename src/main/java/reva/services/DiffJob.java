package reva.services;

import java.util.Map;
import ghidra.util.task.TaskMonitor;

/**
 * In-memory state for a single background diff job (correlation or markup transfer). Thread-safe:
 * the log is a {@link JobLog}; the scalar fields are volatile.
 */
public class DiffJob {

    private final String jobId;
    private final DiffJobKind kind;
    private final String sourcePath;
    private final String destinationPath;
    private final long startMs;
    private final JobLog jobLog;

    private volatile JobStatus status = JobStatus.RUNNING;
    private volatile long endMs = 0;
    private volatile Map<String, Object> result;
    private volatile String error;
    private volatile TaskMonitor monitor;
    private volatile boolean cancelRequested;

    public DiffJob(String jobId, DiffJobKind kind, String sourcePath, String destinationPath) {
        this.jobId = jobId;
        this.kind = kind;
        this.sourcePath = sourcePath;
        this.destinationPath = destinationPath;
        this.startMs = System.currentTimeMillis();
        this.jobLog = new JobLog(startMs);
    }

    public String getJobId() { return jobId; }
    public DiffJobKind getKind() { return kind; }
    public String getSourcePath() { return sourcePath; }
    public String getDestinationPath() { return destinationPath; }
    public long getStartMs() { return startMs; }
    public long getEndMs() { return endMs; }
    public JobStatus getStatus() { return status; }

    public void appendLog(String message) { jobLog.append(message); }
    public void appendLogDeduped(String message) { jobLog.appendDeduped(message); }
    public String getLatestLogMessage() { return jobLog.latestMessage(); }
    public JobLog.LogPage logSince(long sinceSeq, int max) { return jobLog.logSince(sinceSeq, max); }

    public void setResult(Map<String, Object> result) { this.result = result; }
    public Map<String, Object> getResult() { return result; }
    public void setError(String error) { this.error = error; }
    public String getError() { return error; }

    /** Transition to a terminal status, stamping the end time. */
    public void markTerminal(JobStatus status) {
        this.endMs = System.currentTimeMillis();
        this.status = status;
    }

    public TaskMonitor getMonitor() { return monitor; }
    public void setMonitor(TaskMonitor monitor) { this.monitor = monitor; }

    /** Request cancellation: set the flag and cancel the attached monitor if present. */
    public void requestCancel() {
        this.cancelRequested = true;
        TaskMonitor m = this.monitor;
        if (m != null) {
            m.cancel();
        }
    }

    public boolean isCancelRequested() { return cancelRequested; }
}
