package reva.services;

import java.util.Map;

/**
 * In-memory state for a single background analysis job.
 *
 * <p>Holds the job's identity, status, an append-only log buffer with a monotonic
 * per-job sequence counter, and optional result/error payloads. The instance is
 * thread-safe: the log is delegated to {@link JobLog} (which is internally guarded),
 * and the mutable scalar fields are volatile.
 */
public class AnalysisJob {

    private final String jobId;
    private final String programPath;
    private final long startMs;

    private final JobLog jobLog;

    private volatile JobStatus status = JobStatus.RUNNING;
    private volatile int functionCount = 0;
    private volatile long endMs = 0;
    private volatile Map<String, Object> result;
    private volatile String error;

    // Worker-execution state (populated once the job is submitted to the runner).
    private volatile ghidra.program.model.listing.Program program;
    private volatile ghidra.util.task.TaskMonitor monitor;
    private volatile boolean cancelRequested;
    // Cursor into the AutoAnalysisManager message log; advanced by the manager's ticker
    // (single writer) so a volatile int is sufficient.
    private volatile int lastMessageLineCount = 0;

    public AnalysisJob(String jobId, String programPath) {
        this.jobId = jobId;
        this.programPath = programPath;
        this.startMs = System.currentTimeMillis();
        this.jobLog = new JobLog(startMs);
    }

    public String getJobId() {
        return jobId;
    }

    public String getProgramPath() {
        return programPath;
    }

    public JobStatus getStatus() {
        return status;
    }

    public long getStartMs() {
        return startMs;
    }

    public long getEndMs() {
        return endMs;
    }

    /**
     * Append a message to the log buffer, assigning it the next monotonic sequence
     * number and recording the elapsed time since job start.
     *
     * @param message the log message
     */
    public void appendLog(String message) { jobLog.append(message); }

    /**
     * Append a message only if it differs from the most-recently-appended message. Used by
     * the analysis monitor's {@code setMessage} hook to avoid flooding the log with repeats.
     *
     * @param message the candidate log message
     */
    public void appendLogDeduped(String message) { jobLog.appendDeduped(message); }

    /**
     * The most recently appended log message, or {@code null} if nothing has been logged yet.
     * Used for live progress display (shows current activity rather than a stale first line).
     *
     * @return the latest log message, or null
     */
    public String getLatestLogMessage() { return jobLog.latestMessage(); }

    /**
     * Return log entries with {@code seq > sinceSeq}, at most {@code max} of them.
     *
     * @param sinceSeq exclusive lower bound on entry sequence number
     * @param max      maximum number of entries to return
     * @return a page whose {@code nextCursor} is the seq of the last returned entry
     *         (or {@code sinceSeq} if none), and whose {@code truncated} flag is true
     *         when more matching entries existed beyond {@code max}
     */
    public JobLog.LogPage logSince(long sinceSeq, int max) { return jobLog.logSince(sinceSeq, max); }

    public void setFunctionCount(int functionCount) {
        this.functionCount = functionCount;
    }

    public int getFunctionCount() {
        return functionCount;
    }

    public void setResult(Map<String, Object> result) {
        this.result = result;
    }

    public Map<String, Object> getResult() {
        return result == null ? null : java.util.Collections.unmodifiableMap(result);
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getError() {
        return error;
    }

    /**
     * Transition this job to a (typically terminal) status, recording the end time.
     *
     * @param status the new status
     */
    public void markTerminal(JobStatus status) {
        this.endMs = System.currentTimeMillis();
        this.status = status;
    }

    /**
     * Transition this job to the non-terminal PERSISTING state. Unlike
     * {@link #markTerminal(JobStatus)} this does NOT stamp the end time.
     */
    public void toPersisting() {
        this.status = JobStatus.PERSISTING;
    }

    public ghidra.program.model.listing.Program getProgram() {
        return program;
    }

    public void setProgram(ghidra.program.model.listing.Program program) {
        this.program = program;
    }

    public ghidra.util.task.TaskMonitor getMonitor() {
        return monitor;
    }

    public void setMonitor(ghidra.util.task.TaskMonitor monitor) {
        this.monitor = monitor;
    }

    /**
     * Request cancellation of this job: sets the cancel flag and, if a monitor is attached,
     * cancels it so the in-flight analysis unwinds.
     */
    public void requestCancel() {
        this.cancelRequested = true;
        ghidra.util.task.TaskMonitor m = this.monitor;
        if (m != null) {
            m.cancel();
        }
    }

    public boolean isCancelRequested() {
        return cancelRequested;
    }

    public int getLastMessageLineCount() {
        return lastMessageLineCount;
    }

    public void setLastMessageLineCount(int lastMessageLineCount) {
        this.lastMessageLineCount = lastMessageLineCount;
    }
}
