package reva.services;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * In-memory state for a single background analysis job.
 *
 * <p>Holds the job's identity, status, an append-only log buffer with a monotonic
 * per-job sequence counter, and optional result/error payloads. The instance is
 * thread-safe: the log entry list is guarded by a private lock, the sequence counter
 * is incremented under that lock, and the mutable scalar fields are volatile.
 */
public class AnalysisJob {

    /**
     * Lifecycle status of an analysis job.
     */
    public enum Status {
        RUNNING,
        PERSISTING,
        COMPLETED,
        FAILED,
        CANCELLED,
        TIMED_OUT;

        /**
         * @return true if this status is a terminal state (no further transitions)
         */
        public boolean isTerminal() {
            switch (this) {
                case COMPLETED:
                case FAILED:
                case CANCELLED:
                case TIMED_OUT:
                    return true;
                default:
                    return false;
            }
        }
    }

    /**
     * A single append-only log entry with its sequence number and elapsed time.
     */
    public static final class LogEntry {
        public final long seq;
        public final long elapsedMs;
        public final String message;

        public LogEntry(long seq, long elapsedMs, String message) {
            this.seq = seq;
            this.elapsedMs = elapsedMs;
            this.message = message;
        }
    }

    /**
     * A page of log entries returned by {@link AnalysisJob#logSince(long, int)}.
     */
    public static final class LogPage {
        public final List<LogEntry> entries;
        public final long nextCursor;
        public final boolean truncated;

        public LogPage(List<LogEntry> entries, long nextCursor, boolean truncated) {
            this.entries = entries;
            this.nextCursor = nextCursor;
            this.truncated = truncated;
        }
    }

    private final String jobId;
    private final String programPath;
    private final long startMs;

    private final Object logLock = new Object();
    private final List<LogEntry> log = new ArrayList<>();
    private long seqCounter = 0;

    private volatile Status status = Status.RUNNING;
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
    // Most-recently-appended message, used by appendLogDeduped to suppress setMessage spam.
    // Guarded by logLock.
    private String lastAppendedMessage;

    public AnalysisJob(String jobId, String programPath) {
        this.jobId = jobId;
        this.programPath = programPath;
        this.startMs = System.currentTimeMillis();
    }

    public String getJobId() {
        return jobId;
    }

    public String getProgramPath() {
        return programPath;
    }

    public Status getStatus() {
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
    public void appendLog(String message) {
        synchronized (logLock) {
            lastAppendedMessage = message;
            long seq = ++seqCounter;
            long elapsedMs = System.currentTimeMillis() - startMs;
            log.add(new LogEntry(seq, elapsedMs, message));
        }
    }

    /**
     * Append a message only if it differs from the most-recently-appended message. Used by
     * the analysis monitor's {@code setMessage} hook to avoid flooding the log with repeats.
     *
     * @param message the candidate log message
     */
    public void appendLogDeduped(String message) {
        synchronized (logLock) {
            if (message != null && message.equals(lastAppendedMessage)) {
                return;
            }
            lastAppendedMessage = message;
            long seq = ++seqCounter;
            long elapsedMs = System.currentTimeMillis() - startMs;
            log.add(new LogEntry(seq, elapsedMs, message));
        }
    }

    /**
     * The most recently appended log message, or {@code null} if nothing has been logged yet.
     * Used for live progress display (shows current activity rather than a stale first line).
     *
     * @return the latest log message, or null
     */
    public String getLatestLogMessage() {
        synchronized (logLock) {
            return lastAppendedMessage;
        }
    }

    /**
     * Return log entries with {@code seq > sinceSeq}, at most {@code max} of them.
     *
     * @param sinceSeq exclusive lower bound on entry sequence number
     * @param max      maximum number of entries to return
     * @return a page whose {@code nextCursor} is the seq of the last returned entry
     *         (or {@code sinceSeq} if none), and whose {@code truncated} flag is true
     *         when more matching entries existed beyond {@code max}
     */
    public LogPage logSince(long sinceSeq, int max) {
        synchronized (logLock) {
            List<LogEntry> out = new ArrayList<>();
            int matched = 0;
            long nextCursor = sinceSeq;
            boolean truncated = false;
            for (LogEntry entry : log) {
                if (entry.seq <= sinceSeq) {
                    continue;
                }
                matched++;
                if (out.size() < max) {
                    out.add(entry);
                    nextCursor = entry.seq;
                } else {
                    truncated = true;
                    break;
                }
            }
            return new LogPage(Collections.unmodifiableList(out), nextCursor, truncated);
        }
    }

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
        return result;
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
    public void markTerminal(Status status) {
        this.endMs = System.currentTimeMillis();
        this.status = status;
    }

    /**
     * Transition this job to the non-terminal PERSISTING state. Unlike
     * {@link #markTerminal(Status)} this does NOT stamp the end time.
     */
    public void toPersisting() {
        this.status = Status.PERSISTING;
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
