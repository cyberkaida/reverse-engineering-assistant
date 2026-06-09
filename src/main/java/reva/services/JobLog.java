package reva.services;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Thread-safe append-only log buffer with a monotonic per-job sequence counter, shared by
 * background job types. The entry list is guarded by a private lock; the sequence counter is
 * incremented under that lock.
 */
public final class JobLog {

    /** One append-only entry: its sequence number and elapsed time since job start. */
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

    /** A page of entries from {@link #logSince(long, int)}. */
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

    private final long startMs;
    private final Object lock = new Object();
    private final List<LogEntry> log = new ArrayList<>();
    private long seqCounter = 0;
    private String lastAppendedMessage;

    public JobLog(long startMs) {
        this.startMs = startMs;
    }

    /** Append a message, assigning the next monotonic seq and recording elapsed time. */
    public void append(String message) {
        synchronized (lock) {
            lastAppendedMessage = message;
            long seq = ++seqCounter;
            log.add(new LogEntry(seq, System.currentTimeMillis() - startMs, message));
        }
    }

    /** Append only if the message differs from the most-recently-appended one. */
    public void appendDeduped(String message) {
        synchronized (lock) {
            if (message != null && message.equals(lastAppendedMessage)) {
                return;
            }
            lastAppendedMessage = message;
            long seq = ++seqCounter;
            log.add(new LogEntry(seq, System.currentTimeMillis() - startMs, message));
        }
    }

    /** @return the most-recently-appended message, or null. */
    public String latestMessage() {
        synchronized (lock) {
            return lastAppendedMessage;
        }
    }

    /**
     * @return entries with {@code seq > sinceSeq}, at most {@code max}. The page's
     *         {@code nextCursor} is the seq of the last returned entry, or equals
     *         {@code sinceSeq} when no entries matched (the empty-page case).
     */
    public LogPage logSince(long sinceSeq, int max) {
        synchronized (lock) {
            List<LogEntry> out = new ArrayList<>();
            long nextCursor = sinceSeq;
            boolean truncated = false;
            for (LogEntry entry : log) {
                if (entry.seq <= sinceSeq) {
                    continue;
                }
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
}
