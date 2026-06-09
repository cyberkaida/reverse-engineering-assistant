package reva.services;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory registry of background diff jobs plus the worker that runs them. Assigns
 * monotonically increasing ids ("diff-N"); a single-thread worker executes submitted jobs off
 * the request thread (correlation/markup are memory-heavy, so serialize them).
 */
public class DiffJobManager {

    private static final int MAX_TERMINAL_JOBS = 50;

    private final ConcurrentHashMap<String, DiffJob> jobs = new ConcurrentHashMap<>();
    private final AtomicLong counter = new AtomicLong(0);
    private final ExecutorService worker;

    public DiffJobManager() {
        this.worker = Executors.newSingleThreadExecutor(daemonFactory("reva-diff"));
    }

    private static ThreadFactory daemonFactory(String name) {
        return r -> {
            Thread t = new Thread(r, name);
            t.setDaemon(true);
            return t;
        };
    }

    public DiffJob create(DiffJobKind kind, String sourcePath, String destinationPath) {
        String jobId = "diff-" + counter.incrementAndGet();
        DiffJob job = new DiffJob(jobId, kind, sourcePath, destinationPath);
        jobs.put(jobId, job);
        prune();
        return job;
    }

    private synchronized void prune() {
        List<DiffJob> terminal = new ArrayList<>();
        for (DiffJob job : jobs.values()) {
            if (job.getStatus().isTerminal()) {
                terminal.add(job);
            }
        }
        if (terminal.size() <= MAX_TERMINAL_JOBS) {
            return;
        }
        terminal.sort((a, b) -> Long.compare(idSuffix(a.getJobId()), idSuffix(b.getJobId())));
        int toEvict = terminal.size() - MAX_TERMINAL_JOBS;
        for (int i = 0; i < toEvict; i++) {
            jobs.remove(terminal.get(i).getJobId());
        }
    }

    private static long idSuffix(String jobId) {
        return Long.parseLong(jobId.substring(jobId.lastIndexOf('-') + 1));
    }

    public DiffJob get(String jobId) { return jobs.get(jobId); }
    public Collection<DiffJob> all() { return jobs.values(); }

    /** Find a non-terminal job of the given kind for the exact (source,destination) pair. */
    public DiffJob runningJob(DiffJobKind kind, String sourcePath, String destinationPath) {
        for (DiffJob job : jobs.values()) {
            if (job.getKind() == kind
                    && job.getSourcePath().equals(sourcePath)
                    && job.getDestinationPath().equals(destinationPath)
                    && !job.getStatus().isTerminal()) {
                return job;
            }
        }
        return null;
    }

    /** Most-recently-created job (any kind) for the given (source,destination) pair. */
    public DiffJob latestForPair(String sourcePath, String destinationPath) {
        DiffJob latest = null;
        for (DiffJob job : jobs.values()) {
            if (job.getSourcePath().equals(sourcePath) && job.getDestinationPath().equals(destinationPath)) {
                if (latest == null || idSuffix(job.getJobId()) > idSuffix(latest.getJobId())) {
                    latest = job;
                }
            }
        }
        return latest;
    }

    /** Cancel every non-terminal job whose source OR destination is the given program path. */
    public void cancelJobsForProgram(String programPath) {
        for (DiffJob job : jobs.values()) {
            if ((job.getSourcePath().equals(programPath) || job.getDestinationPath().equals(programPath))
                    && !job.getStatus().isTerminal()) {
                job.requestCancel();
            }
        }
    }

    public void submit(DiffJob job, DiffWork work, int timeoutSeconds) {
        worker.submit(new DiffJobRunner(job, work, timeoutSeconds));
    }

    /**
     * Single-flight: reuse the in-flight job for this (kind, source, destination), or create and
     * submit a new one. The lock spans find+create+submit so two concurrent identical calls
     * cannot both launch the work (no double correlation, no double markup write). The work
     * supplier is invoked only when a new job is started.
     */
    public synchronized DiffJob startOrAttach(DiffJobKind kind, String sourcePath,
            String destinationPath, Supplier<DiffWork> workSupplier, int timeoutSeconds) {
        DiffJob existing = runningJob(kind, sourcePath, destinationPath);
        if (existing != null) {
            return existing;
        }
        DiffJob job = create(kind, sourcePath, destinationPath);
        submit(job, workSupplier.get(), timeoutSeconds);
        return job;
    }

    public void dispose() {
        for (DiffJob job : jobs.values()) {
            if (!job.getStatus().isTerminal()) {
                job.requestCancel();
            }
        }
        worker.shutdownNow();
    }
}
