package reva.services;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import reva.services.AnalysisJob.Status;

/**
 * In-memory registry of background analysis jobs plus the worker execution that runs them.
 *
 * <p>Assigns deterministic, monotonically increasing job ids and tracks jobs by id. A
 * single-thread worker executes submitted jobs off the request thread; a 1Hz ticker pumps
 * each running job's analysis message log into its job log.
 */
public class AnalysisJobManager {

    /** Maximum number of TERMINAL jobs retained; oldest beyond this are pruned. */
    private static final int MAX_TERMINAL_JOBS = 50;

    private final ConcurrentHashMap<String, AnalysisJob> jobs = new ConcurrentHashMap<>();
    private final AtomicLong counter = new AtomicLong(0);

    private final ExecutorService worker;
    private final ScheduledExecutorService ticker;

    public AnalysisJobManager() {
        this.worker = Executors.newSingleThreadExecutor(daemonFactory("reva-analysis"));
        this.ticker = Executors.newSingleThreadScheduledExecutor(daemonFactory("reva-analysis-tick"));
        this.ticker.scheduleWithFixedDelay(this::pumpMessageLogs, 1, 1, TimeUnit.SECONDS);
    }

    private static ThreadFactory daemonFactory(String name) {
        return r -> {
            Thread t = new Thread(r, name);
            t.setDaemon(true);
            return t;
        };
    }

    /**
     * Create a new RUNNING job for the given program, register it, and return it.
     *
     * @param programPath the Ghidra project pathname of the program
     * @return the newly created and registered job
     */
    public AnalysisJob create(String programPath) {
        String jobId = "analysis-" + counter.incrementAndGet();
        AnalysisJob job = new AnalysisJob(jobId, programPath);
        jobs.put(jobId, job);
        prune();
        return job;
    }

    /**
     * Evict the oldest TERMINAL jobs so that at most {@link #MAX_TERMINAL_JOBS} remain.
     *
     * <p>"Oldest" is the smallest numeric id suffix (the part after the last {@code '-'}).
     * Non-terminal (RUNNING/PERSISTING) jobs are never counted toward the cap and are
     * never evicted. Synchronized because {@code create()} may run on concurrent request
     * threads and the count-then-remove sequence is otherwise racy; n is tiny so O(n log n)
     * sorting is fine.
     */
    private synchronized void prune() {
        List<AnalysisJob> terminal = new ArrayList<>();
        for (AnalysisJob job : jobs.values()) {
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

    /**
     * Request cancellation of every non-terminal job belonging to the given program.
     * Called when a program is closed so background analysis on it stops promptly.
     *
     * @param programPath the Ghidra project pathname of the closed program
     */
    public void cancelJobsForProgram(String programPath) {
        for (AnalysisJob job : jobs.values()) {
            if (job.getProgramPath().equals(programPath) && !job.getStatus().isTerminal()) {
                job.requestCancel();
            }
        }
    }

    /**
     * @param jobId the job id
     * @return the job with the given id, or null if none
     */
    public AnalysisJob get(String jobId) {
        return jobs.get(jobId);
    }

    /**
     * Find a non-terminal (RUNNING or PERSISTING) job for the given program.
     *
     * @param programPath the Ghidra project pathname of the program
     * @return a non-terminal job for that path, or null if none exists
     */
    public AnalysisJob runningJobForProgram(String programPath) {
        for (AnalysisJob job : jobs.values()) {
            if (job.getProgramPath().equals(programPath) && !job.getStatus().isTerminal()) {
                return job;
            }
        }
        return null;
    }

    /**
     * @return all registered jobs
     */
    public Collection<AnalysisJob> all() {
        return jobs.values();
    }

    /**
     * Submit a job for background execution. Attaches the program to the job and schedules
     * an {@link AnalysisJobRunner} on the worker thread.
     *
     * @param job the job to run (already created via {@link #create(String)})
     * @param req the analysis request describing what to run
     */
    public void submit(AnalysisJob job, AnalyzeRequest req) {
        job.setProgram(req.program);
        worker.submit(new AnalysisJobRunner(this, job, req));
    }

    /**
     * Atomically reuse the in-flight job for a program, or create and submit a new one. Holds the
     * manager lock across the find+create+submit so two concurrent callers for the same program
     * cannot both launch an analysis (the single-flight guarantee — without this, a check-then-act
     * race lets both observe "no running job" and each start a run, doubling the analysis and the
     * checkin). {@code prune()} (called by {@code create}) shares this monitor, so the lock is
     * reentrant.
     *
     * @param programPath the Ghidra project pathname of the program
     * @param req the analysis request to run if a new job is started
     * @return the existing in-flight job, or the newly created-and-submitted job
     */
    public synchronized AnalysisJob startOrAttach(String programPath, AnalyzeRequest req) {
        AnalysisJob existing = runningJobForProgram(programPath);
        if (existing != null) {
            return existing;
        }
        AnalysisJob job = create(programPath);
        submit(job, req);
        return job;
    }

    /**
     * Request cancellation of every non-terminal job and shut down the worker and ticker.
     */
    public void dispose() {
        for (AnalysisJob job : jobs.values()) {
            if (!job.getStatus().isTerminal()) {
                job.requestCancel();
            }
        }
        worker.shutdownNow();
        ticker.shutdownNow();
    }

    /**
     * Ticker body: for each RUNNING job with an attached program, diff the program's
     * auto-analysis message log and append any new non-blank lines to the job log.
     *
     * <p>Robust to per-job failures and to a failure of the whole pass — a thrown exception
     * here would otherwise permanently stop all future ticks (scheduleWithFixedDelay
     * suppresses subsequent runs after an uncaught throw).
     */
    private void pumpMessageLogs() {
        try {
            for (AnalysisJob job : jobs.values()) {
                try {
                    if (job.getStatus() != Status.RUNNING) {
                        continue;
                    }
                    Program program = job.getProgram();
                    if (program == null) {
                        continue;
                    }
                    AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(program);
                    if (aam == null || aam.getMessageLog() == null) {
                        continue;
                    }
                    String[] lines = aam.getMessageLog().toString().split("\n");
                    int start = job.getLastMessageLineCount();
                    for (int i = start; i < lines.length; i++) {
                        String line = lines[i];
                        if (line != null && !line.isBlank()) {
                            job.appendLog(line);
                        }
                    }
                    job.setLastMessageLineCount(lines.length);
                } catch (Throwable t) {
                    // One bad job must not kill the ticker. Catch Throwable (not just Exception)
                    // so an Error can't slip past and permanently stop scheduleWithFixedDelay.
                    Msg.error(this, "Error pumping analysis log for job " + job.getJobId()
                        + ": " + t.getMessage(), t);
                }
            }
        } catch (Throwable t) {
            // Same reason: a thrown Error here would suppress all future ticks.
            Msg.error(this, "Error in analysis log pump: " + t.getMessage(), t);
        }
    }
}
