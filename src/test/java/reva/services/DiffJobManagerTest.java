package reva.services;

import static org.junit.Assert.*;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.After;
import org.junit.Test;

public class DiffJobManagerTest {
    private DiffJobManager mgr;

    @After
    public void tearDown() { if (mgr != null) mgr.dispose(); }

    /** A work that signals it started, then blocks until the monitor is cancelled. */
    private DiffWork blockingWork(CountDownLatch started) {
        return monitor -> {
            started.countDown();
            while (!monitor.isCancelled()) {
                Thread.sleep(10);
            }
            throw new ghidra.util.exception.CancelledException();
        };
    }

    @Test
    public void testStartOrAttachSingleFlightSamePairAndKind() throws Exception {
        mgr = new DiffJobManager();
        CountDownLatch started = new CountDownLatch(1);
        DiffJob a = mgr.startOrAttach(DiffJobKind.CORRELATE, "/s", "/d", () -> blockingWork(started), -1);
        assertTrue(started.await(2, TimeUnit.SECONDS));
        // Second identical call attaches to the same running job — supplier must NOT run again.
        DiffJob b = mgr.startOrAttach(DiffJobKind.CORRELATE, "/s", "/d",
            () -> { throw new AssertionError("supplier ran on attach"); }, -1);
        assertSame(a, b);
    }

    @Test
    public void testDifferentKindGetsSeparateJob() throws Exception {
        mgr = new DiffJobManager();
        CountDownLatch s1 = new CountDownLatch(1);
        // The single-thread worker serializes jobs, so TRANSFER_MARKUP queues behind the
        // blocking CORRELATE job. We only need to verify they are separate job objects —
        // waiting for s1 confirms CORRELATE is running, and the assertNotSame check is
        // sufficient proof that different kinds don't share a job.
        DiffJob c = mgr.startOrAttach(DiffJobKind.CORRELATE, "/s", "/d", () -> blockingWork(s1), -1);
        DiffJob t = mgr.startOrAttach(DiffJobKind.TRANSFER_MARKUP, "/s", "/d",
            () -> monitor -> java.util.Map.of("kind", "transfer"), -1);
        assertTrue(s1.await(2, TimeUnit.SECONDS));
        assertNotSame(c, t);
        assertNotEquals(c.getJobId(), t.getJobId());
    }

    @Test
    public void testCancelJobsForProgramMatchesEitherSide() throws Exception {
        mgr = new DiffJobManager();
        CountDownLatch started = new CountDownLatch(1);
        DiffJob job = mgr.startOrAttach(DiffJobKind.CORRELATE, "/s", "/d", () -> blockingWork(started), -1);
        assertTrue(started.await(2, TimeUnit.SECONDS));
        mgr.cancelJobsForProgram("/d"); // matches destination
        for (int i = 0; i < 200 && !job.getStatus().isTerminal(); i++) Thread.sleep(10);
        assertEquals(JobStatus.CANCELLED, job.getStatus());
    }

    @Test
    public void testLatestForPairReturnsHighestId() {
        mgr = new DiffJobManager();
        DiffJob a = mgr.create(DiffJobKind.CORRELATE, "/s", "/d");
        DiffJob b = mgr.create(DiffJobKind.TRANSFER_MARKUP, "/s", "/d");
        assertSame(b, mgr.latestForPair("/s", "/d"));
        a.markTerminal(JobStatus.COMPLETED);
        b.markTerminal(JobStatus.COMPLETED);
    }
}
