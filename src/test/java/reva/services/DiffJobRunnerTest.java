package reva.services;

import static org.junit.Assert.*;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.After;
import org.junit.Test;

public class DiffJobRunnerTest {
    private DiffJobManager mgr;

    @After
    public void tearDown() { if (mgr != null) mgr.dispose(); }

    private DiffJob await(DiffJob job) throws Exception {
        for (int i = 0; i < 300 && !job.getStatus().isTerminal(); i++) Thread.sleep(10);
        return job;
    }

    @Test
    public void testCompletedStoresResult() throws Exception {
        mgr = new DiffJobManager();
        DiffJob job = mgr.startOrAttach(DiffJobKind.CORRELATE, "/s", "/d",
            () -> monitor -> Map.of("matched", 7), -1);
        await(job);
        assertEquals(JobStatus.COMPLETED, job.getStatus());
        assertEquals(7, job.getResult().get("matched"));
    }

    @Test
    public void testThrownExceptionBecomesFailed() throws Exception {
        mgr = new DiffJobManager();
        DiffJob job = mgr.startOrAttach(DiffJobKind.CORRELATE, "/s", "/d",
            () -> monitor -> { throw new java.io.IOException("boom"); }, -1);
        await(job);
        assertEquals(JobStatus.FAILED, job.getStatus());
        assertEquals("boom", job.getError());
    }

    @Test
    public void testCancelDuringWorkBecomesCancelled() throws Exception {
        mgr = new DiffJobManager();
        CountDownLatch started = new CountDownLatch(1);
        DiffJob job = mgr.startOrAttach(DiffJobKind.TRANSFER_MARKUP, "/s", "/d",
            () -> monitor -> {
                started.countDown();           // signal: worker is inside the work closure
                while (!monitor.isCancelled()) Thread.sleep(10);
                throw new ghidra.util.exception.CancelledException();
            }, -1);
        assertTrue(started.await(2, TimeUnit.SECONDS));
        job.requestCancel();
        await(job);
        assertEquals(JobStatus.CANCELLED, job.getStatus());
    }
}
