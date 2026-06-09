package reva.services;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class AnalysisJobManagerTest {
    private AnalysisJobManager mgr;

    @Before public void setUp() { mgr = new AnalysisJobManager(); }

    @Test public void registersJobWithUniqueIds() {
        AnalysisJob a = mgr.create("/a.exe");
        AnalysisJob b = mgr.create("/b.exe");
        assertNotEquals(a.getJobId(), b.getJobId());
        assertSame(a, mgr.get(a.getJobId()));
        assertEquals(JobStatus.RUNNING, a.getStatus());
    }

    @Test public void logCursorReturnsOnlyNewEntries() {
        AnalysisJob a = mgr.create("/a.exe");
        a.appendLog("one"); a.appendLog("two"); a.appendLog("three");
        JobLog.LogPage p1 = a.logSince(0, 10);
        assertEquals(3, p1.entries.size());
        assertEquals(3, p1.nextCursor);
        a.appendLog("four");
        JobLog.LogPage p2 = a.logSince(p1.nextCursor, 10);
        assertEquals(1, p2.entries.size());
        assertEquals("four", p2.entries.get(0).message);
        assertEquals(4, p2.nextCursor);
    }

    @Test public void logPageTruncatesAtMaxAndFlags() {
        AnalysisJob a = mgr.create("/a.exe");
        for (int i = 0; i < 100; i++) a.appendLog("line" + i);
        JobLog.LogPage p = a.logSince(0, 50);
        assertEquals(50, p.entries.size());
        assertTrue(p.truncated);
        assertEquals(50, p.nextCursor);
    }

    @Test public void singleFlightFindsActiveJobForProgram() {
        AnalysisJob a = mgr.create("/a.exe");
        assertSame(a, mgr.runningJobForProgram("/a.exe"));
        a.markTerminal(JobStatus.COMPLETED);
        assertNull(mgr.runningJobForProgram("/a.exe"));
    }

    @Test public void terminalStatusIsTerminal() {
        AnalysisJob a = mgr.create("/a.exe");
        assertFalse(a.getStatus().isTerminal());
        a.markTerminal(JobStatus.CANCELLED);
        assertTrue(a.getStatus().isTerminal());
    }

    @Test public void retainsAtMostMaxTerminalJobsEvictingOldest() {
        AnalysisJob first = mgr.create("/a.exe");
        first.markTerminal(JobStatus.COMPLETED);
        AnalysisJob lastTerminal = null;
        for (int i = 1; i < 60; i++) {
            AnalysisJob job = mgr.create("/a.exe");
            job.markTerminal(JobStatus.COMPLETED);
            lastTerminal = job;
        }
        // 60 terminal jobs created; creating one more (active) triggers prune.
        AnalysisJob newest = mgr.create("/a.exe");

        int terminalCount = 0;
        for (AnalysisJob job : mgr.all()) {
            if (job.getStatus().isTerminal()) {
                terminalCount++;
            }
        }
        assertTrue("terminal jobs should be capped at 50", terminalCount <= 50);
        assertNull("oldest terminal job should be evicted", mgr.get(first.getJobId()));
        assertSame("most-recent terminal job should be retained",
            lastTerminal, mgr.get(lastTerminal.getJobId()));
        assertSame("newest active job should be retained",
            newest, mgr.get(newest.getJobId()));
    }

    @Test public void pruneNeverEvictsActiveJobs() {
        java.util.List<AnalysisJob> created = new java.util.ArrayList<>();
        for (int i = 0; i < 60; i++) {
            created.add(mgr.create("/a.exe"));
        }
        // None marked terminal; creating one more must not evict any.
        created.add(mgr.create("/a.exe"));

        for (AnalysisJob job : created) {
            assertSame("active job must not be evicted", job, mgr.get(job.getJobId()));
        }
    }

    @Test public void cancelJobsForProgramCancelsOnlyMatchingActiveJobs() {
        AnalysisJob aActive = mgr.create("/a.exe");
        AnalysisJob aTerminal = mgr.create("/a.exe");
        aTerminal.markTerminal(JobStatus.COMPLETED);
        AnalysisJob bActive = mgr.create("/b.exe");

        mgr.cancelJobsForProgram("/a.exe");

        assertTrue("active /a.exe job should be cancel-requested", aActive.isCancelRequested());
        assertFalse("terminal /a.exe job should be untouched", aTerminal.isCancelRequested());
        assertFalse("/b.exe job should be untouched", bActive.isCancelRequested());
    }

    @Test public void disposeRequestsCancelOnActiveJobs() {
        AnalysisJob a = mgr.create("/a.exe");
        AnalysisJob b = mgr.create("/b.exe");
        mgr.dispose();
        assertTrue(a.isCancelRequested());
        assertTrue(b.isCancelRequested());
    }
}
