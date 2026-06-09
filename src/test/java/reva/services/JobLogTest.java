package reva.services;

import static org.junit.Assert.*;
import org.junit.Test;
import reva.services.JobLog.LogPage;

public class JobLogTest {
    @Test
    public void testSeqMonotonicAndCursorPaging() {
        JobLog log = new JobLog(System.currentTimeMillis());
        log.append("a");
        log.append("b");
        log.append("c");
        LogPage first = log.logSince(0, 2);
        assertEquals(2, first.entries.size());
        assertEquals(1, first.entries.get(0).seq);
        assertEquals(2, first.entries.get(1).seq);
        assertEquals(2, first.nextCursor);
        assertTrue(first.truncated);
        LogPage second = log.logSince(first.nextCursor, 2);
        assertEquals(1, second.entries.size());
        assertEquals("c", second.entries.get(0).message);
        assertEquals(3, second.nextCursor);
        assertFalse(second.truncated);
    }

    @Test
    public void testAppendDedupedSuppressesConsecutiveRepeats() {
        JobLog log = new JobLog(System.currentTimeMillis());
        log.appendDeduped("x");
        log.appendDeduped("x");
        log.appendDeduped("y");
        assertEquals(2, log.logSince(0, 100).entries.size());
        assertEquals("y", log.latestMessage());
    }

    @Test
    public void testEmptyPageReturnsSinceSeqAsCursor() {
        JobLog log = new JobLog(System.currentTimeMillis());
        LogPage p = log.logSince(0, 10);
        assertEquals(0, p.entries.size());
        assertEquals(0, p.nextCursor);
        assertFalse(p.truncated);
    }
}
