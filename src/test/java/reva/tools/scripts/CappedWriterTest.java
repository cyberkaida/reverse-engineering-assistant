/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.tools.scripts;

import static org.junit.Assert.*;

import java.io.PrintWriter;

import org.junit.Test;

/**
 * Unit tests for {@link CappedWriter}.
 *
 * The CappedWriter captures characters up to a configured cap, then silently
 * drops the rest while reporting truncation. Used to bound stdout/stderr
 * capture from user-supplied scripts so a runaway `print` loop can't bloat
 * the MCP response.
 */
public class CappedWriterTest {

    @Test
    public void writesUnderCapAreCapturedVerbatim() {
        CappedWriter writer = new CappedWriter(100);
        writer.write("hello world");
        assertEquals("hello world", writer.getCapturedString());
        assertFalse("under cap should not be truncated", writer.isTruncated());
    }

    @Test
    public void writeUpToCapExactlyIsNotTruncated() {
        CappedWriter writer = new CappedWriter(5);
        writer.write("12345");
        assertEquals("12345", writer.getCapturedString());
        assertFalse("exact cap should not be truncated", writer.isTruncated());
    }

    @Test
    public void writePastCapIsTruncatedAtBoundary() {
        CappedWriter writer = new CappedWriter(5);
        writer.write("1234567890");
        assertEquals("12345", writer.getCapturedString());
        assertTrue("over cap should be truncated", writer.isTruncated());
    }

    @Test
    public void multipleWritesAccumulateAndTruncate() {
        CappedWriter writer = new CappedWriter(7);
        writer.write("hello ");
        writer.write("world!!!");
        assertEquals("hello w", writer.getCapturedString());
        assertTrue(writer.isTruncated());
    }

    @Test
    public void writesAfterTruncationAreDropped() {
        CappedWriter writer = new CappedWriter(3);
        writer.write("abc");
        writer.write("def");
        writer.write("ghi");
        assertEquals("abc", writer.getCapturedString());
        assertTrue(writer.isTruncated());
    }

    @Test
    public void worksAsPrintWriterTarget() {
        CappedWriter writer = new CappedWriter(20);
        PrintWriter pw = new PrintWriter(writer);
        pw.println("line one");
        pw.println("this line goes past the cap");
        pw.flush();
        String captured = writer.getCapturedString();
        assertTrue("captured prefix should be present, got: " + captured,
            captured.startsWith("line one"));
        assertTrue("cap should be reached", captured.length() <= 20);
        assertTrue("should report truncation", writer.isTruncated());
    }

    @Test
    public void emptyWriteDoesNotMarkTruncated() {
        CappedWriter writer = new CappedWriter(0);
        writer.write("");
        assertEquals("", writer.getCapturedString());
        assertFalse("empty write at zero cap should not be truncated",
            writer.isTruncated());
    }

    @Test
    public void zeroCapWithAnyContentIsTruncated() {
        CappedWriter writer = new CappedWriter(0);
        writer.write("x");
        assertEquals("", writer.getCapturedString());
        assertTrue(writer.isTruncated());
    }

    @Test
    public void writeWithOffsetAndLengthHonoursCap() {
        CappedWriter writer = new CappedWriter(4);
        char[] buf = "abcdefghij".toCharArray();
        writer.write(buf, 2, 6); // would write "cdefgh"
        assertEquals("cdef", writer.getCapturedString());
        assertTrue(writer.isTruncated());
    }

    @Test(expected = IllegalArgumentException.class)
    public void negativeCapIsRejected() {
        new CappedWriter(-1);
    }

    /**
     * The cap exists to bound memory growth from untrusted script output. The
     * String overload must NOT allocate a buffer proportional to the input
     * length — otherwise a single huge {@code print} could OOM the JVM even
     * though we'd only keep 64K of the result.
     *
     * Measure via {@code ThreadMXBean.getThreadAllocatedBytes} which is a
     * cumulative allocation counter — unaffected by GC reclaiming the temp
     * buffer between measurements (which is why a heap-delta probe is
     * unreliable here). A {@code char[len]} regression on a 16 MiB input
     * would add at least 32 MiB to the thread's allocation counter; the
     * fixed path should add only a few KiB of {@code StringBuilder} growth.
     */
    @Test
    public void largeStringWriteDoesNotAllocateProportionalBuffer() {
        com.sun.management.ThreadMXBean tmx =
            (com.sun.management.ThreadMXBean)
                java.lang.management.ManagementFactory.getThreadMXBean();
        org.junit.Assume.assumeTrue(
            "ThreadMXBean allocation counter not supported on this JVM",
            tmx.isThreadAllocatedMemorySupported()
                && tmx.isThreadAllocatedMemoryEnabled());

        // Allocate the input out of band — we want the counter to only see
        // what write() itself allocates.
        String huge = "x".repeat(16 * 1024 * 1024);
        CappedWriter writer = new CappedWriter(1024);
        long tid = Thread.currentThread().getId();

        long before = tmx.getThreadAllocatedBytes(tid);
        writer.write(huge);
        long after = tmx.getThreadAllocatedBytes(tid);
        long delta = after - before;

        // char[16M] is 32MB. Bounded copying should be well under 1MB even
        // accounting for StringBuilder growth and JIT side effects.
        assertTrue(
            "write(String) must not allocate proportional to input length; "
                + "delta=" + delta + " bytes",
            delta < 1L * 1024 * 1024);
        assertEquals(1024, writer.getCapturedString().length());
        assertTrue(writer.isTruncated());
    }

    @Test
    public void largeStringWriteWithOffsetHonoursCapAndAvoidsFullBuffer() {
        CappedWriter writer = new CappedWriter(8);
        String huge = "x".repeat(10 * 1024 * 1024);  // 10 MiB
        // Offset deep into the string; cap should still clamp to 8 chars.
        writer.write(huge, 1_000_000, 5_000_000);
        assertEquals(8, writer.getCapturedString().length());
        assertTrue(writer.isTruncated());
    }
}
