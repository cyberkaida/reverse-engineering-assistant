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

import java.io.Writer;

/**
 * A {@link Writer} that captures up to a configured number of characters and
 * silently drops any further input, while tracking whether truncation occurred.
 *
 * Used to bound stdout/stderr capture from user-supplied scripts so a runaway
 * {@code print} loop cannot bloat the MCP response.
 */
public class CappedWriter extends Writer {

    private final StringBuilder buffer = new StringBuilder();
    private final int capChars;
    private boolean truncated = false;

    /**
     * @param capChars maximum number of characters to capture; further writes
     *                 are silently dropped
     */
    public CappedWriter(int capChars) {
        if (capChars < 0) {
            throw new IllegalArgumentException("capChars must be non-negative");
        }
        this.capChars = capChars;
    }

    @Override
    public void write(char[] cbuf, int off, int len) {
        if (len <= 0) {
            return;
        }
        int remaining = capChars - buffer.length();
        if (remaining <= 0) {
            truncated = true;
            return;
        }
        int toWrite = Math.min(len, remaining);
        buffer.append(cbuf, off, toWrite);
        if (toWrite < len) {
            truncated = true;
        }
    }

    @Override
    public void write(String str) {
        write(str, 0, str.length());
    }

    @Override
    public void write(String str, int off, int len) {
        if (len <= 0) {
            return;
        }
        int remaining = capChars - buffer.length();
        if (remaining <= 0) {
            truncated = true;
            return;
        }
        int toAppend = Math.min(len, remaining);
        // StringBuilder.append(CharSequence, start, end) reads directly from
        // the String without materialising a separate char[] — critical for
        // bounding memory when a script prints a huge string at once.
        buffer.append((CharSequence) str, off, off + toAppend);
        if (toAppend < len) {
            truncated = true;
        }
    }

    @Override
    public void flush() {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    /** @return the characters captured so far (never exceeds the cap) */
    public String getCapturedString() {
        return buffer.toString();
    }

    /** @return true if at least one character was dropped because of the cap */
    public boolean isTruncated() {
        return truncated;
    }
}
