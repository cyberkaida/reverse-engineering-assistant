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
package reva.util;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

/**
 * Unit tests for the text renderings produced by MemoryUtil.
 */
public class MemoryUtilFormatTest {

    @Test
    public void asciiRenderingEscapesNonPrintables() {
        byte[] bytes = {0x53, 0x4f, 0x0a, 0x01};
        assertEquals("SO\\n\\x01", MemoryUtil.formatAscii(bytes));
    }

    @Test
    public void asciiRenderingKeepsPrintableRangeAndEscapesTheRest() {
        byte[] bytes = {0x20, 0x41, 0x7e, 0x7f, (byte) 0xff};
        assertEquals(" A~\\x7F\\xFF", MemoryUtil.formatAscii(bytes));
    }

    @Test
    public void asciiRenderingEscapesTab() {
        assertEquals("\\t", MemoryUtil.formatAscii(new byte[] {0x09}));
    }

    @Test
    public void emptyAndNullInputsRenderEmpty() {
        assertEquals("", MemoryUtil.formatAscii(null));
        assertEquals("", MemoryUtil.formatAscii(new byte[0]));
        assertEquals("", MemoryUtil.formatUtf16(null));
        assertEquals("", MemoryUtil.formatUtf16(new byte[0]));
    }

    @Test
    public void utf16RenderingCollapsesByteSpacedText() {
        byte[] bytes = {'S', 0, 'O', 0};
        assertEquals("SO", MemoryUtil.formatUtf16(bytes));
    }

    @Test
    public void utf16RenderingEscapesControlUnits() {
        byte[] bytes = {'\n', 0, '\t', 0, 0x01, 0};
        assertEquals("\\n\\t\\u0001", MemoryUtil.formatUtf16(bytes));
    }

    @Test
    public void utf16RenderingKeepsPrintableBmpUnits() {
        // U+00E9 LATIN SMALL LETTER E WITH ACUTE, little-endian.
        byte[] bytes = {(byte) 0xE9, 0};
        assertEquals("\u00E9", MemoryUtil.formatUtf16(bytes));
    }

    @Test
    public void utf16RenderingEscapesLoneTrailingByte() {
        byte[] bytes = {'S', 0, 0x00};
        assertEquals("S\\x00", MemoryUtil.formatUtf16(bytes));
    }

    @Test
    public void hexFormattingIsUnchanged() {
        assertEquals("53 4F", MemoryUtil.formatHexString(new byte[] {0x53, 0x4f}));
    }

    @Test
    public void intListConversionIsUnchanged() {
        assertEquals(List.of(0x53, 0x4f),
            MemoryUtil.byteArrayToIntList(new byte[] {0x53, 0x4f}));
    }
}
