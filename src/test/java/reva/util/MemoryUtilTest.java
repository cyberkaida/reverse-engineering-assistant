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
 * Unit tests for the pure-Java methods in MemoryUtil.
 * Tests that do not require a Ghidra environment are included here.
 * Methods that require a live Program/Memory are covered by integration tests.
 */
public class MemoryUtilTest {

    // ========== formatHexString ==========

    @Test
    public void testFormatHexString_NullInput() {
        String result = MemoryUtil.formatHexString(null);
        assertEquals("Null input should produce empty string", "", result);
    }

    @Test
    public void testFormatHexString_EmptyArray() {
        String result = MemoryUtil.formatHexString(new byte[0]);
        assertEquals("Empty array should produce empty string", "", result);
    }

    @Test
    public void testFormatHexString_SingleByte_Zero() {
        String result = MemoryUtil.formatHexString(new byte[]{0x00});
        assertEquals("Single zero byte should format as '00'", "00", result);
    }

    @Test
    public void testFormatHexString_SingleByte_MaxUnsigned() {
        String result = MemoryUtil.formatHexString(new byte[]{(byte) 0xFF});
        assertEquals("0xFF should format as 'FF'", "FF", result);
    }

    @Test
    public void testFormatHexString_SingleByte_SignedNegative() {
        // -1 in signed byte == 0xFF unsigned
        String result = MemoryUtil.formatHexString(new byte[]{(byte) -1});
        assertEquals("Signed -1 byte should format as 'FF'", "FF", result);
    }

    @Test
    public void testFormatHexString_MultipleBytes() {
        byte[] bytes = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello" in ASCII hex
        String result = MemoryUtil.formatHexString(bytes);
        assertEquals("48 65 6C 6C 6F", result);
    }

    @Test
    public void testFormatHexString_UppercaseOutput() {
        // All hex digits should be uppercase (format spec %02X)
        byte[] bytes = {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF};
        String result = MemoryUtil.formatHexString(bytes);
        assertEquals("AB CD EF", result);
        // Ensure no lowercase hex
        assertFalse("Output should be uppercase", result.matches(".*[a-f].*"));
    }

    @Test
    public void testFormatHexString_TwoByteLeadingZero() {
        byte[] bytes = {0x0A, 0x0B};
        String result = MemoryUtil.formatHexString(bytes);
        assertEquals("0A 0B", result);
    }

    @Test
    public void testFormatHexString_SpaceSeparated() {
        // Multiple bytes should be space-separated and trimmed at the end
        byte[] bytes = {0x01, 0x02, 0x03};
        String result = MemoryUtil.formatHexString(bytes);
        // Should not have trailing space
        assertFalse("Result should not end with a space", result.endsWith(" "));
        String[] parts = result.split(" ");
        assertEquals(3, parts.length);
    }

    @Test
    public void testFormatHexString_AllZeroBytes() {
        byte[] bytes = {0x00, 0x00, 0x00};
        String result = MemoryUtil.formatHexString(bytes);
        assertEquals("00 00 00", result);
    }

    @Test
    public void testFormatHexString_MixedValues() {
        byte[] bytes = {0x00, (byte) 0xFF, 0x7F, (byte) 0x80};
        String result = MemoryUtil.formatHexString(bytes);
        assertEquals("00 FF 7F 80", result);
    }

    // ========== byteArrayToIntList ==========

    @Test
    public void testByteArrayToIntList_NullInput() {
        List<Integer> result = MemoryUtil.byteArrayToIntList(null);
        assertNotNull(result);
        assertTrue("Null input should produce empty list", result.isEmpty());
    }

    @Test
    public void testByteArrayToIntList_EmptyArray() {
        List<Integer> result = MemoryUtil.byteArrayToIntList(new byte[0]);
        assertNotNull(result);
        assertTrue("Empty array should produce empty list", result.isEmpty());
    }

    @Test
    public void testByteArrayToIntList_SingleZero() {
        List<Integer> result = MemoryUtil.byteArrayToIntList(new byte[]{0x00});
        assertEquals(1, result.size());
        assertEquals(Integer.valueOf(0), result.get(0));
    }

    @Test
    public void testByteArrayToIntList_SingleMaxByte() {
        List<Integer> result = MemoryUtil.byteArrayToIntList(new byte[]{(byte) 0xFF});
        assertEquals(1, result.size());
        assertEquals("0xFF byte should become 255 (unsigned)", Integer.valueOf(255), result.get(0));
    }

    @Test
    public void testByteArrayToIntList_SignedNegativeBecomesPositiveInt() {
        // Java byte is signed: -128 == 0x80, should become 128 in the list
        List<Integer> result = MemoryUtil.byteArrayToIntList(new byte[]{(byte) -128});
        assertEquals(1, result.size());
        assertEquals(Integer.valueOf(128), result.get(0));
    }

    @Test
    public void testByteArrayToIntList_AllValuesInRange() {
        // Every value in the result list must be in [0, 255]
        byte[] all256 = new byte[256];
        for (int i = 0; i < 256; i++) {
            all256[i] = (byte) i;
        }
        List<Integer> result = MemoryUtil.byteArrayToIntList(all256);
        assertEquals(256, result.size());
        for (int i = 0; i < 256; i++) {
            int val = result.get(i);
            assertTrue("Value must be >= 0", val >= 0);
            assertTrue("Value must be <= 255", val <= 255);
            assertEquals("Value at index " + i + " should be " + i, i, val);
        }
    }

    @Test
    public void testByteArrayToIntList_MultipleBytes() {
        byte[] bytes = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
        List<Integer> result = MemoryUtil.byteArrayToIntList(bytes);
        assertEquals(5, result.size());
        assertEquals(Integer.valueOf(0x48), result.get(0));
        assertEquals(Integer.valueOf(0x65), result.get(1));
        assertEquals(Integer.valueOf(0x6C), result.get(2));
        assertEquals(Integer.valueOf(0x6C), result.get(3));
        assertEquals(Integer.valueOf(0x6F), result.get(4));
    }

    @Test
    public void testByteArrayToIntList_OrderPreserved() {
        byte[] bytes = {0x01, 0x02, 0x03, 0x04};
        List<Integer> result = MemoryUtil.byteArrayToIntList(bytes);
        assertEquals(Integer.valueOf(1), result.get(0));
        assertEquals(Integer.valueOf(2), result.get(1));
        assertEquals(Integer.valueOf(3), result.get(2));
        assertEquals(Integer.valueOf(4), result.get(3));
    }

    @Test
    public void testByteArrayToIntList_NoSignExtension() {
        // Ensure (byte & 0xFF) is applied - no negative integers
        byte[] bytes = {(byte) 0x80, (byte) 0x90, (byte) 0xA0, (byte) 0xFF};
        List<Integer> result = MemoryUtil.byteArrayToIntList(bytes);
        for (Integer val : result) {
            assertTrue("No negative values should appear", val >= 0);
        }
        assertEquals(Integer.valueOf(128), result.get(0));
        assertEquals(Integer.valueOf(144), result.get(1));
        assertEquals(Integer.valueOf(160), result.get(2));
        assertEquals(Integer.valueOf(255), result.get(3));
    }

    // ========== consistency between formatHexString and byteArrayToIntList ==========

    @Test
    public void testConsistency_FormatAndIntList() {
        // Both methods should agree on the byte values they observe
        byte[] bytes = {0x12, (byte) 0xAB, 0x00, (byte) 0xFF};

        String hexStr = MemoryUtil.formatHexString(bytes);
        List<Integer> intList = MemoryUtil.byteArrayToIntList(bytes);

        String[] hexParts = hexStr.split(" ");
        assertEquals("Hex string and int list must have same length", hexParts.length, intList.size());

        for (int i = 0; i < hexParts.length; i++) {
            int fromHex = Integer.parseInt(hexParts[i], 16);
            int fromList = intList.get(i);
            assertEquals("Values must agree at index " + i, fromHex, fromList);
        }
    }
}
