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

import org.junit.Test;

/**
 * Test class for SymbolUtil utility methods.
 */
public class SymbolUtilTest {

    /**
     * Test the isDefaultSymbolName method with valid Ghidra default function names.
     */
    @Test
    public void testIsDefaultSymbolName_FunctionNames() {
        // Valid function names
        assertTrue("FUN_00000000 should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("FUN_00000000"));
        assertTrue("FUN_12345678 should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("FUN_12345678"));
        assertTrue("FUN_deadbeef should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("FUN_deadbeef"));
        assertTrue("FUN_DEADBEEF should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("FUN_DEADBEEF"));
        assertTrue("FUN_abcDEF12 should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("FUN_abcDEF12"));
    }

    /**
     * Test the isDefaultSymbolName method with valid Ghidra default label names.
     */
    @Test
    public void testIsDefaultSymbolName_LabelNames() {
        // Valid label names
        assertTrue("LAB_00000000 should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("LAB_00000000"));
        assertTrue("LAB_12345678 should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("LAB_12345678"));
        assertTrue("LAB_deadbeef should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("LAB_deadbeef"));
    }

    /**
     * Test the isDefaultSymbolName method with valid Ghidra default subroutine names.
     */
    @Test
    public void testIsDefaultSymbolName_SubroutineNames() {
        // Valid subroutine names
        assertTrue("SUB_00000000 should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("SUB_00000000"));
        assertTrue("SUB_87654321 should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("SUB_87654321"));
    }

    /**
     * Test the isDefaultSymbolName method with valid Ghidra default data names.
     */
    @Test
    public void testIsDefaultSymbolName_DataNames() {
        // Valid data names
        assertTrue("DAT_00000000 should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("DAT_00000000"));
        assertTrue("DAT_12345678 should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("DAT_12345678"));
    }

    /**
     * Test the isDefaultSymbolName method with valid Ghidra default external names.
     */
    @Test
    public void testIsDefaultSymbolName_ExternalNames() {
        // Valid external names
        assertTrue("EXT_00000000 should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("EXT_00000000"));
        assertTrue("EXT_abcdef12 should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("EXT_abcdef12"));
    }

    /**
     * Test the isDefaultSymbolName method with valid Ghidra default pointer names.
     */
    @Test
    public void testIsDefaultSymbolName_PointerNames() {
        // Valid pointer names
        assertTrue("PTR_00000000 should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("PTR_00000000"));
        assertTrue("PTR_fedcba98 should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("PTR_fedcba98"));
    }

    /**
     * Test the isDefaultSymbolName method with valid Ghidra default array names.
     */
    @Test
    public void testIsDefaultSymbolName_ArrayNames() {
        // Valid array names
        assertTrue("ARRAY_00000000 should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("ARRAY_00000000"));
        assertTrue("ARRAY_12345678 should be recognized as default",
                   SymbolUtil.isDefaultSymbolName("ARRAY_12345678"));
    }

    /**
     * Test the isDefaultSymbolName method with custom/user-defined symbol names.
     */
    @Test
    public void testIsDefaultSymbolName_CustomNames() {
        // Custom function names - should not be recognized as default
        assertFalse("main should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("main"));
        assertFalse("printf should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("printf"));
        assertFalse("myFunction should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("myFunction"));
        assertFalse("calculateSum should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("calculateSum"));

        // Custom variable names
        assertFalse("myVariable should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("myVariable"));
        assertFalse("buffer should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("buffer"));
        assertFalse("counter should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("counter"));
    }

    /**
     * Test the isDefaultSymbolName method with invalid format names.
     */
    @Test
    public void testIsDefaultSymbolName_InvalidFormat() {
        // Invalid format - missing underscore
        assertFalse("FUN00000000 should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("FUN00000000"));

        // Invalid format - wrong prefix
        assertFalse("FUNC_00000000 should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("FUNC_00000000"));
        assertFalse("FUNCTION_00000000 should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("FUNCTION_00000000"));

        // Invalid format - non-hex characters
        assertFalse("FUN_0000000g should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("FUN_0000000g"));
        assertFalse("FUN_0000000z should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("FUN_0000000z"));

        // Invalid format - empty hex part
        assertFalse("FUN_ should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("FUN_"));

        // Invalid format - multiple underscores
        assertFalse("FUN__00000000 should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("FUN__00000000"));
        assertFalse("FUN_000_00000 should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("FUN_000_00000"));

        // Invalid format - lowercase prefix
        assertFalse("fun_00000000 should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("fun_00000000"));
        assertFalse("lab_00000000 should not be recognized as default",
                    SymbolUtil.isDefaultSymbolName("lab_00000000"));
    }

    /**
     * Test the isDefaultSymbolName method with null input.
     */
    @Test
    public void testIsDefaultSymbolName_NullInput() {
        assertFalse("null input should return false",
                    SymbolUtil.isDefaultSymbolName(null));
    }

    /**
     * Test the isDefaultSymbolName method with empty string input.
     */
    @Test
    public void testIsDefaultSymbolName_EmptyString() {
        assertFalse("empty string should return false",
                    SymbolUtil.isDefaultSymbolName(""));
    }

    /**
     * Test the isDefaultSymbolName method with whitespace input.
     */
    @Test
    public void testIsDefaultSymbolName_Whitespace() {
        assertFalse("whitespace should return false",
                    SymbolUtil.isDefaultSymbolName("   "));
        assertFalse("tab should return false",
                    SymbolUtil.isDefaultSymbolName("\t"));
        assertFalse("newline should return false",
                    SymbolUtil.isDefaultSymbolName("\n"));
    }

    /**
     * Test the isDefaultSymbolName method with edge cases.
     */
    @Test
    public void testIsDefaultSymbolName_EdgeCases() {
        // Valid edge cases - hex numbers can be any length
        assertTrue("Single digit hex should work",
                   SymbolUtil.isDefaultSymbolName("FUN_0"));
        assertTrue("Long hex should work",
                   SymbolUtil.isDefaultSymbolName("FUN_123456789abcdef0"));
        assertTrue("Short hex should work",
                   SymbolUtil.isDefaultSymbolName("FUN_123"));

        // Edge case - symbol with leading/trailing spaces
        assertFalse("Symbol with leading space should not match",
                    SymbolUtil.isDefaultSymbolName(" FUN_00000000"));
        assertFalse("Symbol with trailing space should not match",
                    SymbolUtil.isDefaultSymbolName("FUN_00000000 "));

        // Mixed case in hex part (should be valid)
        assertTrue("Mixed case hex should work",
                   SymbolUtil.isDefaultSymbolName("FUN_AbCdEf12"));

        // Invalid - empty hex part
        assertFalse("Empty hex part should not work",
                    SymbolUtil.isDefaultSymbolName("FUN_"));
    }

    /**
     * Test the isDefaultSymbolName method with all supported prefixes.
     */
    @Test
    public void testIsDefaultSymbolName_AllPrefixes() {
        String[] validPrefixes = {"FUN", "LAB", "SUB", "DAT", "EXT", "PTR", "ARRAY"};
        String hexSuffix = "_12345678";

        for (String prefix : validPrefixes) {
            String symbolName = prefix + hexSuffix;
            assertTrue(prefix + " prefix should be recognized as default",
                       SymbolUtil.isDefaultSymbolName(symbolName));
        }
    }

    /**
     * Test the isDefaultSymbolName method with unsupported prefixes.
     */
    @Test
    public void testIsDefaultSymbolName_UnsupportedPrefixes() {
        String[] invalidPrefixes = {"VAR", "CONST", "STRUCT", "CLASS", "ENUM", "UNION", "TYPEDEF"};
        String hexSuffix = "_12345678";

        for (String prefix : invalidPrefixes) {
            String symbolName = prefix + hexSuffix;
            assertFalse(prefix + " prefix should not be recognized as default",
                        SymbolUtil.isDefaultSymbolName(symbolName));
        }
    }

    /**
     * Test the isDefaultSymbolName method with regex edge cases and boundary conditions.
     */
    @Test
    public void testIsDefaultSymbolName_RegexBoundaryConditions() {
        // Test minimum valid hex length (1 character)
        assertTrue("Single hex digit should be valid",
                   SymbolUtil.isDefaultSymbolName("FUN_A"));
        assertTrue("Single hex digit 0 should be valid",
                   SymbolUtil.isDefaultSymbolName("LAB_0"));
        assertTrue("Single hex digit F should be valid",
                   SymbolUtil.isDefaultSymbolName("DAT_F"));

        // Test all valid hex digits
        assertTrue("All lowercase hex digits should work",
                   SymbolUtil.isDefaultSymbolName("FUN_0123456789abcdef"));
        assertTrue("All uppercase hex digits should work",
                   SymbolUtil.isDefaultSymbolName("FUN_0123456789ABCDEF"));

        // Test invalid characters in hex part
        assertFalse("Letter g should not be valid",
                    SymbolUtil.isDefaultSymbolName("FUN_123g"));
        assertFalse("Letter G should not be valid",
                    SymbolUtil.isDefaultSymbolName("FUN_123G"));
        assertFalse("Special characters should not be valid",
                    SymbolUtil.isDefaultSymbolName("FUN_123!"));
        assertFalse("Space in hex should not be valid",
                    SymbolUtil.isDefaultSymbolName("FUN_123 456"));
        assertFalse("Hyphen in hex should not be valid",
                    SymbolUtil.isDefaultSymbolName("FUN_123-456"));

        // Test case sensitivity of prefix
        assertFalse("Lowercase prefix should not match",
                    SymbolUtil.isDefaultSymbolName("fun_123456"));
        assertFalse("Mixed case prefix should not match",
                    SymbolUtil.isDefaultSymbolName("Fun_123456"));
        assertFalse("Partial lowercase prefix should not match",
                    SymbolUtil.isDefaultSymbolName("FUn_123456"));
    }

    /**
     * Test the isDefaultSymbolName method with complex invalid patterns.
     */
    @Test
    public void testIsDefaultSymbolName_ComplexInvalidPatterns() {
        // Multiple underscores
        assertFalse("Double underscore should not match",
                    SymbolUtil.isDefaultSymbolName("FUN__123456"));
        assertFalse("Underscore in hex should not match",
                    SymbolUtil.isDefaultSymbolName("FUN_123_456"));
        assertFalse("Trailing underscore should not match",
                    SymbolUtil.isDefaultSymbolName("FUN_123456_"));

        // Missing parts
        assertFalse("Missing underscore should not match",
                    SymbolUtil.isDefaultSymbolName("FUN123456"));
        assertFalse("Missing prefix should not match",
                    SymbolUtil.isDefaultSymbolName("_123456"));

        // Extra content
        assertFalse("Extra text after hex should not match",
                    SymbolUtil.isDefaultSymbolName("FUN_123456extra"));
        assertFalse("Extra text before prefix should not match",
                    SymbolUtil.isDefaultSymbolName("extraFUN_123456"));
        assertFalse("Parentheses should not match",
                    SymbolUtil.isDefaultSymbolName("FUN_123456()"));

        // Very long patterns (should still work if they're valid hex)
        String longHex = "1234567890abcdef".repeat(10); // 160 hex chars
        assertTrue("Very long hex should work if valid",
                   SymbolUtil.isDefaultSymbolName("FUN_" + longHex));

        // Very long invalid patterns
        String longInvalidHex = longHex + "g";
        assertFalse("Very long invalid hex should not work",
                    SymbolUtil.isDefaultSymbolName("FUN_" + longInvalidHex));
    }
}
