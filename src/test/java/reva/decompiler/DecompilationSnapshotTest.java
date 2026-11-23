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
package reva.decompiler;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;

import reva.decompiler.DecompilationSnapshot.Line;

public class DecompilationSnapshotTest {

    private final AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);

    private Address a(long off) {
        return space.getAddress(off);
    }

    private static Line line(int n, List<Address> tokens, Address closest) {
        return new Line(n, tokens, closest);
    }

    private DecompilationSnapshot snap(String code, Line... lines) {
        return new DecompilationSnapshot(code, "void f(void)", List.of(lines));
    }

    @Test
    public void lineForAddressReturnsFirstMatchingLine() {
        Address x = a(0x40);
        DecompilationSnapshot s = snap("a\nb\nc\nd\ne",
            line(1, List.of(a(0x10)), a(0x10)),
            line(3, List.of(a(0x30)), x),
            line(5, List.of(x), a(0x50)));
        assertEquals(3, s.lineForAddress(x));
    }

    @Test
    public void lineForAddressReturnsMinusOneWhenAbsent() {
        DecompilationSnapshot s = snap("a", line(1, List.of(a(0x10)), a(0x10)));
        assertEquals(-1, s.lineForAddress(a(0x99)));
        assertEquals(-1, s.lineForAddress(null));
    }

    @Test
    public void addressForLineFallsBackToClosest() {
        DecompilationSnapshot s = snap("a\nb",
            line(1, List.of(), a(0x10)),
            line(2, List.of(a(0x20), a(0x18)), a(0x18)));
        assertEquals(a(0x10), s.addressForLine(1));
        assertEquals(a(0x20), s.addressForLine(2));
        assertNull(s.addressForLine(7));
    }

    @Test
    public void addressesForLineSortedDistinct() {
        DecompilationSnapshot s = snap("a\nb",
            line(1, List.of(a(0x20), a(0x10), a(0x20)), null),
            line(2, List.of(), a(0x30)));
        assertEquals(List.of(a(0x10), a(0x20)), s.addressesForLine(1));
        assertEquals(List.of(a(0x30)), s.addressesForLine(2));
        assertTrue(s.addressesForLine(9).isEmpty());
    }

    @Test
    public void linesForAddressesListsEachLineOnce() {
        DecompilationSnapshot s = snap("a\nb\nc",
            line(1, List.of(a(0x10), a(0x11)), a(0x10)),
            line(2, List.of(a(0x20)), a(0x20)),
            line(3, List.of(), a(0x30)));
        assertEquals(List.of(1, 2), s.linesForAddresses(List.of(a(0x11), a(0x10), a(0x20))));
        // closest address alone does not count
        assertTrue(s.linesForAddresses(List.of(a(0x30))).isEmpty());
        assertTrue(s.linesForAddresses(List.of()).isEmpty());
    }

    @Test
    public void contextClampsAtFunctionStartAndEnd() {
        DecompilationSnapshot s = snap("l1\nl2\nl3\nl4\nl5");
        assertEquals("l1\nl2\nl3", s.context(1, 2));
        assertEquals("l3\nl4\nl5", s.context(5, 2));
        assertEquals("l3", s.context(3, 0));
        assertEquals("l1\nl2\nl3\nl4\nl5", s.context(3, 10));
    }

    @Test
    public void contextNullOnlyForInvalidArguments() {
        DecompilationSnapshot s = snap("l1\nl2\nl3");
        assertNull(s.context(0, 1));
        assertNull(s.context(-3, 1));
        assertNull(s.context(2, -1));
    }

    @Test
    public void contextEmptyStringWhenWindowIsPastTheEnd() {
        DecompilationSnapshot s = snap("l1\nl2\nl3");
        assertEquals("", s.context(10, 1));
        assertEquals("l3", s.context(4, 1));
    }

    @Test
    public void listsAreUnmodifiable() {
        List<Address> tokens = new java.util.ArrayList<>(List.of(a(0x10)));
        List<Line> input = new java.util.ArrayList<>(List.of(line(1, tokens, a(0x10))));
        DecompilationSnapshot s = new DecompilationSnapshot("a", "sig", input);
        tokens.add(a(0x20));
        input.clear();
        assertEquals(1, s.lines().size());
        assertEquals(List.of(a(0x10)), s.lines().get(0).tokenAddresses());
        assertThrows(UnsupportedOperationException.class, () -> s.lines().add(line(2, List.of(), null)));
        assertThrows(UnsupportedOperationException.class, () -> s.lines().get(0).tokenAddresses().add(a(1)));
        assertThrows(UnsupportedOperationException.class, () -> s.addressesForLine(1).add(a(1)));
    }

    @Test
    public void sizeInCharsCountsCodeAndAddresses() {
        DecompilationSnapshot s = snap("abcd", line(1, List.of(a(1), a(2)), a(1)));
        // two token addresses plus the closest address are stored
        assertEquals(4 + 32 * 3, s.sizeInChars());
    }
}
