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
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Test class for AddressUtil utility methods.
 */
public class AddressUtilTest {

    @Mock private Program program;
    @Mock private AddressFactory addressFactory;
    @Mock private AddressSpace addressSpace;
    @Mock private Address address;
    @Mock private SymbolTable symbolTable;
    @Mock private Symbol symbol;
    @Mock private FunctionManager functionManager;
    @Mock private Function function;
    @Mock private Listing listing;
    @Mock private Data data;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        when(program.getAddressFactory()).thenReturn(addressFactory);
        when(addressFactory.getDefaultAddressSpace()).thenReturn(addressSpace);
    }

    /**
     * Test formatAddress with valid address
     */
    @Test
    public void testFormatAddress_ValidAddress() {
        when(address.toString()).thenReturn("00401000");
        
        String result = AddressUtil.formatAddress(address);
        
        assertEquals("0x00401000", result);
    }

    /**
     * Test formatAddress with null address
     */
    @Test
    public void testFormatAddress_NullAddress() {
        String result = AddressUtil.formatAddress(null);
        
        assertNull(result);
    }

    /**
     * Test parseAddress with hex string with 0x prefix
     */
    @Test
    public void testParseAddress_WithHexPrefix() {
        String addressString = "0x00401000";
        when(addressSpace.getAddress(0x00401000L)).thenReturn(address);
        
        Address result = AddressUtil.parseAddress(program, addressString);
        
        assertEquals(address, result);
    }

    /**
     * Test parseAddress with hex string without 0x prefix
     */
    @Test
    public void testParseAddress_WithoutHexPrefix() {
        String addressString = "00401000";
        when(addressSpace.getAddress(0x00401000L)).thenReturn(address);
        
        Address result = AddressUtil.parseAddress(program, addressString);
        
        assertEquals(address, result);
    }

    /**
     * Test parseAddress with uppercase hex
     */
    @Test
    public void testParseAddress_UppercaseHex() {
        String addressString = "0xDEADBEEF";
        when(addressSpace.getAddress(0xDEADBEEFL)).thenReturn(address);
        
        Address result = AddressUtil.parseAddress(program, addressString);
        
        assertEquals(address, result);
    }

    /**
     * Test parseAddress with null input
     */
    @Test
    public void testParseAddress_NullInput() {
        Address result = AddressUtil.parseAddress(program, null);
        
        assertNull(result);
    }

    /**
     * Test parseAddress with empty string
     */
    @Test
    public void testParseAddress_EmptyString() {
        Address result = AddressUtil.parseAddress(program, "");
        
        assertNull(result);
    }

    /**
     * Test parseAddress with whitespace
     */
    @Test
    public void testParseAddress_Whitespace() {
        Address result = AddressUtil.parseAddress(program, "   ");
        
        assertNull(result);
    }

    /**
     * Test parseAddress with invalid hex string
     */
    @Test
    public void testParseAddress_InvalidHex() {
        String addressString = "0xGHIJKL";
        
        Address result = AddressUtil.parseAddress(program, addressString);
        
        assertNull(result);
    }

    /**
     * Test isValidAddress with valid address
     */
    @Test
    public void testIsValidAddress_ValidAddress() {
        String addressString = "0x00401000";
        when(addressSpace.getAddress(0x00401000L)).thenReturn(address);
        
        boolean result = AddressUtil.isValidAddress(program, addressString);
        
        assertTrue(result);
    }

    /**
     * Test isValidAddress with invalid address
     */
    @Test
    public void testIsValidAddress_InvalidAddress() {
        String addressString = "invalid";
        
        boolean result = AddressUtil.isValidAddress(program, addressString);
        
        assertFalse(result);
    }

    /**
     * Test resolveAddressOrSymbol with symbol name
     */
    @Test
    public void testResolveAddressOrSymbol_Symbol() {
        String symbolName = "main";
        List<Symbol> symbols = new ArrayList<>();
        symbols.add(symbol);
        
        when(program.getSymbolTable()).thenReturn(symbolTable);
        when(symbolTable.getLabelOrFunctionSymbols(symbolName, null)).thenReturn(symbols);
        when(symbol.getAddress()).thenReturn(address);
        
        Address result = AddressUtil.resolveAddressOrSymbol(program, symbolName);
        
        assertEquals(address, result);
    }

    /**
     * Test resolveAddressOrSymbol with address string
     */
    @Test
    public void testResolveAddressOrSymbol_Address() {
        String addressString = "0x00401000";
        List<Symbol> symbols = new ArrayList<>(); // Empty list
        
        when(program.getSymbolTable()).thenReturn(symbolTable);
        when(symbolTable.getLabelOrFunctionSymbols(addressString, null)).thenReturn(symbols);
        when(addressSpace.getAddress(0x00401000L)).thenReturn(address);
        
        Address result = AddressUtil.resolveAddressOrSymbol(program, addressString);
        
        assertEquals(address, result);
    }

    /**
     * Test resolveAddressOrSymbol with null input
     */
    @Test
    public void testResolveAddressOrSymbol_NullInput() {
        Address result = AddressUtil.resolveAddressOrSymbol(program, null);
        
        assertNull(result);
    }

    /**
     * Test resolveAddressOrSymbol with empty string
     */
    @Test
    public void testResolveAddressOrSymbol_EmptyString() {
        Address result = AddressUtil.resolveAddressOrSymbol(program, "");
        
        assertNull(result);
    }

    /**
     * Test resolveAddressOrSymbol with neither symbol nor valid address
     */
    @Test
    public void testResolveAddressOrSymbol_InvalidInput() {
        String input = "invalid";
        List<Symbol> symbols = new ArrayList<>(); // Empty list
        
        when(program.getSymbolTable()).thenReturn(symbolTable);
        when(symbolTable.getLabelOrFunctionSymbols(input, null)).thenReturn(symbols);
        // parseAddress will return null for invalid input
        
        Address result = AddressUtil.resolveAddressOrSymbol(program, input);
        
        assertNull(result);
    }

    /**
     * Test getContainingFunction with address inside function
     */
    @Test
    public void testGetContainingFunction_InsideFunction() {
        when(program.getFunctionManager()).thenReturn(functionManager);
        when(functionManager.getFunctionContaining(address)).thenReturn(function);
        
        Function result = AddressUtil.getContainingFunction(program, address);
        
        assertEquals(function, result);
    }

    /**
     * Test getContainingFunction with address outside any function
     */
    @Test
    public void testGetContainingFunction_OutsideFunction() {
        when(program.getFunctionManager()).thenReturn(functionManager);
        when(functionManager.getFunctionContaining(address)).thenReturn(null);
        
        Function result = AddressUtil.getContainingFunction(program, address);
        
        assertNull(result);
    }

    /**
     * Test getContainingFunction with null program
     */
    @Test
    public void testGetContainingFunction_NullProgram() {
        Function result = AddressUtil.getContainingFunction(null, address);
        
        assertNull(result);
    }

    /**
     * Test getContainingFunction with null address
     */
    @Test
    public void testGetContainingFunction_NullAddress() {
        Function result = AddressUtil.getContainingFunction(program, null);
        
        assertNull(result);
    }

    /**
     * Test getContainingData with data at exact address
     */
    @Test
    public void testGetContainingData_ExactAddress() {
        when(program.getListing()).thenReturn(listing);
        when(listing.getDataAt(address)).thenReturn(data);
        
        Data result = AddressUtil.getContainingData(program, address);
        
        assertEquals(data, result);
    }

    /**
     * Test getContainingData with address inside data structure
     */
    @Test
    public void testGetContainingData_InsideDataStructure() {
        when(program.getListing()).thenReturn(listing);
        when(listing.getDataAt(address)).thenReturn(null);
        when(listing.getDataContaining(address)).thenReturn(data);
        
        Data result = AddressUtil.getContainingData(program, address);
        
        assertEquals(data, result);
    }

    /**
     * Test getContainingData with no data at address
     */
    @Test
    public void testGetContainingData_NoData() {
        when(program.getListing()).thenReturn(listing);
        when(listing.getDataAt(address)).thenReturn(null);
        when(listing.getDataContaining(address)).thenReturn(null);
        
        Data result = AddressUtil.getContainingData(program, address);
        
        assertNull(result);
    }

    /**
     * Test getContainingData with null program
     */
    @Test
    public void testGetContainingData_NullProgram() {
        Data result = AddressUtil.getContainingData(null, address);
        
        assertNull(result);
    }

    /**
     * Test getContainingData with null address
     */
    @Test
    public void testGetContainingData_NullAddress() {
        Data result = AddressUtil.getContainingData(program, null);
        
        assertNull(result);
    }

    /**
     * Test parseAddress with very large hex number
     */
    @Test
    public void testParseAddress_VeryLargeHex() {
        String addressString = "0xFFFFFFFFFFFFFFFF";
        when(addressSpace.getAddress(0xFFFFFFFFFFFFFFFFL)).thenReturn(address);
        
        Address result = AddressUtil.parseAddress(program, addressString);
        
        assertEquals(address, result);
    }

    /**
     * Test parseAddress with leading/trailing spaces
     */
    @Test
    public void testParseAddress_WithSpaces() {
        String addressString = "  0x00401000  ";
        when(addressSpace.getAddress(0x00401000L)).thenReturn(address);
        
        Address result = AddressUtil.parseAddress(program, addressString);
        
        assertEquals(address, result);
    }

    /**
     * Test resolveAddressOrSymbol with case-sensitive symbol
     */
    @Test
    public void testResolveAddressOrSymbol_CaseSensitiveSymbol() {
        String symbolName = "Main"; // Different case than "main"
        List<Symbol> symbols = new ArrayList<>();
        symbols.add(symbol);
        
        when(program.getSymbolTable()).thenReturn(symbolTable);
        when(symbolTable.getLabelOrFunctionSymbols(symbolName, null)).thenReturn(symbols);
        when(symbol.getAddress()).thenReturn(address);
        
        Address result = AddressUtil.resolveAddressOrSymbol(program, symbolName);
        
        assertEquals(address, result);
    }

    /**
     * Test resolveAddressOrSymbol with multiple symbols (returns first)
     */
    @Test
    public void testResolveAddressOrSymbol_MultipleSymbols() {
        String symbolName = "duplicate";
        List<Symbol> symbols = new ArrayList<>();
        Symbol symbol2 = mock(Symbol.class);
        Address address2 = mock(Address.class);
        
        symbols.add(symbol);
        symbols.add(symbol2);
        
        when(program.getSymbolTable()).thenReturn(symbolTable);
        when(symbolTable.getLabelOrFunctionSymbols(symbolName, null)).thenReturn(symbols);
        when(symbol.getAddress()).thenReturn(address);
        when(symbol2.getAddress()).thenReturn(address2);
        
        Address result = AddressUtil.resolveAddressOrSymbol(program, symbolName);
        
        assertEquals(address, result); // Should return first symbol's address
    }
}