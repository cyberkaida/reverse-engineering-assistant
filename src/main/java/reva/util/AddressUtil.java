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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.util.List;

/**
 * Utility functions for working with Ghidra addresses.
 * Provides consistent address formatting across all ReVa tools.
 */
public class AddressUtil {

    /**
     * Format an address for JSON output with consistent "0x" prefix.
     * This is the standard format used across all ReVa tool providers.
     *
     * @param address The Ghidra address to format
     * @return A hex string representation with "0x" prefix
     */
    public static String formatAddress(Address address) {
        if (address == null) {
            return null;
        }
        // Ensure we have an actual Address object and format it properly
        if (!(address instanceof Address)) {
            throw new IllegalArgumentException("Expected Address object, got: " + address.getClass().getName());
        }

        // address with a 0x prefix.
        return address.toString("0x");
    }

    /**
     * Parse an address string that may or may not have a "0x" prefix.
     * This handles user input that might come in either format.
     *
     * @param program The Ghidra program to get the address space from
     * @param addressString The address string to parse (with or without "0x")
     * @return The parsed Address object, or null if parsing fails
     */
    public static Address parseAddress(Program program, String addressString) {
        if (addressString == null || addressString.trim().isEmpty()) {
            return null;
        }

        // Remove "0x" prefix if present
        String cleanAddress = addressString.trim();
        if (cleanAddress.toLowerCase().startsWith("0x")) {
            cleanAddress = cleanAddress.substring(2);
        }

        try {
            AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
            return defaultSpace.getAddress(Long.parseUnsignedLong(cleanAddress, 16));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Check if an address string is valid (parseable).
     *
     * @param program The Ghidra program to get the address space from
     * @param addressString The address string to validate
     * @return true if the address string can be parsed, false otherwise
     */
    public static boolean isValidAddress(Program program, String addressString) {
        return parseAddress(program, addressString) != null;
    }

    /**
     * Resolve an address or symbol string to an Address object.
     * This method first attempts to find a symbol with the given name,
     * and if not found, falls back to parsing it as an address.
     *
     * @param program The Ghidra program to search in
     * @param addressOrSymbol The address string (with or without "0x") or symbol name
     * @return The resolved Address object, or null if neither symbol nor address is valid
     */
    public static Address resolveAddressOrSymbol(Program program, String addressOrSymbol) {
        if (addressOrSymbol == null || addressOrSymbol.trim().isEmpty()) {
            return null;
        }

        String input = addressOrSymbol.trim();

        // First, try to find it as a symbol
        SymbolTable symbolTable = program.getSymbolTable();
        List<Symbol> symbols = symbolTable.getLabelOrFunctionSymbols(input, null);

        if (!symbols.isEmpty()) {
            // Return the address of the first matching symbol
            return symbols.get(0).getAddress();
        }

        // If not found as a symbol, try to parse as an address
        return parseAddress(program, input);
    }

    /**
     * Get the function containing the given address.
     *
     * @param program The Ghidra program
     * @param address The address to check
     * @return The containing function, or null if the address is not within a function
     */
    public static Function getContainingFunction(Program program, Address address) {
        if (program == null || address == null) {
            return null;
        }

        return program.getFunctionManager().getFunctionContaining(address);
    }

    /**
     * Get the data item containing or starting at the given address.
     *
     * @param program The Ghidra program
     * @param address The address to check
     * @return The data at or containing the address, or null if no data exists there
     */
    public static Data getContainingData(Program program, Address address) {
        if (program == null || address == null) {
            return null;
        }

        Listing listing = program.getListing();

        // First check if there's data exactly at this address
        Data data = listing.getDataAt(address);
        if (data != null) {
            return data;
        }

        // If not, check if this address is within a larger data structure
        return listing.getDataContaining(address);
    }
}