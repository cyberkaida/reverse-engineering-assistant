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
import ghidra.program.model.listing.Program;

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
        return "0x" + address.toString();
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
}