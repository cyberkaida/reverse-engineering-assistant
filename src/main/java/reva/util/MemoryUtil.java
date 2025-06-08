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

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Utility functions for working with Ghidra memory.
 */
public class MemoryUtil {

    /**
     * Format a byte array as a hex string
     * @param bytes The byte array
     * @return A hex string representation
     */
    public static String formatHexString(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }

        StringBuilder hexBuilder = new StringBuilder();
        for (byte b : bytes) {
            hexBuilder.append(String.format("%02X ", b & 0xFF));
        }
        return hexBuilder.toString().trim();
    }

    /**
     * Convert a byte array to a list of integer values (0-255)
     * @param bytes The byte array
     * @return List of integer values
     */
    public static List<Integer> byteArrayToIntList(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return List.of();
        }

        List<Integer> result = new ArrayList<>(bytes.length);
        for (byte b : bytes) {
            result.add(b & 0xFF);
        }
        return result;
    }

    /**
     * Read memory bytes safely
     * @param program The Ghidra program
     * @param address Starting address
     * @param length Number of bytes to read
     * @return Byte array or null if an error occurred
     */
    public static byte[] readMemoryBytes(Program program, Address address, int length) {
        Memory memory = program.getMemory();
        byte[] bytes = new byte[length];

        try {
            int read = memory.getBytes(address, bytes);
            if (read != length) {
                byte[] actualBytes = new byte[read];
                System.arraycopy(bytes, 0, actualBytes, 0, read);
                return actualBytes;
            }
            return bytes;
        } catch (MemoryAccessException e) {
            return null;
        }
    }

    /**
     * Find a memory block by name
     * @param program The Ghidra program
     * @param blockName Name of the block to find
     * @return The memory block or null if not found
     */
    public static MemoryBlock findBlockByName(Program program, String blockName) {
        Memory memory = program.getMemory();
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.getName().equals(blockName)) {
                return block;
            }
        }
        return null;
    }

    /**
     * Find the memory block containing the given address
     * @param program The Ghidra program
     * @param address The address to look up
     * @return The memory block or null if not found
     */
    public static MemoryBlock getBlockContaining(Program program, Address address) {
        Memory memory = program.getMemory();
        return memory.getBlock(address);
    }

    /**
     * Process memory bytes in chunks to avoid large memory allocations
     * @param program The Ghidra program
     * @param startAddress Starting address
     * @param length Total number of bytes to process
     * @param chunkSize Maximum chunk size
     * @param processor Consumer function that processes each chunk
     */
    public static void processMemoryInChunks(
            Program program,
            Address startAddress,
            long length,
            int chunkSize,
            Consumer<byte[]> processor) {

        Memory memory = program.getMemory();
        Address currentAddress = startAddress;
        long remaining = length;

        while (remaining > 0) {
            int currentChunkSize = (int) Math.min(remaining, chunkSize);
            byte[] buffer = new byte[currentChunkSize];

            try {
                int read = memory.getBytes(currentAddress, buffer);
                if (read > 0) {
                    processor.accept(buffer);
                    currentAddress = currentAddress.add(read);
                    remaining -= read;
                } else {
                    break; // Could not read any bytes
                }
            } catch (MemoryAccessException e) {
                break; // Memory access error
            }
        }
    }
}
