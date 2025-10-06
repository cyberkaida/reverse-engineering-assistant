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
package reva.tools.memory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.MemoryUtil;
import reva.util.SchemaUtil;

/**
 * Tool provider for memory-related operations.
 * Provides tools to list memory blocks and read memory content.
 */
public class MemoryToolProvider extends AbstractToolProvider {

    /**
     * Constructor
     * @param server The MCP server
     */
    public MemoryToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerMemoryBlocksTool();
        registerReadMemoryTool();
    }

    /**
     * Register a tool to list memory blocks from a program
     */
    private void registerMemoryBlocksTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-memory-blocks")
            .title("Get Memory Blocks")
            .description("Get memory blocks from the selected program")
            .inputSchema(createSchema(properties, required))
            .build();

        // Add the tool using the parent's method
        super.registerTool(tool, (exchange, request) -> {
            // Get program using helper method
            Program program = getProgramFromArgs(request);

            // Get the memory from the program
            Memory memory = program.getMemory();
            List<Map<String, Object>> blockData = new ArrayList<>();

            // Iterate through all memory blocks
            for (MemoryBlock block : memory.getBlocks()) {
                Map<String, Object> blockInfo = new HashMap<>();
                blockInfo.put("name", block.getName());
                blockInfo.put("start", block.getStart().toString());
                blockInfo.put("end", block.getEnd().toString());
                blockInfo.put("size", block.getSize());
                blockInfo.put("readable", block.isRead());
                blockInfo.put("writable", block.isWrite());
                blockInfo.put("executable", block.isExecute());
                blockInfo.put("initialized", block.isInitialized());
                blockInfo.put("volatile", block.isVolatile());
                blockInfo.put("mapped", block.isMapped());
                blockInfo.put("overlay", block.isOverlay());

                blockData.add(blockInfo);
            }

            return createJsonResult(blockData);
        });
    }

    /**
     * Register a tool to read memory content from a program
     */
    private void registerReadMemoryTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("addressOrSymbol", SchemaUtil.stringProperty("Address or symbol name to read from (e.g. '00400000' or 'main')"));
        properties.put("length", SchemaUtil.integerPropertyWithDefault("Number of bytes to read", 16));
        properties.put("format", SchemaUtil.stringPropertyWithDefault("Output format: 'hex', 'bytes', or 'both'", "hex"));

        List<String> required = List.of("programPath", "addressOrSymbol");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("read-memory")
            .title("Read Memory")
            .description("Read memory at a specific address")
            .inputSchema(createSchema(properties, required))
            .build();

        // Add the tool using the parent's method
        super.registerTool(tool, (exchange, request) -> {
            // Get program and address using helper methods
            Program program = getProgramFromArgs(request);
            Address address = getAddressFromArgs(request, program, "addressOrSymbol");

            // Get the length from the request
            int length = getOptionalInt(request, "length", 16);
            if (length <= 0) {
                return createErrorResult("Invalid length: " + length);
            }

            // Get the format from the request
            String format = getOptionalString(request, "format", "hex");

            // Read the memory
            byte[] bytes = MemoryUtil.readMemoryBytes(program, address, length);
            if (bytes == null) {
                return createErrorResult("Memory access error at address: " + address);
            }

            // Format the result
            Map<String, Object> result = new HashMap<>();
            result.put("address", address.toString());
            result.put("length", bytes.length);

            if ("hex".equals(format) || "both".equals(format)) {
                result.put("hex", MemoryUtil.formatHexString(bytes));
            }

            if ("bytes".equals(format) || "both".equals(format)) {
                result.put("bytes", MemoryUtil.byteArrayToIntList(bytes));
            }

            return createJsonResult(result);
        });
    }

}
