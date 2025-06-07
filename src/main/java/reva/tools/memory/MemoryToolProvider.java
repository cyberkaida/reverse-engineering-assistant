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
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.RevaProgramManager;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
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
    public void registerTools() throws McpError {
        registerMemoryBlocksTool();
        registerReadMemoryTool();
    }

    /**
     * Register a tool to list memory blocks from a program
     * @throws McpError if there's an error registering the tool
     */
    private void registerMemoryBlocksTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-memory-blocks",
            "Get memory blocks from the selected program",
            createSchema(properties, required)
        );

        // Add the tool using the parent's method
        super.registerTool(tool, (exchange, args) -> {
            // Get the program path from the request
            String programPath = (String) args.get("programPath");
            if (programPath == null) {
                return createErrorResult("No program path provided");
            }

            // Get the program from the path
            Program program = RevaProgramManager.getProgramByPath(programPath);
            if (program == null) {
                return createErrorResult("Failed to find Program: " + programPath);
            }

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

            return createSuccessResult(blockData);
        });
    }

    /**
     * Register a tool to read memory content from a program
     * @throws McpError if there's an error registering the tool
     */
    private void registerReadMemoryTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("address", SchemaUtil.stringProperty("Address or symbol name to read from (e.g. '00400000' or 'main')"));
        properties.put("length", SchemaUtil.integerPropertyWithDefault("Number of bytes to read", 16));
        properties.put("format", SchemaUtil.stringPropertyWithDefault("Output format: 'hex', 'bytes', or 'both'", "hex"));

        List<String> required = List.of("programPath", "address");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "read-memory",
            "Read memory at a specific address",
            createSchema(properties, required)
        );

        // Add the tool using the parent's method
        super.registerTool(tool, (exchange, args) -> {
            // Get the program path from the request
            String programPath = (String) args.get("programPath");
            if (programPath == null) {
                return createErrorResult("No program path provided");
            }

            // Get the program from the path
            Program program = RevaProgramManager.getProgramByPath(programPath);
            if (program == null) {
                return createErrorResult("Failed to find Program: " + programPath);
            }

            // Get the address from the request
            String addressStr = (String) args.get("address");
            if (addressStr == null) {
                return createErrorResult("No address provided");
            }

            // Parse the address or symbol
            Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
            if (address == null) {
                return createErrorResult("Invalid address or symbol: " + addressStr);
            }

            // Get the length from the request
            int length = (Integer) args.getOrDefault("length", 16);
            if (length <= 0) {
                return createErrorResult("Invalid length: " + length);
            }

            // Get the format from the request
            String format = (String) args.getOrDefault("format", "hex");

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

            return createSuccessResult(result);
        });
    }

    /**
     * Helper method to create a success result with JSON content
     * @param data The data to serialize as JSON
     * @return CallToolResult with success flag set
     */
    protected McpSchema.CallToolResult createSuccessResult(Object data) {
        try {
            String jsonString = JSON.writeValueAsString(data);
            return new McpSchema.CallToolResult(
                List.of(new McpSchema.TextContent(jsonString)),
                false
            );
        } catch (Exception e) {
            return createErrorResult("Error serializing result to JSON: " + e.getMessage());
        }
    }
}
