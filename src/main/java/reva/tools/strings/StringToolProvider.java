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
package reva.tools.strings;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.RevaProgramManager;
import reva.tools.AbstractToolProvider;

class StringSimilarityComparator implements java.util.Comparator<Map<String, Object>> {
    private final String searchString;

    public StringSimilarityComparator(String searchString) {
        this.searchString = searchString.toLowerCase();
    }

    @Override
    public int compare(Map<String, Object> o1, Map<String, Object> o2) {
        String str1 = (String) o1.get("content");
        String str2 = (String) o2.get("content");
        return findLongestCommonSubstringLength(str2.toLowerCase(), searchString) -
               findLongestCommonSubstringLength(str1.toLowerCase(), searchString);
    }

    private int findLongestCommonSubstringLength(String str1, String str2) {
        int m = str1.length();
        int n = str2.length();
        int[][] dp = new int[m + 1][n + 1];
        int maxLength = 0;

        for (int i = 1; i <= m; i++) {
            for (int j = 1; j <= n; j++) {
                if (str1.charAt(i - 1) == str2.charAt(j - 1)) {
                    dp[i][j] = 1 + dp[i - 1][j - 1];
                    if (dp[i][j] > maxLength) {
                        maxLength = dp[i][j];
                    }
                } else {
                    dp[i][j] = 0; // Reset if characters don't match
                }
            }
        }
        return maxLength;   
    }
}

/**
 * Tool provider for string-related operations.
 */
public class StringToolProvider extends AbstractToolProvider {
    /**
     * Constructor
     * @param server The MCP server
     */
    public StringToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() throws McpError {
        registerStringsCountTool();
        registerStringsTool();
        registerStringsBySimilarityTool();
    }

    /**
     * Register a tool to get the count of strings in a program
     * @throws McpError if there's an error registering the tool
     */
    private void registerStringsCountTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to get string count from"
        ));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-strings-count",
            "Get the total count of strings in the program (use this before calling get-strings to plan pagination)",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
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

            // Count the strings
            AtomicInteger count = new AtomicInteger(0);
            DataIterator dataIterator = program.getListing().getDefinedData(true);
            dataIterator.forEach(data -> {
                if (data.getValue() instanceof String) {
                    count.incrementAndGet();
                }
            });

            // Create result data
            Map<String, Object> countData = new HashMap<>();
            countData.put("count", count.get());

            return createJsonResult(countData);
        });
    }

    /**
     * Register a tool to get strings from a program with pagination
     * @throws McpError if there's an error registering the tool
     */
    private void registerStringsTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to get strings from"
        ));
        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (0-based)",
            "default", 0
        ));
        properties.put("maxCount", Map.of(
            "type", "integer",
            "description", "Maximum number of strings to return (recommended to use get-strings-count first and request chunks of 100 at most)",
            "default", 100
        ));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-strings",
            "Get strings from the selected program with pagination (use get-strings-count first to determine total count)",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get the program path from the request
            String programPath = (String) args.get("programPath");
            if (programPath == null) {
                return createErrorResult("No program path provided");
            }

            // Get pagination parameters
            int startIndex = args.containsKey("startIndex") ?
                ((Number) args.get("startIndex")).intValue() : 0;
            int maxCount = args.containsKey("maxCount") ?
                ((Number) args.get("maxCount")).intValue() : 100;

            // Get the program from the path
            Program program = RevaProgramManager.getProgramByPath(programPath);
            if (program == null) {
                return createErrorResult("Failed to find Program: " + programPath);
            }

            // Get strings with pagination
            List<Map<String, Object>> stringData = new ArrayList<>();
            DataIterator dataIterator = program.getListing().getDefinedData(true);
            AtomicInteger currentIndex = new AtomicInteger(0);

            dataIterator.forEach(data -> {
                if (data.getValue() instanceof String) {
                    int index = currentIndex.getAndIncrement();

                    // Skip strings before the start index
                    if (index < startIndex) {
                        return;
                    }

                    // Stop after we've collected maxCount strings
                    if (stringData.size() >= maxCount) {
                        return;
                    }

                    // Collect string data
                    Map<String, Object> stringInfo = getStringInfo(data);
                    if (stringInfo != null) {
                        stringData.add(stringInfo);
                    }
                }
            });

            // Create pagination metadata
            Map<String, Object> paginationInfo = new HashMap<>();
            paginationInfo.put("startIndex", startIndex);
            paginationInfo.put("requestedCount", maxCount);
            paginationInfo.put("actualCount", stringData.size());
            paginationInfo.put("nextStartIndex", startIndex + stringData.size());
            paginationInfo.put("totalProcessed", currentIndex.get());

            // Return as a single JSON array with pagination info first, then string data
            List<Object> resultData = new ArrayList<>();
            resultData.add(paginationInfo);
            resultData.addAll(stringData);
            return createJsonResult(resultData);
        });
    }

    /**
     * Register a tool to get strings from a program with pagination, sorted by similarity.
     * @throws McpError if there's an error registering the tool
     */
    private void registerStringsBySimilarityTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to get strings from"
        ));

        properties.put("searchString", Map.of(
            "type", "string",
            "description", "String to compare against for similarity"
        ));

        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (0-based)",
            "default", 0
        ));
        properties.put("maxCount", Map.of(
            "type", "integer",
            "description", "Maximum number of strings to return (recommended to use get-strings-count first and request chunks of 100 at most)",
            "default", 100
        ));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-strings-by-similarity",
            "Get strings from the selected program with pagination, sorted by similarity to a given string (use get-strings-count first to determine total count)",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get the program path from the request
            String programPath = (String) args.get("programPath");
            if (programPath == null) {
                return createErrorResult("No program path provided");
            }

            // Get the search string from the request
            String searchString = (String) args.get("searchString");
            if (searchString == null || searchString.isEmpty()) {
                return createErrorResult("No search string provided");
            }

            // Get pagination parameters
            int startIndex = args.containsKey("startIndex") ?
                ((Number) args.get("startIndex")).intValue() : 0;
            int maxCount = args.containsKey("maxCount") ?
                ((Number) args.get("maxCount")).intValue() : 100;

            // Get the program from the path
            Program program = RevaProgramManager.getProgramByPath(programPath);
            if (program == null) {
                return createErrorResult("Failed to find Program: " + programPath);
            }

            // Get strings with pagination
            DataIterator dataIterator = program.getListing().getDefinedData(true);
            AtomicInteger currentIndex = new AtomicInteger(0);

            List<Map<String, Object>> similarStringData = new ArrayList<>();
            // Iterate through the data and collect strings
            dataIterator.forEach(data -> {
                if (data.getValue() instanceof String) {
                    int index = currentIndex.getAndIncrement();

                    // Collect string data
                    Map<String, Object> stringInfo = getStringInfo(data);
                    if (stringInfo != null) {
                        similarStringData.add(stringInfo);
                    }
                }
            });
            Collections.sort(similarStringData, new StringSimilarityComparator(searchString));
            
            List<Map<String, Object>> pagenatedStringData = similarStringData.subList(startIndex, Math.min(startIndex + maxCount, similarStringData.size()));
            // Create pagination metadata
            Map<String, Object> paginationInfo = new HashMap<>();
            paginationInfo.put("startIndex", startIndex);
            paginationInfo.put("requestedCount", maxCount);
            paginationInfo.put("actualCount", pagenatedStringData.size());
            paginationInfo.put("nextStartIndex", startIndex + pagenatedStringData.size());
            paginationInfo.put("totalProcessed", startIndex + pagenatedStringData.size());

            // Default return all strings
            List<Object> resultData = new ArrayList<>();
            resultData.add(paginationInfo);
            resultData.addAll(pagenatedStringData);
            return createMultiJsonResult(resultData);
        });
    }

    /**
     * Extract string information from a Ghidra Data object
     * @param data The data object containing a string
     * @return Map of string properties or null if not a string
     */
    private Map<String, Object> getStringInfo(Data data) {
        if (!(data.getValue() instanceof String)) {
            return null;
        }

        String stringValue = (String) data.getValue();

        Map<String, Object> stringInfo = new HashMap<>();
        stringInfo.put("address", "0x" + data.getAddress().toString());
        stringInfo.put("content", stringValue);
        stringInfo.put("length", stringValue.length());

        // Get the raw bytes
        try {
            byte[] bytes = data.getBytes();
            if (bytes != null) {
                // Convert bytes to hex string
                StringBuilder hexString = new StringBuilder();
                for (byte b : bytes) {
                    hexString.append(String.format("%02x", b & 0xff));
                }
                stringInfo.put("hexBytes", hexString.toString());
                stringInfo.put("byteLength", bytes.length);
            }
        } catch (MemoryAccessException e) {
            stringInfo.put("bytesError", "Memory access error: " + e.getMessage());
        }

        // Add the data type and representation
        stringInfo.put("dataType", data.getDataType().getName());
        stringInfo.put("representation", data.getDefaultValueRepresentation());

        return stringInfo;
    }
}
