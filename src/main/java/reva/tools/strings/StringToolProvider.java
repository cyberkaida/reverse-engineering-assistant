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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Collections;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SimilarityComparator;



/**
 * Tool provider for string-related operations.
 */
public class StringToolProvider extends AbstractToolProvider {
    /**
     * Maximum number of referencing functions to return per string.
     * Prevents unbounded iteration for frequently referenced strings.
     */
    private static final int MAX_REFERENCING_FUNCTIONS = 100;

    /**
     * Temporary key for storing Address objects during similarity search processing.
     * Used to avoid string parsing round-trip; removed before JSON serialization.
     */
    private static final String TEMP_ADDRESS_KEY = "_addressObj";

    /**
     * Constructor
     * @param server The MCP server
     */
    public StringToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerStringsCountTool();
        registerStringsTool();
        registerStringsBySimilarityTool();
        registerStringsRegexSearchTool();
    }

    /**
     * Register a tool to get the count of strings in a program
     */
    private void registerStringsCountTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to get string count from"
        ));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-strings-count")
            .title("Get Strings Count")
            .description("Get the total count of strings in the program (use this before calling get-strings to plan pagination)")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program using helper method
            Program program = getProgramFromArgs(request);

            // Count the strings
            int count = 0;
            DataIterator dataIterator = program.getListing().getDefinedData(true);
            for (Data data : dataIterator) {
                if (data.getValue() instanceof String) {
                    count++;
                }
            }

            // Create result data
            Map<String, Object> countData = new HashMap<>();
            countData.put("count", count);

            return createJsonResult(countData);
        });
    }

    /**
     * Register a tool to get strings from a program with pagination
     */
    private void registerStringsTool() {
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
        properties.put("includeReferencingFunctions", Map.of(
            "type", "boolean",
            "description", "Include list of functions that reference each string (max 100 per string).",
            "default", false
        ));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-strings")
            .title("Get Strings")
            .description("Get strings from the selected program with pagination (use get-strings-count first to determine total count)")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and pagination parameters using helper methods
            Program program = getProgramFromArgs(request);
            PaginationParams pagination = getPaginationParams(request);
            boolean includeReferencingFunctions = getOptionalBoolean(request, "includeReferencingFunctions", false);

            // Get strings with pagination
            List<Map<String, Object>> stringData = new ArrayList<>();
            DataIterator dataIterator = program.getListing().getDefinedData(true);
            int currentIndex = 0;

            for (Data data : dataIterator) {
                if (!(data.getValue() instanceof String)) {
                    continue;
                }

                // Skip strings before the start index
                if (currentIndex++ < pagination.startIndex()) {
                    continue;
                }

                // Stop after we've collected maxCount strings
                if (stringData.size() >= pagination.maxCount()) {
                    break;
                }

                // Collect string data
                Map<String, Object> stringInfo = getStringInfo(data, program, includeReferencingFunctions);
                if (stringInfo != null) {
                    stringData.add(stringInfo);
                }
            }

            // Create pagination metadata
            Map<String, Object> paginationInfo = new HashMap<>();
            paginationInfo.put("startIndex", pagination.startIndex());
            paginationInfo.put("requestedCount", pagination.maxCount());
            paginationInfo.put("actualCount", stringData.size());
            paginationInfo.put("nextStartIndex", pagination.startIndex() + stringData.size());

            // Return as a single JSON array with pagination info first, then string data
            List<Object> resultData = new ArrayList<>();
            resultData.add(paginationInfo);
            resultData.addAll(stringData);
            return createJsonResult(resultData);
        });
    }

    /**
     * Register a tool to get strings from a program with pagination, sorted by similarity.
     */
    private void registerStringsBySimilarityTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to get strings from"
        ));

        properties.put("searchString", Map.of(
            "type", "string",
            "description", "String to compare against for similarity (scored by longest common substring length between the search string and each string in the program)"
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
        properties.put("includeReferencingFunctions", Map.of(
            "type", "boolean",
            "description", "Include list of functions that reference each string (max 100 per string).",
            "default", false
        ));

        List<String> required = List.of("programPath","searchString");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-strings-by-similarity")
            .title("Get Strings by Similarity")
            .description("Get strings from the selected program with pagination, sorted by similarity to a given string (use get-strings-count first to determine total count)")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            String searchString = getString(request, "searchString");
            PaginationParams pagination = getPaginationParams(request);
            boolean includeReferencingFunctions = getOptionalBoolean(request, "includeReferencingFunctions", false);

            if (searchString.trim().isEmpty()) {
                return createErrorResult("Search string cannot be empty");
            }

            // Phase 1: Collect all strings WITHOUT referencing functions (for performance)
            // Store Address objects temporarily for Phase 4 to avoid string parsing round-trip
            DataIterator dataIterator = program.getListing().getDefinedData(true);
            List<Map<String, Object>> allStringData = new ArrayList<>();

            for (Data data : dataIterator) {
                if (data.getValue() instanceof String) {
                    // Collect basic string data without references
                    Map<String, Object> stringInfo = getStringInfo(data);
                    if (stringInfo != null) {
                        // Store Address object temporarily for Phase 4
                        stringInfo.put(TEMP_ADDRESS_KEY, data.getAddress());
                        allStringData.add(stringInfo);
                    }
                }
            }

            // Phase 2: Sort by similarity (SimilarityComparator handles null values internally)
            Collections.sort(allStringData, new SimilarityComparator<Map<String, Object>>(searchString, new SimilarityComparator.StringExtractor<Map<String, Object>>() {
                @Override
                public String extract(Map<String, Object> item) {
                    return (String) item.get("content");
                }
            }));

            // Phase 3: Paginate
            int startIdx = Math.min(pagination.startIndex(), allStringData.size());
            int endIdx = Math.min(pagination.startIndex() + pagination.maxCount(), allStringData.size());
            List<Map<String, Object>> paginatedStringData = new ArrayList<>(allStringData.subList(startIdx, endIdx));
            boolean searchComplete = endIdx >= allStringData.size();

            // Phase 4: Add referencing functions ONLY for paginated results (performance optimization)
            for (Map<String, Object> stringInfo : paginatedStringData) {
                // Remove temporary Address object (not JSON-serializable)
                Address address = (Address) stringInfo.remove(TEMP_ADDRESS_KEY);

                if (includeReferencingFunctions && address != null) {
                    List<Map<String, String>> referencingFunctions = getReferencingFunctions(program, address);
                    stringInfo.put("referencingFunctions", referencingFunctions);
                    stringInfo.put("referenceCount", referencingFunctions.size());
                }
            }

            // Create pagination metadata
            Map<String, Object> paginationInfo = new HashMap<>();
            paginationInfo.put("searchComplete", searchComplete);
            paginationInfo.put("startIndex", pagination.startIndex());
            paginationInfo.put("requestedCount", pagination.maxCount());
            paginationInfo.put("actualCount", paginatedStringData.size());
            paginationInfo.put("nextStartIndex", pagination.startIndex() + paginatedStringData.size());

            List<Object> resultData = new ArrayList<>();
            resultData.add(paginationInfo);
            resultData.addAll(paginatedStringData);
            return createJsonResult(resultData);
        });
    }

    /**
     * Register a tool to search strings using regex pattern
     */
    private void registerStringsRegexSearchTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to search strings in"
        ));
        properties.put("regexPattern", Map.of(
            "type", "string",
            "description", "Regular expression pattern to search for in strings"
        ));
        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (0-based)",
            "default", 0
        ));
        properties.put("maxCount", Map.of(
            "type", "integer",
            "description", "Maximum number of matching strings to return",
            "default", 100
        ));
        properties.put("includeReferencingFunctions", Map.of(
            "type", "boolean",
            "description", "Include list of functions that reference each string (max 100 per string).",
            "default", false
        ));

        List<String> required = List.of("programPath", "regexPattern");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("search-strings-regex")
            .title("Search Strings by Regex")
            .description("Search for strings matching a regex pattern in the program (use this only if you know the string is contained in the program, otherwise use get-strings-by-similarity)")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            String regexPattern = getString(request, "regexPattern");
            PaginationParams pagination = getPaginationParams(request);
            boolean includeReferencingFunctions = getOptionalBoolean(request, "includeReferencingFunctions", false);

            if (regexPattern.trim().isEmpty()) {
                return createErrorResult("Regex pattern cannot be empty");
            }

            // Compile the regex pattern
            Pattern pattern;
            try {
                pattern = Pattern.compile(regexPattern);
            } catch (PatternSyntaxException e) {
                return createErrorResult("Invalid regex pattern: " + e.getMessage());
            }

            // Search strings matching the regex pattern
            List<Map<String, Object>> matchingStrings = new ArrayList<>();
            DataIterator dataIterator = program.getListing().getDefinedData(true);
            int matchesFound = 0;
            boolean searchComplete = true;

            for (Data data : dataIterator) {
                if (!(data.getValue() instanceof String)) {
                    continue;
                }

                String stringValue = (String) data.getValue();

                // Check if string matches the regex pattern
                if (pattern.matcher(stringValue).find()) {
                    // Skip matches before the start index
                    if (matchesFound++ < pagination.startIndex()) {
                        continue;
                    }

                    // Stop after we've collected maxCount matches
                    if (matchingStrings.size() >= pagination.maxCount()) {
                        searchComplete = false;
                        break;
                    }

                    // Collect matching string data
                    Map<String, Object> stringInfo = getStringInfo(data, program, includeReferencingFunctions);
                    if (stringInfo != null) {
                        matchingStrings.add(stringInfo);
                    }
                }
            }

            // Create result metadata
            Map<String, Object> searchMetadata = new HashMap<>();
            searchMetadata.put("regexPattern", regexPattern);
            searchMetadata.put("searchComplete", searchComplete);
            searchMetadata.put("startIndex", pagination.startIndex());
            searchMetadata.put("requestedCount", pagination.maxCount());
            searchMetadata.put("actualCount", matchingStrings.size());
            searchMetadata.put("nextStartIndex", pagination.startIndex() + matchingStrings.size());

            // Return as a single JSON array with metadata first, then matching strings
            List<Object> resultData = new ArrayList<>();
            resultData.add(searchMetadata);
            resultData.addAll(matchingStrings);
            return createJsonResult(resultData);
        });
    }

    /**
     * Extract string information from a Ghidra Data object
     * @param data The data object containing a string
     * @return Map of string properties or null if not a string
     */
    private Map<String, Object> getStringInfo(Data data) {
        return getStringInfo(data, null, false);
    }

    /**
     * Extract string information from a Ghidra Data object with optional referencing functions
     * @param data The data object containing a string
     * @param program The program (required if includeReferencingFunctions is true)
     * @param includeReferencingFunctions Whether to include list of functions that reference this string
     * @return Map of string properties or null if not a string
     */
    private Map<String, Object> getStringInfo(Data data, Program program, boolean includeReferencingFunctions) {
        if (!(data.getValue() instanceof String)) {
            return null;
        }

        String stringValue = (String) data.getValue();

        Map<String, Object> stringInfo = new HashMap<>();
        stringInfo.put("address", AddressUtil.formatAddress(data.getAddress()));
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

        // Add referencing functions if requested
        if (includeReferencingFunctions && program != null) {
            List<Map<String, String>> referencingFunctions = getReferencingFunctions(program, data.getAddress());
            stringInfo.put("referencingFunctions", referencingFunctions);
            stringInfo.put("referenceCount", referencingFunctions.size());
        }

        return stringInfo;
    }

    /**
     * Get list of functions that reference a given address
     * @param program The program
     * @param address The address to find references to
     * @return List of function info maps (name, address), limited to MAX_REFERENCING_FUNCTIONS
     */
    private List<Map<String, String>> getReferencingFunctions(Program program, Address address) {
        List<Map<String, String>> functions = new ArrayList<>();
        Set<String> seenFunctions = new HashSet<>();

        ReferenceManager refManager = program.getReferenceManager();
        FunctionManager funcManager = program.getFunctionManager();
        ReferenceIterator refIter = refManager.getReferencesTo(address);

        while (refIter.hasNext() && functions.size() < MAX_REFERENCING_FUNCTIONS) {
            Reference ref = refIter.next();
            Function func = funcManager.getFunctionContaining(ref.getFromAddress());

            if (func != null) {
                String funcKey = func.getEntryPoint().toString();
                if (!seenFunctions.contains(funcKey)) {
                    seenFunctions.add(funcKey);
                    Map<String, String> funcInfo = new HashMap<>();
                    funcInfo.put("name", func.getName());
                    funcInfo.put("address", AddressUtil.formatAddress(func.getEntryPoint()));
                    functions.add(funcInfo);
                }
            }
        }

        return functions;
    }
}
