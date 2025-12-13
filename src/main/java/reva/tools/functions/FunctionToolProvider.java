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
package reva.tools.functions;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.app.util.cparser.C.ParseException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SimilarityComparator;
import reva.util.SymbolUtil;

/**
 * Tool provider for function-related operations.
 */
public class FunctionToolProvider extends AbstractToolProvider {

    /** Maximum number of cached similarity search results */
    private static final int MAX_CACHE_ENTRIES = 50;

    /** Cache expiration time in milliseconds (10 minutes) */
    private static final long CACHE_EXPIRATION_MS = 10 * 60 * 1000;

    /** Timeout for similarity search operations in seconds */
    private static final int SIMILARITY_SEARCH_TIMEOUT_SECONDS = 120;

    /** Maximum number of results to cache per search (prevents memory bloat) */
    private static final int MAX_CACHED_RESULTS_PER_SEARCH = 2000;

    /** Log a warning if similarity search takes longer than this (milliseconds) */
    private static final long SLOW_SEARCH_THRESHOLD_MS = 5000;

    /**
     * Cache key for similarity search results.
     */
    private record SimilarityCacheKey(String programPath, String searchString, boolean filterDefaultNames) {}

    /**
     * Cached similarity search result with metadata.
     */
    private record CachedSearchResult(
        List<Map<String, Object>> sortedFunctions,
        long timestamp,
        int totalCount,
        long programModificationNumber
    ) {
        boolean isExpired() {
            return System.currentTimeMillis() - timestamp > CACHE_EXPIRATION_MS;
        }
    }

    /**
     * Thread-safe cache for similarity search results.
     * Uses ConcurrentHashMap for safe concurrent access.
     * Eviction is handled manually to respect MAX_CACHE_ENTRIES.
     */
    private final ConcurrentHashMap<SimilarityCacheKey, CachedSearchResult> similarityCache =
        new ConcurrentHashMap<>();

    /**
     * Constructor
     * @param server The MCP server
     */
    public FunctionToolProvider(McpSyncServer server) {
        super(server);
    }

    /**
     * Clear cached similarity results when a program is closed.
     */
    @Override
    public void programClosed(Program program) {
        super.programClosed(program);

        String programPath = program.getDomainFile().getPathname();
        int removedCount = 0;

        // Thread-safe removal using ConcurrentHashMap's keySet iteration
        for (SimilarityCacheKey key : similarityCache.keySet()) {
            if (key.programPath().equals(programPath)) {
                if (similarityCache.remove(key) != null) {
                    removedCount++;
                }
            }
        }

        if (removedCount > 0) {
            logInfo("FunctionToolProvider: Cleared " + removedCount +
                " cached similarity results for closed program: " + programPath);
        }
    }

    @Override
    public void registerTools() {
        registerFunctionCountTool();
        registerFunctionsTool();
        registerFunctionsBySimilarityTool();
        registerSetFunctionPrototypeTool();
    }

    /**
     * Register a tool to count the functions in a program
     */
    private void registerFunctionCountTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to get functions from"
        ));
        properties.put("filterDefaultNames", Map.of(
            "type", "boolean",
            "description", "Whether to filter out default Ghidra generated names like FUN_, DAT_, etc.",
            "default", true
        ));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-function-count")
            .title("Get Function Count")
            .description("Get the total count of functions in the program (use this before calling get-functions to plan pagination)")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            boolean filterDefaultNames = getOptionalBoolean(request, "filterDefaultNames", true);

            AtomicInteger count = new AtomicInteger(0);

            // Iterate through all functions
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            functions.forEach(function -> {
                // Skip default Ghidra function names if filtering is enabled
                if (filterDefaultNames && SymbolUtil.isDefaultSymbolName(function.getName())) {
                    return;
                }

                count.incrementAndGet();
            });

            // Create result data
            Map<String, Object> countData = new HashMap<>();
            countData.put("count", count.get());

            return createJsonResult(countData);
        });
    }

    /**
     * Register a tool to list functions from a program
     */
    private void registerFunctionsTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to get functions from"
        ));
        properties.put("filterDefaultNames", Map.of(
            "type", "boolean",
            "description", "Whether to filter out default Ghidra generated names like FUN_, DAT_, etc.",
            "default", true
        ));

        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (0-based)",
            "default", 0
        ));
        properties.put("maxCount", Map.of(
            "type", "integer",
            "description", "Maximum number of functions to return (recommended to use get-function-count first and request chunks of 100 at most)",
            "default", 100
        ));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-functions")
            .title("Get Functions")
            .description("Get functions from the selected program (use get-function-count to determine the total count)")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            PaginationParams pagination = getPaginationParams(request);
            boolean filterDefaultNames = getOptionalBoolean(request, "filterDefaultNames", true);

            // Get the functions from the program
            List<Map<String, Object>> functionData = new ArrayList<>();

            AtomicInteger currentIndex = new AtomicInteger(0);

            // Iterate through all functions
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            functions.forEach(function -> {
                // Skip default Ghidra function names if filtering is enabled
                if (filterDefaultNames && SymbolUtil.isDefaultSymbolName(function.getName())) {
                    return;
                }

                int index = currentIndex.getAndIncrement();
                // Skip functions before the start index
                if (index < pagination.startIndex()) {
                    return;
                }

                // Stop after we've collected maxCount functions
                if (functionData.size() >= pagination.maxCount()) {
                    return;
                }

                functionData.add(createFunctionInfo(function));
            });

            // Add metadata about the filtering
            Map<String, Object> metadataInfo = new HashMap<>();
            metadataInfo.put("startIndex", pagination.startIndex());
            metadataInfo.put("requestedCount", pagination.maxCount());
            metadataInfo.put("actualCount", functionData.size());
            metadataInfo.put("nextStartIndex", pagination.startIndex() + functionData.size());
            metadataInfo.put("totalProcessed", currentIndex.get());
            metadataInfo.put("filterDefaultNames", filterDefaultNames);

            // Create combined result
            List<Object> resultData = new ArrayList<>();
            resultData.add(metadataInfo);
            resultData.addAll(functionData);
            return createMultiJsonResult(resultData);
        });
    }

    /**
     * Register a tool to get functions from a program with pagination, sorted by similarity to a given function name.
     */
    private void registerFunctionsBySimilarityTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to get functions from"
        ));

        properties.put("searchString", Map.of(
            "type", "string",
            "description", "Function name to compare against for similarity (scored by longest common substring length between the search string and each function name in the program)"
        ));

        properties.put("filterDefaultNames", Map.of(
            "type", "boolean",
            "description", "Whether to filter out default Ghidra generated names like FUN_, DAT_, etc.",
            "default", true
        ));

        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (0-based)",
            "default", 0
        ));
        properties.put("maxCount", Map.of(
            "type", "integer",
            "description", "Maximum number of functions to return (recommended to use get-function-count first and request chunks of 100 at most)",
            "default", 100
        ));

        List<String> required = List.of("programPath", "searchString");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-functions-by-similarity")
            .title("Get Functions by Similarity")
            .description("Get functions from the selected program with pagination, sorted by similarity to a given function name (use get-function-count first to determine total count)")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            String searchString = getString(request, "searchString");
            PaginationParams pagination = getPaginationParams(request);
            boolean filterDefaultNames = getOptionalBoolean(request, "filterDefaultNames", true);
            String programPath = program.getDomainFile().getPathname();

            if (searchString.trim().isEmpty()) {
                return createErrorResult("Search string cannot be empty");
            }

            logInfo("get-functions-by-similarity: Searching for '" + searchString + "' in " + program.getName());

            // Check cache for existing results
            SimilarityCacheKey cacheKey = new SimilarityCacheKey(programPath, searchString, filterDefaultNames);
            long currentModNumber = program.getModificationNumber();
            CachedSearchResult cached = similarityCache.get(cacheKey);

            List<Map<String, Object>> sortedFunctions;
            boolean wasCacheHit = false;
            int originalTotalCount = 0;

            if (cached != null && !cached.isExpired() && cached.programModificationNumber() == currentModNumber) {
                // Cache hit - reuse sorted results
                wasCacheHit = true;
                sortedFunctions = cached.sortedFunctions();
                originalTotalCount = cached.totalCount();
            } else {
                // Cache miss - compute results
                long startTime = System.currentTimeMillis();

                // Create timeout monitor
                final TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(SIMILARITY_SEARCH_TIMEOUT_SECONDS, TimeUnit.SECONDS);

                // Pre-filter: collect functions that contain search string as substring first
                // This dramatically reduces the number of functions to sort with expensive LCS
                String searchLower = searchString.toLowerCase();
                List<Map<String, Object>> substringMatches = new ArrayList<>();
                List<Map<String, Object>> nonMatches = new ArrayList<>();

                // Iterate through all functions
                FunctionIterator functions = program.getFunctionManager().getFunctions(true);
                int processed = 0;

                while (functions.hasNext()) {
                    // Check for timeout/cancellation periodically
                    if (processed % 1000 == 0 && monitor.isCancelled()) {
                        return createErrorResult("Similarity search timed out after processing " +
                            processed + " functions. Try a more specific search string.");
                    }

                    Function function = functions.next();
                    processed++;

                    // Skip default Ghidra function names if filtering is enabled
                    if (filterDefaultNames && SymbolUtil.isDefaultSymbolName(function.getName())) {
                        continue;
                    }

                    // Collect function data
                    Map<String, Object> functionInfo = createFunctionInfo(function);
                    String nameLower = function.getName().toLowerCase();

                    // Pre-filter: separate substring matches from non-matches
                    if (nameLower.contains(searchLower)) {
                        substringMatches.add(functionInfo);
                    } else {
                        nonMatches.add(functionInfo);
                    }
                }

                // Create comparator for LCS-based similarity sorting
                SimilarityComparator<Map<String, Object>> comparator = new SimilarityComparator<>(searchString,
                    new SimilarityComparator.StringExtractor<Map<String, Object>>() {
                        @Override
                        public String extract(Map<String, Object> item) {
                            return (String) item.get("name");
                        }
                    });

                // Sort substring matches first (best candidates, typically small list)
                Collections.sort(substringMatches, comparator);

                // Only sort non-matches if substring matches are few (optimization)
                if (substringMatches.size() < 1000 && !nonMatches.isEmpty()) {
                    Collections.sort(nonMatches, comparator);
                }

                // Combine results: substring matches first, then non-matches
                sortedFunctions = new ArrayList<>(substringMatches.size() + nonMatches.size());
                sortedFunctions.addAll(substringMatches);
                sortedFunctions.addAll(nonMatches);
                originalTotalCount = sortedFunctions.size();

                // Limit cached results to prevent memory bloat
                List<Map<String, Object>> toCache = sortedFunctions.size() > MAX_CACHED_RESULTS_PER_SEARCH
                    ? List.copyOf(sortedFunctions.subList(0, MAX_CACHED_RESULTS_PER_SEARCH))
                    : List.copyOf(sortedFunctions);

                // Evict expired cache entries and store new results
                evictExpiredCacheEntries();
                CachedSearchResult newCached = new CachedSearchResult(toCache, System.currentTimeMillis(),
                    originalTotalCount, currentModNumber);
                similarityCache.put(cacheKey, newCached);

                // Log warning if search took a long time
                long elapsed = System.currentTimeMillis() - startTime;
                if (elapsed > SLOW_SEARCH_THRESHOLD_MS) {
                    logInfo("get-functions-by-similarity: Search for '" + searchString +
                        "' took " + (elapsed / 1000) + "s (" + originalTotalCount + " functions)");
                }
            }

            // Apply pagination to sorted results (with bounds check)
            int startIndex = pagination.startIndex();
            int totalCount = sortedFunctions.size();

            List<Map<String, Object>> paginatedFunctionData;
            if (startIndex >= totalCount) {
                paginatedFunctionData = Collections.emptyList();
            } else {
                int endIndex = Math.min(startIndex + pagination.maxCount(), totalCount);
                paginatedFunctionData = sortedFunctions.subList(startIndex, endIndex);
            }

            // Create pagination metadata
            int reportedTotal = originalTotalCount > 0 ? originalTotalCount : totalCount;
            boolean resultsTruncated = totalCount < reportedTotal;

            Map<String, Object> paginationInfo = new HashMap<>();
            paginationInfo.put("searchString", searchString);
            paginationInfo.put("startIndex", startIndex);
            paginationInfo.put("requestedCount", pagination.maxCount());
            paginationInfo.put("actualCount", paginatedFunctionData.size());
            paginationInfo.put("nextStartIndex", startIndex + paginatedFunctionData.size());
            paginationInfo.put("totalMatchingFunctions", reportedTotal);
            paginationInfo.put("filterDefaultNames", filterDefaultNames);
            paginationInfo.put("cacheHit", wasCacheHit);
            if (resultsTruncated) {
                paginationInfo.put("resultsTruncated", true);
                paginationInfo.put("maxCachedResults", MAX_CACHED_RESULTS_PER_SEARCH);
            }

            // Create combined result
            List<Object> resultData = new ArrayList<>();
            resultData.add(paginationInfo);
            resultData.addAll(paginatedFunctionData);
            return createMultiJsonResult(resultData);
        });
    }

    /**
     * Evict expired cache entries and enforce size limit.
     */
    private void evictExpiredCacheEntries() {
        long now = System.currentTimeMillis();

        // Remove expired entries
        similarityCache.entrySet().removeIf(entry ->
            now - entry.getValue().timestamp() > CACHE_EXPIRATION_MS);

        // Enforce size limit by removing oldest entries
        while (similarityCache.size() > MAX_CACHE_ENTRIES) {
            SimilarityCacheKey oldest = null;
            long oldestTime = Long.MAX_VALUE;
            for (var entry : similarityCache.entrySet()) {
                if (entry.getValue().timestamp() < oldestTime) {
                    oldestTime = entry.getValue().timestamp();
                    oldest = entry.getKey();
                }
            }
            if (oldest != null) {
                similarityCache.remove(oldest);
            } else {
                break;
            }
        }
    }

    /**
     * Create a map of function information
     * @param function The function to extract information from
     * @return Map containing function properties
     */
    private Map<String, Object> createFunctionInfo(Function function) {
        Map<String, Object> functionInfo = new HashMap<>();

        // Basic information
        functionInfo.put("name", function.getName());
        functionInfo.put("address", "0x" + function.getEntryPoint().toString());

        // Get the function's body to determine the end address and size
        AddressSetView body = function.getBody();
        if (body != null && body.getMaxAddress() != null) {
            functionInfo.put("endAddress", "0x" + body.getMaxAddress().toString());
            functionInfo.put("sizeInBytes", body.getNumAddresses());
        } else {
            functionInfo.put("sizeInBytes", 0);
        }

        // Additional function metadata
        functionInfo.put("signature", function.getSignature().toString());
        functionInfo.put("returnType", function.getReturnType().toString());
        functionInfo.put("isExternal", function.isExternal());
        functionInfo.put("isThunk", function.isThunk());
        functionInfo.put("bodySize", function.getBody().getNumAddresses());

        // Add parameters info
        List<Map<String, String>> parameters = new ArrayList<>();
        for (int i = 0; i < function.getParameterCount(); i++) {
            Map<String, String> paramInfo = new HashMap<>();
            paramInfo.put("name", function.getParameter(i).getName());
            paramInfo.put("dataType", function.getParameter(i).getDataType().toString());
            parameters.add(paramInfo);
        }
        functionInfo.put("parameters", parameters);

        return functionInfo;
    }

    /**
     * Check if applying a new signature would require custom storage to be enabled.
     * This is needed when the new signature modifies an auto-parameter's data type.
     *
     * @param function The function being updated
     * @param newSignature The parsed new function signature
     * @return true if custom storage needs to be enabled to apply this signature
     */
    private boolean needsCustomStorageForSignature(Function function, FunctionDefinitionDataType newSignature) {
        if (function == null || newSignature == null) {
            return false;
        }

        // Get existing parameters and new parameter definitions
        Parameter[] existingParams = function.getParameters();
        ParameterDefinition[] newParams = newSignature.getArguments();

        // Check each existing auto-parameter to see if its type is being changed
        for (int i = 0; i < existingParams.length; i++) {
            Parameter existingParam = existingParams[i];

            // Only care about auto-parameters with auto storage
            if (!existingParam.isAutoParameter() || !existingParam.getVariableStorage().isAutoStorage()) {
                continue;
            }

            // If the new signature has a parameter at this index, check if type is changing
            if (i < newParams.length) {
                ParameterDefinition newParam = newParams[i];

                // Compare data types - if they're different, we need custom storage
                if (!existingParam.getDataType().isEquivalent(newParam.getDataType())) {
                    logInfo("Detected auto-parameter '" + existingParam.getName() +
                            "' type change from " + existingParam.getDataType() +
                            " to " + newParam.getDataType() +
                            " - custom storage required");
                    return true;
                }
            }
            // If new signature has fewer parameters and would remove an auto-parameter,
            // we also need custom storage to handle this
            else {
                logInfo("Auto-parameter '" + existingParam.getName() +
                        "' would be removed - custom storage required");
                return true;
            }
        }

        return false;
    }

    /**
     * Normalize a function signature to handle whitespace issues that can cause parsing failures.
     *
     * Common issues:
     * - "char *funcname" fails parsing (space before * in return type)
     * - "char* funcname" works correctly
     *
     * This method normalizes whitespace to ensure consistent parsing.
     *
     * @param signature The original C-style function signature
     * @return Normalized signature with whitespace corrected
     */
    private String normalizeFunctionSignature(String signature) {
        if (signature == null || signature.isEmpty()) {
            return signature;
        }

        // Pattern: Match "type *name(" where there's a space before the pointer
        // This handles cases like "char *fgets(" which fail parsing
        // Convert to "type* name(" which parses correctly
        // Regex explanation:
        //   (\w+)      - Capture word (type name like "char", "int", etc.)
        //   \s+        - One or more spaces
        //   \*         - Literal asterisk (pointer)
        //   (\w+)      - Capture word (function name)
        //   \(         - Literal opening parenthesis
        String normalized = signature.replaceAll("(\\w+)\\s+\\*(\\w+)\\(", "$1* $2(");

        return normalized;
    }

    /**
     * Register a tool to set or update a function prototype using C-style signatures
     */
    private void registerSetFunctionPrototypeTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("location", Map.of(
            "type", "string",
            "description", "Address or symbol name where the function is located"
        ));
        properties.put("signature", Map.of(
            "type", "string",
            "description", "C-style function signature (e.g., 'int main(int argc, char** argv)')"
        ));
        properties.put("createIfNotExists", Map.of(
            "type", "boolean",
            "description", "Create function if it doesn't exist at the location",
            "default", true
        ));

        List<String> required = List.of("programPath", "location", "signature");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("set-function-prototype")
            .title("Set Function Prototype")
            .description("Set or update a function prototype using C-style function signatures. Can create new functions or update existing ones.")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String location = getString(request, "location");
                String signature = getString(request, "signature");
                boolean createIfNotExists = getOptionalBoolean(request, "createIfNotExists", true);

                // Normalize signature to handle whitespace issues
                String normalizedSignature = normalizeFunctionSignature(signature);

                // Resolve the address from location
                Address address = getAddressFromArgs(request, program, "location");
                if (address == null) {
                    return createErrorResult("Invalid address or symbol: " + location);
                }

                FunctionManager functionManager = program.getFunctionManager();
                Function existingFunction = functionManager.getFunctionAt(address);

                // Parse the function signature using Ghidra's parser
                FunctionSignatureParser parser = new FunctionSignatureParser(
                    program.getDataTypeManager(), null);

                FunctionDefinitionDataType functionDef;
                try {
                    // Create original signature from existing function if it exists
                    FunctionDefinitionDataType originalSignature = null;
                    if (existingFunction != null) {
                        originalSignature = new FunctionDefinitionDataType(existingFunction.getName());
                        originalSignature.setReturnType(existingFunction.getReturnType());

                        // Convert parameters
                        List<ParameterDefinition> paramDefs = new ArrayList<>();
                        for (Parameter param : existingFunction.getParameters()) {
                            paramDefs.add(new ParameterDefinitionImpl(
                                param.getName(), param.getDataType(), param.getComment()));
                        }
                        originalSignature.setArguments(paramDefs.toArray(new ParameterDefinition[0]));
                        originalSignature.setVarArgs(existingFunction.hasVarArgs());
                    }

                    functionDef = parser.parse(originalSignature, normalizedSignature);
                } catch (ParseException e) {
                    // Check if the error is about missing datatypes
                    String errorMsg = e.getMessage();
                    if (errorMsg != null && errorMsg.contains("Can't resolve datatype")) {
                        return createErrorResult("Failed to parse function signature: " + errorMsg +
                            "\n\nHint: The datatype may not be defined in the program. Consider using a basic type (e.g., 'void*' instead of 'FILE*') or import the necessary type definitions.");
                    }
                    return createErrorResult("Failed to parse function signature: " + errorMsg);
                } catch (CancelledException e) {
                    return createErrorResult("Function signature parsing was cancelled");
                }

                int txId = program.startTransaction("Set Function Prototype");
                try {
                    Function function = existingFunction;

                    // Create function if it doesn't exist and creation is allowed
                    if (function == null) {
                        if (!createIfNotExists) {
                            return createErrorResult("Function does not exist at " +
                                AddressUtil.formatAddress(address) + " and createIfNotExists is false");
                        }

                        // Create a new function with minimal body (just the entry point)
                        AddressSet body = new AddressSet(address, address);
                        function = functionManager.createFunction(
                            functionDef.getName(), address, body, SourceType.USER_DEFINED);

                        if (function == null) {
                            return createErrorResult("Failed to create function at " +
                                AddressUtil.formatAddress(address));
                        }
                    }

                    // Check if we need to enable custom storage to modify auto-parameters
                    // Only enable it if an auto-parameter's type is actually being changed
                    boolean needsCustomStorage = needsCustomStorageForSignature(function, functionDef);
                    boolean wasUsingCustomStorage = function.hasCustomVariableStorage();

                    if (needsCustomStorage && !wasUsingCustomStorage) {
                        // Enable custom storage to allow modifying auto-parameters like 'this'
                        function.setCustomVariableStorage(true);
                        logInfo("Enabled custom storage for function " + function.getName() +
                                " to allow modifying auto-parameters (e.g., 'this' in __thiscall)");
                    }

                    // Update function name if it's different
                    if (!function.getName().equals(functionDef.getName())) {
                        function.setName(functionDef.getName(), SourceType.USER_DEFINED);
                    }

                    // Convert ParameterDefinitions to Variables (Parameters extend Variable)
                    // If using custom storage, preserve existing parameter storage where possible
                    List<Variable> parameters = new ArrayList<>();
                    ParameterDefinition[] paramDefs = functionDef.getArguments();
                    Parameter[] existingParams = function.getParameters();

                    for (int i = 0; i < paramDefs.length; i++) {
                        ParameterDefinition paramDef = paramDefs[i];

                        // If using custom storage and this parameter index exists, preserve its storage
                        if (function.hasCustomVariableStorage() && i < existingParams.length) {
                            // Preserve the existing parameter's storage when updating its type
                            parameters.add(new ParameterImpl(
                                paramDef.getName(),
                                paramDef.getDataType(),
                                existingParams[i].getVariableStorage(),
                                program));
                        } else {
                            // Create parameter without explicit storage (will be auto-assigned)
                            parameters.add(new ParameterImpl(
                                paramDef.getName(),
                                paramDef.getDataType(),
                                program));
                        }
                    }

                    // Update the function signature
                    // First update return type separately
                    function.setReturnType(functionDef.getReturnType(), SourceType.USER_DEFINED);

                    // Then update parameters
                    // Use appropriate update type based on whether we're using custom storage
                    Function.FunctionUpdateType updateType = function.hasCustomVariableStorage()
                        ? Function.FunctionUpdateType.CUSTOM_STORAGE
                        : Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS;

                    function.replaceParameters(parameters, updateType, true, SourceType.USER_DEFINED);

                    // Set varargs if needed
                    if (functionDef.hasVarArgs() != function.hasVarArgs()) {
                        function.setVarArgs(functionDef.hasVarArgs());
                    }

                    program.endTransaction(txId, true);

                    // Return updated function information
                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("created", existingFunction == null);
                    result.put("function", createFunctionInfo(function));
                    result.put("address", AddressUtil.formatAddress(address));
                    result.put("parsedSignature", functionDef.toString());
                    result.put("customStorageEnabled", needsCustomStorage && !wasUsingCustomStorage);
                    result.put("usingCustomStorage", function.hasCustomVariableStorage());

                    return createJsonResult(result);

                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    return createErrorResult("Failed to set function prototype: " + e.getMessage());
                }

            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                return createErrorResult("Unexpected error: " + e.getMessage());
            }
        });
    }
}
