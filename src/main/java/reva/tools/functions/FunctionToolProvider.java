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
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.app.cmd.function.CreateFunctionCmd;
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
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.FunctionTagManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
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

    /** Maximum function info cache entries (one per program/filter combination) */
    private static final int MAX_FUNCTION_INFO_CACHE_ENTRIES = 10;

    /** Timeout for building function info cache in seconds */
    private static final int FUNCTION_INFO_CACHE_TIMEOUT_SECONDS = 300;

    /** Maximum unique candidates to track before early termination (memory protection) */
    private static final int MAX_UNIQUE_CANDIDATES = 10000;

    /** Memory block patterns to exclude from undefined function candidates (PLT, GOT, imports) */
    private static final Set<String> EXCLUDED_BLOCK_PATTERNS = Set.of(
        ".plt", ".got", ".idata", ".edata", "extern", "external"
    );

    /** Valid modes for the function-tags tool */
    private static final Set<String> VALID_TAG_MODES = Set.of("get", "set", "add", "remove", "list");

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
     * Cache key for raw function info (shared between get-functions and get-functions-by-similarity).
     */
    private record FunctionInfoCacheKey(String programPath, boolean filterDefaultNames) {}

    /**
     * Cached function info list with metadata.
     */
    private record CachedFunctionInfo(
        List<Map<String, Object>> functions,
        long timestamp,
        long programModificationNumber
    ) {
        boolean isExpired() {
            return System.currentTimeMillis() - timestamp > CACHE_EXPIRATION_MS;
        }
    }

    /**
     * Thread-safe cache for raw function info (shared between listing tools).
     * Computing function info is expensive due to caller/callee counts.
     */
    private final ConcurrentHashMap<FunctionInfoCacheKey, CachedFunctionInfo> functionInfoCache =
        new ConcurrentHashMap<>();

    /**
     * Helper class to track undefined function candidate info including reference types.
     */
    private static class CandidateInfo {
        private final List<Address> references = new ArrayList<>();
        private boolean hasCallRef = false;
        private boolean hasDataRef = false;

        void addReference(Address fromAddr, boolean isCall, boolean isData) {
            references.add(fromAddr);
            if (isCall) hasCallRef = true;
            if (isData) hasDataRef = true;
        }

        int referenceCount() { return references.size(); }
        List<Address> references() { return references; }
        boolean hasCallRef() { return hasCallRef; }
        boolean hasDataRef() { return hasDataRef; }
    }

    /**
     * Constructor
     * @param server The MCP server
     */
    public FunctionToolProvider(McpSyncServer server) {
        super(server);
    }

    /**
     * Invalidate function caches for a specific program.
     * Called after modifications that change function metadata (e.g., tags).
     * Clears both functionInfoCache and similarityCache since both contain function data with tags.
     */
    private void invalidateFunctionCaches(String programPath) {
        functionInfoCache.entrySet().removeIf(entry -> entry.getKey().programPath().equals(programPath));
        similarityCache.entrySet().removeIf(entry -> entry.getKey().programPath().equals(programPath));
    }

    /**
     * Build a result map for rename operations.
     */
    private Map<String, Object> buildRenameResult(boolean renamed, String oldName, Function function, Address address, String programPath) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("renamed", renamed);
        result.put("created", false);
        result.put("oldName", oldName);
        result.put("function", createFunctionInfo(function, null));
        result.put("address", AddressUtil.formatAddress(address));
        result.put("programPath", programPath);
        return result;
    }

    /**
     * Clear cached results when a program is closed.
     */
    @Override
    public void programClosed(Program program) {
        super.programClosed(program);

        String programPath = program.getDomainFile().getPathname();

        // Clear similarity cache using removeIf (thread-safe, no iterator-while-modifying)
        int beforeSimilarity = similarityCache.size();
        similarityCache.entrySet().removeIf(entry -> entry.getKey().programPath().equals(programPath));
        int removedSimilarity = beforeSimilarity - similarityCache.size();

        // Clear function info cache using removeIf (thread-safe, no iterator-while-modifying)
        int beforeFunctionInfo = functionInfoCache.size();
        functionInfoCache.entrySet().removeIf(entry -> entry.getKey().programPath().equals(programPath));
        int removedFunctionInfo = beforeFunctionInfo - functionInfoCache.size();

        if (removedSimilarity > 0 || removedFunctionInfo > 0) {
            logInfo("FunctionToolProvider: Cleared " + removedSimilarity +
                " similarity cache entries and " + removedFunctionInfo +
                " function info cache entries for closed program: " + programPath);
        }
    }

    /**
     * Get function info list from cache or build it.
     * This is the shared cache used by both get-functions and get-functions-by-similarity.
     *
     * @param program The program to get function info from
     * @param filterDefaultNames Whether to filter out default Ghidra names
     * @return List of function info maps (never null, but may be empty if timeout)
     */
    private List<Map<String, Object>> getOrBuildFunctionInfoCache(Program program, boolean filterDefaultNames) {
        String programPath = program.getDomainFile().getPathname();
        FunctionInfoCacheKey cacheKey = new FunctionInfoCacheKey(programPath, filterDefaultNames);
        long currentModNumber = program.getModificationNumber();

        // Check cache first (thread-safe read)
        CachedFunctionInfo cached = functionInfoCache.get(cacheKey);
        if (cached != null && !cached.isExpired() && cached.programModificationNumber() == currentModNumber) {
            logInfo("FunctionToolProvider: Using cached function info for " + programPath);
            return cached.functions();
        }

        // Synchronize cache building to prevent duplicate work from concurrent requests
        synchronized (functionInfoCache) {
            // Double-check after acquiring lock (another thread may have built it)
            cached = functionInfoCache.get(cacheKey);
            if (cached != null && !cached.isExpired() && cached.programModificationNumber() == currentModNumber) {
                return cached.functions();
            }

            // Build function info list with timeout support
            logInfo("FunctionToolProvider: Building function info cache for " + programPath);
            long startTime = System.currentTimeMillis();

            TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(FUNCTION_INFO_CACHE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            List<Map<String, Object>> functionList = new ArrayList<>();
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            int processed = 0;

            while (functions.hasNext()) {
                // Check for timeout periodically
                if (processed % 100 == 0 && monitor.isCancelled()) {
                    logInfo("FunctionToolProvider: Cache build timed out after " + processed + " functions");
                    break;
                }

                Function function = functions.next();
                processed++;

                // Skip default Ghidra function names if filtering is enabled
                if (filterDefaultNames && SymbolUtil.isDefaultSymbolName(function.getName())) {
                    continue;
                }

                functionList.add(createFunctionInfo(function, monitor));
            }

            // Enforce cache size limit before adding new entry
            evictFunctionInfoCacheIfNeeded();

            // Cache the results
            CachedFunctionInfo newCached = new CachedFunctionInfo(
                List.copyOf(functionList),
                System.currentTimeMillis(),
                currentModNumber
            );
            functionInfoCache.put(cacheKey, newCached);

            long elapsed = System.currentTimeMillis() - startTime;
            if (elapsed > SLOW_SEARCH_THRESHOLD_MS) {
                logInfo("FunctionToolProvider: Building function info cache took " +
                    (elapsed / 1000) + "s (" + functionList.size() + " functions)");
            }

            return functionList;
        }
    }

    /**
     * Evict oldest function info cache entries if cache is at capacity.
     * Must be called while holding functionInfoCache lock.
     */
    private void evictFunctionInfoCacheIfNeeded() {
        // Remove expired entries first
        functionInfoCache.entrySet().removeIf(entry -> entry.getValue().isExpired());

        // Evict oldest entries if still over limit
        while (functionInfoCache.size() >= MAX_FUNCTION_INFO_CACHE_ENTRIES) {
            FunctionInfoCacheKey oldest = null;
            long oldestTime = Long.MAX_VALUE;
            for (var entry : functionInfoCache.entrySet()) {
                if (entry.getValue().timestamp() < oldestTime) {
                    oldestTime = entry.getValue().timestamp();
                    oldest = entry.getKey();
                }
            }
            if (oldest != null) {
                functionInfoCache.remove(oldest);
                logInfo("FunctionToolProvider: Evicted function info cache entry for: " + oldest.programPath());
            } else {
                break;
            }
        }
    }

    @Override
    public void registerTools() {
        registerFunctionCountTool();
        registerFunctionsTool();
        registerFunctionsBySimilarityTool();
        registerSetFunctionPrototypeTool();
        registerUndefinedFunctionCandidatesTool();
        registerCreateFunctionTool();
        registerFunctionTagsTool();
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

            logInfo("get-function-count: Counting functions in " + program.getName() +
                " (filterDefaultNames=" + filterDefaultNames + ")");
            long startTime = System.currentTimeMillis();

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

            // Log warning if operation took too long
            long elapsed = System.currentTimeMillis() - startTime;
            if (elapsed > SLOW_SEARCH_THRESHOLD_MS) {
                logInfo("get-function-count: Counting " + count.get() + " functions took " +
                    (elapsed / 1000) + "s in " + program.getName());
            }

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
        properties.put("filterByTag", Map.of(
            "type", "string",
            "description", "Only return functions with this tag (applied after filterDefaultNames)"
        ));
        properties.put("untagged", Map.of(
            "type", "boolean",
            "description", "Only return functions with no tags (mutually exclusive with filterByTag)",
            "default", false
        ));
        properties.put("verbose", Map.of(
            "type", "boolean",
            "description", "Return full function details. When false (default), returns compact results (name, address, sizeInBytes, tags, callerCount, calleeCount). Note: counts may be -1 if computation timed out.",
            "default", false
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
            String filterByTag = getOptionalString(request, "filterByTag", null);
            boolean untagged = getOptionalBoolean(request, "untagged", false);
            boolean verbose = getOptionalBoolean(request, "verbose", false);

            // Check mutual exclusivity
            if (untagged && filterByTag != null && !filterByTag.isEmpty()) {
                return createErrorResult("Cannot use both 'untagged' and 'filterByTag' - they are mutually exclusive");
            }

            // Get function info from shared cache (or build it)
            List<Map<String, Object>> allFunctions = getOrBuildFunctionInfoCache(program, filterDefaultNames);

            // Apply tag filter if specified
            List<Map<String, Object>> filteredFunctions;
            if (untagged) {
                filteredFunctions = allFunctions.stream()
                    .filter(f -> {
                        @SuppressWarnings("unchecked")
                        List<String> tags = (List<String>) f.get("tags");
                        return tags == null || tags.isEmpty();
                    })
                    .toList();
            } else if (filterByTag != null && !filterByTag.isEmpty()) {
                filteredFunctions = allFunctions.stream()
                    .filter(f -> {
                        @SuppressWarnings("unchecked")
                        List<String> tags = (List<String>) f.get("tags");
                        return tags != null && tags.contains(filterByTag);
                    })
                    .toList();
            } else {
                filteredFunctions = allFunctions;
            }

            int totalCount = filteredFunctions.size();

            // Apply pagination
            int startIndex = pagination.startIndex();
            int endIndex = Math.min(startIndex + pagination.maxCount(), totalCount);
            List<Map<String, Object>> paginatedData = startIndex < totalCount
                ? filteredFunctions.subList(startIndex, endIndex)
                : Collections.emptyList();

            // Transform results based on verbose flag
            List<Map<String, Object>> functionData;
            if (verbose) {
                // Full: return all function info as-is
                functionData = paginatedData;
            } else {
                // Compact: name, address, sizeInBytes, tags, callerCount, calleeCount
                functionData = new ArrayList<>(paginatedData.size());
                for (Map<String, Object> funcInfo : paginatedData) {
                    Map<String, Object> compactInfo = new HashMap<>();
                    compactInfo.put("name", funcInfo.get("name"));
                    compactInfo.put("address", funcInfo.get("address"));
                    compactInfo.put("sizeInBytes", funcInfo.get("sizeInBytes"));
                    compactInfo.put("tags", funcInfo.get("tags"));
                    compactInfo.put("callerCount", funcInfo.get("callerCount"));
                    compactInfo.put("calleeCount", funcInfo.get("calleeCount"));
                    functionData.add(compactInfo);
                }
            }

            // Add metadata about the filtering
            Map<String, Object> metadataInfo = new HashMap<>();
            metadataInfo.put("startIndex", startIndex);
            metadataInfo.put("requestedCount", pagination.maxCount());
            metadataInfo.put("actualCount", functionData.size());
            metadataInfo.put("nextStartIndex", startIndex + functionData.size());
            metadataInfo.put("totalCount", totalCount);
            metadataInfo.put("filterDefaultNames", filterDefaultNames);
            metadataInfo.put("verbose", verbose);
            if (filterByTag != null && !filterByTag.isEmpty()) {
                metadataInfo.put("filterByTag", filterByTag);
            }
            if (untagged) {
                metadataInfo.put("untagged", true);
            }

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
        properties.put("verbose", Map.of(
            "type", "boolean",
            "description", "Return full function details. When false (default), returns compact results (name, address, sizeInBytes, tags, callerCount, calleeCount, similarity). Note: counts may be -1 if computation timed out.",
            "default", false
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
            boolean verbose = getOptionalBoolean(request, "verbose", false);
            String programPath = program.getDomainFile().getPathname();

            if (searchString.trim().isEmpty()) {
                return createErrorResult("Search string cannot be empty");
            }

            logInfo("get-functions-by-similarity: Searching for '" + searchString + "' in " + program.getName());

            // Check similarity cache for existing sorted results (thread-safe read)
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
                // Cache miss - need to build similarity results
                // Get function info FIRST (outside similarityCache lock) to avoid holding
                // the lock during expensive cache-building operations
                List<Map<String, Object>> allFunctions = getOrBuildFunctionInfoCache(program, filterDefaultNames);

                // Now synchronize on similarityCache to prevent duplicate similarity computation
                synchronized (similarityCache) {
                    // Double-check after acquiring lock (another thread may have computed while we fetched function info)
                    cached = similarityCache.get(cacheKey);
                    if (cached != null && !cached.isExpired() && cached.programModificationNumber() == currentModNumber) {
                        wasCacheHit = true;
                        sortedFunctions = cached.sortedFunctions();
                        originalTotalCount = cached.totalCount();
                    } else {
                        long startTime = System.currentTimeMillis();

                        // Pre-filter: collect functions that contain search string as substring first
                        // This dramatically reduces the number of functions to sort with expensive LCS
                        String searchLower = searchString.toLowerCase();
                        List<Map<String, Object>> substringMatches = new ArrayList<>();
                        List<Map<String, Object>> nonMatches = new ArrayList<>();

                        for (Map<String, Object> functionInfo : allFunctions) {
                            String name = (String) functionInfo.get("name");
                            String nameLower = name.toLowerCase();

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

                        // Limit cached results to prevent memory bloat using stream for efficiency
                        List<Map<String, Object>> toCache = sortedFunctions.stream()
                            .limit(MAX_CACHED_RESULTS_PER_SEARCH)
                            .toList();

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

            // Transform results: add similarity score and optionally make compact
            String searchLower = searchString.toLowerCase();
            List<Map<String, Object>> transformedResults = new ArrayList<>(paginatedFunctionData.size());
            for (Map<String, Object> funcInfo : paginatedFunctionData) {
                String name = (String) funcInfo.get("name");
                double similarity = SimilarityComparator.calculateLcsSimilarity(searchLower, name.toLowerCase());

                if (verbose) {
                    // Full: all function info + similarity
                    Map<String, Object> fullInfo = new HashMap<>(funcInfo);
                    fullInfo.put("similarity", Math.round(similarity * 100.0) / 100.0);
                    transformedResults.add(fullInfo);
                } else {
                    // Compact: name, address, sizeInBytes, tags, callerCount, calleeCount, similarity
                    Map<String, Object> compactInfo = new HashMap<>();
                    compactInfo.put("name", name);
                    compactInfo.put("address", funcInfo.get("address"));
                    compactInfo.put("sizeInBytes", funcInfo.get("sizeInBytes"));
                    compactInfo.put("tags", funcInfo.get("tags"));
                    compactInfo.put("callerCount", funcInfo.get("callerCount"));
                    compactInfo.put("calleeCount", funcInfo.get("calleeCount"));
                    compactInfo.put("similarity", Math.round(similarity * 100.0) / 100.0); // Round to 2 decimals
                    transformedResults.add(compactInfo);
                }
            }

            // Create pagination metadata
            int reportedTotal = originalTotalCount > 0 ? originalTotalCount : totalCount;
            boolean resultsTruncated = totalCount < reportedTotal;

            Map<String, Object> paginationInfo = new HashMap<>();
            paginationInfo.put("searchString", searchString);
            paginationInfo.put("startIndex", startIndex);
            paginationInfo.put("requestedCount", pagination.maxCount());
            paginationInfo.put("actualCount", transformedResults.size());
            paginationInfo.put("nextStartIndex", startIndex + transformedResults.size());
            paginationInfo.put("totalMatchingFunctions", reportedTotal);
            paginationInfo.put("filterDefaultNames", filterDefaultNames);
            paginationInfo.put("verbose", verbose);
            paginationInfo.put("cacheHit", wasCacheHit);
            if (resultsTruncated) {
                paginationInfo.put("resultsTruncated", true);
                paginationInfo.put("maxCachedResults", MAX_CACHED_RESULTS_PER_SEARCH);
            }

            // Create combined result
            List<Object> resultData = new ArrayList<>();
            resultData.add(paginationInfo);
            resultData.addAll(transformedResults);
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
     * @param monitor TaskMonitor for cancellation support (can be null for quick operations)
     * @return Immutable map containing function properties
     */
    private Map<String, Object> createFunctionInfo(Function function, TaskMonitor monitor) {
        Map<String, Object> functionInfo = new HashMap<>();

        // Basic information - use AddressUtil for consistent formatting
        functionInfo.put("name", function.getName());
        functionInfo.put("address", AddressUtil.formatAddress(function.getEntryPoint()));

        // Get the function's body to determine the end address and size (cache to avoid duplicate call)
        AddressSetView body = function.getBody();
        if (body != null && body.getMaxAddress() != null) {
            functionInfo.put("endAddress", AddressUtil.formatAddress(body.getMaxAddress()));
            functionInfo.put("sizeInBytes", body.getNumAddresses());
        } else {
            functionInfo.put("sizeInBytes", 0);
        }

        // Additional function metadata
        functionInfo.put("signature", function.getSignature().toString());
        functionInfo.put("returnType", function.getReturnType().toString());
        functionInfo.put("isExternal", function.isExternal());
        functionInfo.put("isThunk", function.isThunk());

        // Analysis progress indicators (helps prioritize which functions to investigate)
        functionInfo.put("isDefaultName", SymbolUtil.isDefaultSymbolName(function.getName()));

        // Use provided monitor for caller/callee counts (these can be slow for complex programs)
        TaskMonitor countMonitor = (monitor != null) ? monitor : TaskMonitor.DUMMY;
        int callerCount = function.getCallingFunctions(countMonitor).size();
        // Check if operation was cancelled - use -1 to indicate incomplete data
        if (countMonitor.isCancelled()) {
            functionInfo.put("callerCount", -1);
            functionInfo.put("calleeCount", -1);
        } else {
            functionInfo.put("callerCount", callerCount);
            int calleeCount = function.getCalledFunctions(countMonitor).size();
            functionInfo.put("calleeCount", countMonitor.isCancelled() ? -1 : calleeCount);
        }

        // Add parameters info (as immutable list of immutable maps)
        List<Map<String, String>> parameters = new ArrayList<>();
        for (int i = 0; i < function.getParameterCount(); i++) {
            // Use Map.of for immutable parameter info
            parameters.add(Map.of(
                "name", function.getParameter(i).getName(),
                "dataType", function.getParameter(i).getDataType().toString()
            ));
        }
        functionInfo.put("parameters", List.copyOf(parameters));

        // Add function tags (sorted for consistent output)
        Set<FunctionTag> tags = function.getTags();
        List<String> tagNames = tags.stream()
            .map(FunctionTag::getName)
            .sorted()
            .toList();
        functionInfo.put("tags", tagNames);

        // Return immutable copy to prevent cache corruption
        return Collections.unmodifiableMap(functionInfo);
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
        properties.put("newName", Map.of(
            "type", "string",
            "description", "New name for the function (simple rename without changing signature). Mutually exclusive with 'signature'."
        ));
        properties.put("signature", Map.of(
            "type", "string",
            "description", "C-style function signature (e.g., 'int main(int argc, char** argv)'). Mutually exclusive with 'newName'."
        ));
        properties.put("createIfNotExists", Map.of(
            "type", "boolean",
            "description", "When using 'signature', create the function if it doesn't exist. Ignored when using 'newName'.",
            "default", true
        ));

        List<String> required = List.of("programPath", "location");

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
                String newName = getOptionalString(request, "newName", null);
                String signature = getOptionalString(request, "signature", null);
                boolean createIfNotExists = getOptionalBoolean(request, "createIfNotExists", true);

                // Check mutual exclusivity (trim once to avoid redundant calls)
                String trimmedNewName = newName != null ? newName.trim() : null;
                String trimmedSignature = signature != null ? signature.trim() : null;
                boolean hasNewName = trimmedNewName != null && !trimmedNewName.isEmpty();
                boolean hasSignature = trimmedSignature != null && !trimmedSignature.isEmpty();

                if (hasNewName && hasSignature) {
                    return createErrorResult("Cannot use both 'newName' and 'signature' - they are mutually exclusive");
                }
                if (!hasNewName && !hasSignature) {
                    return createErrorResult("Either 'newName' or 'signature' must be provided");
                }

                // Resolve the address from location
                Address address = getAddressFromArgs(request, program, "location");
                if (address == null) {
                    return createErrorResult("Invalid address or symbol: " + location);
                }

                FunctionManager functionManager = program.getFunctionManager();
                Function existingFunction = functionManager.getFunctionAt(address);

                // Handle simple rename case
                if (hasNewName) {
                    if (existingFunction == null) {
                        return createErrorResult("Function does not exist at " + AddressUtil.formatAddress(address) +
                            ". Use 'signature' with 'createIfNotExists' to create a new function.");
                    }

                    // Capture actual old name before renaming
                    String oldName = existingFunction.getName();
                    String programPath = program.getDomainFile().getPathname();

                    // Check if renaming to the same name (no-op)
                    if (trimmedNewName.equals(oldName)) {
                        return createJsonResult(buildRenameResult(false, oldName, existingFunction, address, programPath));
                    }

                    int txId = program.startTransaction("Rename function");
                    try {
                        existingFunction.setName(trimmedNewName, SourceType.USER_DEFINED);
                        program.endTransaction(txId, true);

                        // Invalidate function caches since name changed
                        invalidateFunctionCaches(programPath);

                        return createJsonResult(buildRenameResult(true, oldName, existingFunction, address, programPath));
                    } catch (DuplicateNameException e) {
                        program.endTransaction(txId, false);
                        return createErrorResult("Function name '" + trimmedNewName + "' already exists in this namespace");
                    } catch (InvalidInputException e) {
                        program.endTransaction(txId, false);
                        return createErrorResult("Invalid function name '" + trimmedNewName + "': " + e.getMessage());
                    } catch (Exception e) {
                        program.endTransaction(txId, false);
                        return createErrorResult("Failed to rename function: " + e.getMessage());
                    }
                }

                // Full signature change path - normalize to handle whitespace issues
                String normalizedSignature = normalizeFunctionSignature(trimmedSignature);

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

                // Capture old name before any changes (for renamed tracking)
                String oldName = existingFunction != null ? existingFunction.getName() : null;

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

                    // Invalidate function caches since prototype changed
                    String programPath = program.getDomainFile().getPathname();
                    invalidateFunctionCaches(programPath);

                    // Return updated function information
                    boolean wasCreated = existingFunction == null;
                    boolean wasRenamed = oldName != null && !oldName.equals(function.getName());

                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("created", wasCreated);
                    result.put("renamed", wasRenamed);
                    if (oldName != null) {
                        result.put("oldName", oldName);
                    }
                    result.put("function", createFunctionInfo(function, null));
                    result.put("address", AddressUtil.formatAddress(address));
                    result.put("programPath", programPath);
                    result.put("parsedSignature", functionDef.toString());
                    result.put("customStorageEnabled", needsCustomStorage && !wasUsingCustomStorage);
                    result.put("usingCustomStorage", function.hasCustomVariableStorage());

                    return createJsonResult(result);

                } catch (DuplicateNameException e) {
                    program.endTransaction(txId, false);
                    return createErrorResult("Function name '" + functionDef.getName() + "' already exists in this namespace");
                } catch (InvalidInputException e) {
                    program.endTransaction(txId, false);
                    return createErrorResult("Invalid function prototype: " + e.getMessage());
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

    /**
     * Register a tool to find undefined function candidates - addresses that receive
     * CALL or DATA references but are not defined as functions.
     */
    private void registerUndefinedFunctionCandidatesTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("maxCandidates", Map.of(
            "type", "integer",
            "description", "Maximum number of candidates to return (default: 100)",
            "default", 100
        ));
        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (0-based)",
            "default", 0
        ));
        properties.put("minReferenceCount", Map.of(
            "type", "integer",
            "description", "Minimum number of references required to be a candidate (default: 1)",
            "default", 1
        ));

        List<String> required = List.of("programPath");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-undefined-function-candidates")
            .title("Get Undefined Function Candidates")
            .description("Find addresses in executable memory with valid instructions that are referenced but not defined as functions. " +
                "Includes both CALL references and DATA references (function pointers, callbacks, exception handlers). " +
                "Use get-decompilation to preview candidates, then create-function to define them permanently.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            String programPath = program.getDomainFile().getPathname();
            int maxCandidates = getOptionalInt(request, "maxCandidates", 100);
            int startIndex = getOptionalInt(request, "startIndex", 0);
            int minReferenceCount = getOptionalInt(request, "minReferenceCount", 1);

            // Validate minReferenceCount
            if (minReferenceCount < 1) {
                return createErrorResult("minReferenceCount must be at least 1");
            }

            logInfo("get-undefined-function-candidates: Scanning " + program.getName());
            long startTime = System.currentTimeMillis();

            FunctionManager funcMgr = program.getFunctionManager();
            ReferenceManager refMgr = program.getReferenceManager();

            // Collect all reference targets and track reference types
            // Key: target address, Value: map with "callers" list and "hasCallRef"/"hasDataRef" flags
            Map<Address, CandidateInfo> candidates = new HashMap<>();
            ReferenceIterator refIter = refMgr.getReferenceIterator(program.getMinAddress());

            // Cache memory block exclusion status to avoid recalculating for every reference
            Map<MemoryBlock, Boolean> blockExclusionCache = new HashMap<>();

            int refsScanned = 0;
            boolean earlyTermination = false;

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                refsScanned++;

                boolean isCallRef = ref.getReferenceType().isCall();
                boolean isDataRef = ref.getReferenceType().isData();

                // Only interested in CALL and DATA references (function calls and function pointers)
                if (!isCallRef && !isDataRef) {
                    continue;
                }

                Address targetAddr = ref.getToAddress();

                // Skip if already a defined function
                if (funcMgr.getFunctionAt(targetAddr) != null) {
                    continue;
                }

                // Skip external addresses
                if (targetAddr.isExternalAddress()) {
                    continue;
                }

                // Skip addresses in non-executable memory or special sections
                MemoryBlock block = program.getMemory().getBlock(targetAddr);
                if (block == null || !block.isExecute()) {
                    continue;
                }

                // Skip PLT/GOT/import entries (common false positives) - use cached result
                Boolean isExcluded = blockExclusionCache.get(block);
                if (isExcluded == null) {
                    String blockNameLower = block.getName().toLowerCase();
                    isExcluded = EXCLUDED_BLOCK_PATTERNS.stream()
                        .anyMatch(blockNameLower::contains);
                    blockExclusionCache.put(block, isExcluded);
                }
                if (isExcluded) {
                    continue;
                }

                // Skip addresses without instructions (IAT thunks, data pointers, etc.)
                // These are not valid function candidates
                if (program.getListing().getInstructionAt(targetAddr) == null) {
                    continue;
                }

                // Track this candidate
                CandidateInfo info = candidates.computeIfAbsent(targetAddr, k -> new CandidateInfo());
                info.addReference(ref.getFromAddress(), isCallRef, isDataRef);

                // Memory protection: stop if too many unique candidates
                if (candidates.size() >= MAX_UNIQUE_CANDIDATES) {
                    earlyTermination = true;
                    logInfo("get-undefined-function-candidates: Early termination at " +
                        MAX_UNIQUE_CANDIDATES + " unique candidates (memory protection)");
                    break;
                }
            }

            // Filter by minimum reference count and sort by reference count (descending)
            List<Map.Entry<Address, CandidateInfo>> sortedCandidates = candidates.entrySet().stream()
                .filter(e -> e.getValue().referenceCount() >= minReferenceCount)
                .sorted((a, b) -> Integer.compare(b.getValue().referenceCount(), a.getValue().referenceCount()))
                .toList();

            int totalCandidates = sortedCandidates.size();

            // Apply pagination
            List<Map<String, Object>> candidatesList = new ArrayList<>();
            int endIndex = Math.min(startIndex + maxCandidates, sortedCandidates.size());

            for (int i = startIndex; i < endIndex; i++) {
                Map.Entry<Address, CandidateInfo> entry = sortedCandidates.get(i);
                Address addr = entry.getKey();
                CandidateInfo info = entry.getValue();

                Map<String, Object> candidate = new HashMap<>();
                candidate.put("address", AddressUtil.formatAddress(addr));
                candidate.put("referenceCount", info.referenceCount());
                candidate.put("hasCallReference", info.hasCallRef());
                candidate.put("hasDataReference", info.hasDataRef());

                // Include sample references (up to 5)
                List<String> sampleReferences = new ArrayList<>();
                List<Address> refs = info.references();
                for (int j = 0; j < Math.min(5, refs.size()); j++) {
                    Address refAddr = refs.get(j);
                    Function refFunc = funcMgr.getFunctionContaining(refAddr);
                    if (refFunc != null) {
                        sampleReferences.add(refFunc.getName() + " (" +
                            AddressUtil.formatAddress(refAddr) + ")");
                    } else {
                        sampleReferences.add(AddressUtil.formatAddress(refAddr));
                    }
                }
                candidate.put("sampleReferences", sampleReferences);

                // Get memory block info
                MemoryBlock block = program.getMemory().getBlock(addr);
                if (block != null) {
                    candidate.put("memoryBlock", block.getName());
                }

                // Check for any existing symbol
                Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
                if (symbol != null) {
                    candidate.put("existingSymbol", symbol.getName());
                }

                candidatesList.add(candidate);
            }

            // Log timing for slow operations (with pagination context)
            long elapsed = System.currentTimeMillis() - startTime;
            if (elapsed > SLOW_SEARCH_THRESHOLD_MS) {
                logInfo("get-undefined-function-candidates: Found " + totalCandidates +
                    " candidates in " + (elapsed / 1000) + "s (scanned " + refsScanned +
                    " refs, returning " + startIndex + "-" + endIndex + ")");
            }

            // Build response
            Map<String, Object> result = new HashMap<>();
            result.put("programPath", programPath);
            result.put("candidates", candidatesList);
            result.put("totalCandidates", totalCandidates);
            result.put("referencesScanned", refsScanned);
            if (earlyTermination) {
                result.put("earlyTermination", true);
                result.put("note", "Scan stopped early due to memory limits. Results may be incomplete.");
            }
            result.put("pagination", Map.of(
                "startIndex", startIndex,
                "maxCandidates", maxCandidates,
                "returnedCount", candidatesList.size(),
                "hasMore", endIndex < totalCandidates
            ));

            return createJsonResult(result);
        });
    }

    /**
     * Register a tool to create a function at an address with auto-detected signature.
     * This is simpler than set-function-prototype as it doesn't require specifying a signature.
     */
    private void registerCreateFunctionTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("address", Map.of(
            "type", "string",
            "description", "Address where the function should be created (e.g., '0x401000')"
        ));
        properties.put("name", Map.of(
            "type", "string",
            "description", "Optional name for the function. If not provided, Ghidra will generate a default name (FUN_xxxxxxxx)"
        ));

        List<String> required = List.of("programPath", "address");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("create-function")
            .title("Create Function")
            .description("Create a function at an address with auto-detected signature. " +
                "Ghidra will analyze the code to determine the function body, parameters, and return type. " +
                "Use this after get-undefined-function-candidates to define discovered functions. " +
                "For explicit signature control, use set-function-prototype instead.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            String programPath = program.getDomainFile().getPathname();
            String name = getOptionalString(request, "name", null);

            // Resolve the address using the standard helper
            Address address = getAddressFromArgs(request, program, "address");

            // Validate address is in executable memory
            MemoryBlock block = program.getMemory().getBlock(address);
            if (block == null) {
                return createErrorResult("Address " + AddressUtil.formatAddress(address) +
                    " is not in any memory block");
            }
            if (!block.isExecute()) {
                return createErrorResult("Address " + AddressUtil.formatAddress(address) +
                    " is not in executable memory (block: " + block.getName() + ")");
            }

            // Check if there's already a function at this address
            FunctionManager funcMgr = program.getFunctionManager();
            Function existingFunc = funcMgr.getFunctionAt(address);
            if (existingFunc != null) {
                return createErrorResult("Function already exists at " +
                    AddressUtil.formatAddress(address) + ": " + existingFunc.getName());
            }

            // Check if there's an instruction at the address
            Instruction instr = program.getListing().getInstructionAt(address);
            if (instr == null) {
                return createErrorResult("No instruction at address " +
                    AddressUtil.formatAddress(address) +
                    ". The address may need to be disassembled first.");
            }

            // Create the function using CreateFunctionCmd
            int txId = program.startTransaction("Create Function");
            try {
                CreateFunctionCmd cmd = new CreateFunctionCmd(address);
                boolean success = cmd.applyTo(program);

                if (!success) {
                    program.endTransaction(txId, false);
                    String statusMsg = cmd.getStatusMsg();
                    return createErrorResult("Failed to create function at " +
                        AddressUtil.formatAddress(address) +
                        (statusMsg != null ? ": " + statusMsg : ""));
                }

                // Get the created function
                Function createdFunc = funcMgr.getFunctionAt(address);
                if (createdFunc == null) {
                    program.endTransaction(txId, false);
                    return createErrorResult("Function creation reported success but function not found");
                }

                // Set custom name if provided
                if (name != null && !name.isEmpty()) {
                    try {
                        createdFunc.setName(name, SourceType.USER_DEFINED);
                    } catch (DuplicateNameException e) {
                        // Name already exists, keep the default name
                        logInfo("create-function: Name '" + name + "' already exists, keeping default name");
                    } catch (InvalidInputException e) {
                        logInfo("create-function: Invalid name '" + name + "': " + e.getMessage());
                    }
                }

                program.endTransaction(txId, true);

                // Build response
                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("programPath", programPath);
                result.put("function", createFunctionInfo(createdFunc, null));
                result.put("address", AddressUtil.formatAddress(address));
                result.put("nameWasProvided", name != null && !name.isEmpty());

                return createJsonResult(result);

            } catch (Exception e) {
                program.endTransaction(txId, false);
                return createErrorResult("Error creating function: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to manage function tags (get/set/add/remove/list).
     */
    private void registerFunctionTagsTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("function", Map.of(
            "type", "string",
            "description", "Function name or address (required for get/set/add/remove modes)"
        ));
        properties.put("mode", Map.of(
            "type", "string",
            "description", "Operation: 'get' (tags on function), 'set' (replace), 'add', 'remove', 'list' (all tags in program)",
            "enum", List.of("get", "set", "add", "remove", "list")
        ));
        properties.put("tags", Map.of(
            "type", "array",
            "description", "Tag names (required for add; optional for set/remove). Empty/whitespace names are ignored.",
            "items", Map.of("type", "string")
        ));

        List<String> required = List.of("programPath", "mode");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("function-tags")
            .title("Function Tags")
            .description("Manage function tags. Tags categorize functions (e.g., 'AI', 'rendering'). Use mode='list' for all tags in program.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            String mode = getString(request, "mode");
            String programPath = program.getDomainFile().getPathname();

            // Defensive validation - schema enum should catch this, but validates against direct API calls
            if (!VALID_TAG_MODES.contains(mode)) {
                return createErrorResult("Unknown mode: " + mode + ". Valid modes: " + VALID_TAG_MODES);
            }

            // Handle list mode (program-wide, no function needed)
            if ("list".equals(mode)) {
                FunctionTagManager tagManager = program.getFunctionManager().getFunctionTagManager();
                List<? extends FunctionTag> allTags = tagManager.getAllFunctionTags();

                List<Map<String, Object>> tagInfoList = new ArrayList<>();
                for (FunctionTag tag : allTags) {
                    Map<String, Object> tagInfo = new HashMap<>();
                    tagInfo.put("name", tag.getName());
                    tagInfo.put("count", tagManager.getUseCount(tag));
                    String comment = tag.getComment();
                    if (comment != null && !comment.isEmpty()) {
                        tagInfo.put("comment", comment);
                    }
                    tagInfoList.add(tagInfo);
                }

                // Sort by name for consistent output
                tagInfoList.sort(Comparator.comparing(m -> (String) m.get("name")));

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("programPath", programPath);
                result.put("tags", tagInfoList);
                result.put("totalTags", tagInfoList.size());

                return createJsonResult(result);
            }

            // For all other modes, function is required
            String functionRef = getOptionalString(request, "function", null);
            if (functionRef == null || functionRef.isEmpty()) {
                return createErrorResult("'function' parameter is required for mode: " + mode);
            }

            // Resolve function (throws IllegalArgumentException if not found, caught by registerTool wrapper)
            Function function = getFunctionFromArgs(request.arguments(), program, "function");

            // Handle get mode (no modification)
            if ("get".equals(mode)) {
                List<String> tagNames = function.getTags().stream()
                    .map(FunctionTag::getName)
                    .sorted()
                    .toList();

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("programPath", programPath);
                result.put("mode", mode);
                result.put("function", function.getName());
                result.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
                result.put("tags", tagNames);

                return createJsonResult(result);
            }

            // For set/add/remove, tags parameter handling
            List<String> tagList = getOptionalStringList(request.arguments(), "tags", null);
            if (tagList == null || tagList.isEmpty()) {
                if ("set".equals(mode) || "remove".equals(mode)) {
                    // Empty set clears all tags; empty remove is a no-op
                    tagList = List.of();
                } else {
                    // add mode requires at least one tag
                    return createErrorResult("'tags' parameter is required for mode: " + mode);
                }
            }

            // Modify tags within a transaction
            int txId = program.startTransaction("Update function tags");
            boolean committed = false;
            try {
                if ("set".equals(mode)) {
                    // Copy to HashSet to avoid ConcurrentModificationException when removing
                    Set<FunctionTag> existingTags = new HashSet<>(function.getTags());
                    for (FunctionTag tag : existingTags) {
                        function.removeTag(tag.getName());
                    }
                    for (String tagName : tagList) {
                        if (tagName != null && !tagName.trim().isEmpty()) {
                            function.addTag(tagName.trim());
                        }
                    }
                } else if ("add".equals(mode)) {
                    for (String tagName : tagList) {
                        if (tagName != null && !tagName.trim().isEmpty()) {
                            function.addTag(tagName.trim());
                        }
                    }
                } else if ("remove".equals(mode)) {
                    for (String tagName : tagList) {
                        if (tagName != null && !tagName.trim().isEmpty()) {
                            function.removeTag(tagName.trim());
                        }
                    }
                }

                program.endTransaction(txId, true);
                committed = true;
            } catch (Exception e) {
                if (!committed) {
                    program.endTransaction(txId, false);
                }
                return createErrorResult("Error updating function tags: " + e.getMessage());
            }

            // Invalidate caches since tags changed (outside try block for robustness)
            invalidateFunctionCaches(programPath);

            // Return lean response with just identifiers and updated tags
            List<String> updatedTags = function.getTags().stream()
                .map(FunctionTag::getName)
                .sorted()
                .toList();

            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("programPath", programPath);
            result.put("mode", mode);
            result.put("function", function.getName());
            result.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
            result.put("tags", updatedTags);

            return createJsonResult(result);
        });
    }

}
