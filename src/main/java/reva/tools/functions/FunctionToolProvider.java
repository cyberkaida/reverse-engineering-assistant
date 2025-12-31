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
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
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
import reva.util.IncludeFilterUtil;
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
    private record SimilarityCacheKey(String programPath, String searchString, String include) {}

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
     * Caches ALL functions - filtering by include is done at query time.
     */
    private record FunctionInfoCacheKey(String programPath) {}

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
     * Filter a function info map based on the include parameter.
     *
     * @param funcInfo The function info map (must contain "name" key)
     * @param include The include filter value ("all", "named", or "unnamed")
     * @return true if the function should be included, false otherwise
     */
    private boolean shouldIncludeFunctionInfo(Map<String, Object> funcInfo, String include) {
        String name = (String) funcInfo.get("name");
        return IncludeFilterUtil.shouldInclude(name, include);
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
     * Caches ALL functions - filtering by include is done at query time.
     *
     * @param program The program to get function info from
     * @return List of function info maps for ALL functions (never null, but may be empty if timeout)
     */
    private List<Map<String, Object>> getOrBuildFunctionInfoCache(Program program) {
        String programPath = program.getDomainFile().getPathname();
        FunctionInfoCacheKey cacheKey = new FunctionInfoCacheKey(programPath);
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

            // Build function info list (cache ALL functions)
            // Use createFunctionInfoFast to skip expensive caller/callee count computation
            logInfo("FunctionToolProvider: Building function info cache for " + programPath);
            long startTime = System.currentTimeMillis();

            List<Map<String, Object>> functionList = new ArrayList<>();
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            int processed = 0;

            while (functions.hasNext()) {
                Function function = functions.next();
                processed++;

                // Use fast version - skips caller/callee count computation
                functionList.add(createFunctionInfoFast(function));
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
        registerBatchSetFunctionPrototypeTool();
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
        properties.put("include", IncludeFilterUtil.getIncludePropertyDefinition());

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
            String include = IncludeFilterUtil.validate(getOptionalString(request, "include", null));

            logInfo("get-function-count: Counting functions in " + program.getName() +
                " (include=" + include + ")");
            long startTime = System.currentTimeMillis();

            AtomicInteger count = new AtomicInteger(0);

            // Iterate through all functions using shared filter logic
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            functions.forEach(function -> {
                if (IncludeFilterUtil.shouldInclude(function.getName(), include)) {
                    count.incrementAndGet();
                }
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
            countData.put("include", include);

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
        properties.put("include", IncludeFilterUtil.getIncludePropertyDefinition());

        // Name filtering
        properties.put("nameRegex", Map.of(
            "type", "string",
            "description", "Only return functions whose names match this regex pattern (e.g., '^(TG_|Map_|Vehicle_)' or '.*Handler$')"
        ));
        properties.put("excludeNameRegex", Map.of(
            "type", "string",
            "description", "Exclude functions whose names match this regex pattern (e.g., '^(CDC_|CWnd_|CString_)' to filter out MFC classes)"
        ));

        // Tag filtering
        properties.put("filterByTags", Map.of(
            "type", "array",
            "description", "Only return functions with ANY of these tags (OR logic)",
            "items", Map.of("type", "string")
        ));
        properties.put("excludeTags", Map.of(
            "type", "array",
            "description", "Exclude functions with ANY of these tags",
            "items", Map.of("type", "string")
        ));
        properties.put("untagged", Map.of(
            "type", "boolean",
            "description", "Only return functions with no tags (mutually exclusive with filterByTags)",
            "default", false
        ));

        // Count range filtering
        properties.put("minCalleeCount", Map.of(
            "type", "integer",
            "description", "Minimum number of callees (functions this function calls)"
        ));
        properties.put("maxCalleeCount", Map.of(
            "type", "integer",
            "description", "Maximum number of callees (functions this function calls)"
        ));
        properties.put("minCallerCount", Map.of(
            "type", "integer",
            "description", "Minimum number of callers (functions that call this function)"
        ));
        properties.put("maxCallerCount", Map.of(
            "type", "integer",
            "description", "Maximum number of callers (functions that call this function)"
        ));

        // Sorting
        properties.put("sortBy", Map.of(
            "type", "string",
            "description", "Sort results by this field",
            "enum", List.of("address", "name", "calleeCount", "callerCount", "sizeInBytes")
        ));
        properties.put("sortOrder", Map.of(
            "type", "string",
            "description", "Sort order (default: ascending)",
            "enum", List.of("ascending", "descending"),
            "default", "ascending"
        ));

        // Dependency filtering (for bottom-up porting workflows)
        properties.put("requireCalleesTagged", Map.of(
            "type", "array",
            "description", "Only return functions where ALL callees have ALL of these tags (or are external/thunks). Useful for finding functions ready to port.",
            "items", Map.of("type", "string")
        ));
        properties.put("allowExternalCallees", Map.of(
            "type", "boolean",
            "description", "When using requireCalleesTagged, treat external/thunk callees as satisfying the tag requirement (default: true)",
            "default", true
        ));
        properties.put("allowUntaggedCallees", Map.of(
            "type", "boolean",
            "description", "When using requireCalleesTagged, allow callees with no tags (default: false)",
            "default", false
        ));

        // Output options
        properties.put("verbose", Map.of(
            "type", "boolean",
            "description", "Return full function details (signature, parameters, etc.). When false (default), returns compact results.",
            "default", false
        ));
        properties.put("includeCallees", Map.of(
            "type", "boolean",
            "description", "Include callee details in response (address, name, tags, isExternal). Useful with requireCalleesTagged.",
            "default", false
        ));

        // Structure usage filter
        properties.put("usesStructure", Map.of(
            "type", "string",
            "description", "Only return functions that use this structure (in return type, parameters, or local variables)"
        ));

        // Pagination
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
            .description("Get functions from the selected program with filtering, sorting, and dependency analysis. Supports tag filtering, caller/callee count ranges, and finding functions where all callees meet tag requirements (useful for bottom-up porting workflows).")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            String programPath = program.getDomainFile().getPathname();
            PaginationParams pagination = getPaginationParams(request);
            String include = IncludeFilterUtil.validate(getOptionalString(request, "include", null));

            // Name regex filtering parameters
            String nameRegexStr = getOptionalString(request, "nameRegex", null);
            String excludeNameRegexStr = getOptionalString(request, "excludeNameRegex", null);

            // Compile regex patterns (with validation)
            Pattern namePattern = null;
            Pattern excludeNamePattern = null;
            try {
                if (nameRegexStr != null && !nameRegexStr.isEmpty()) {
                    namePattern = Pattern.compile(nameRegexStr);
                }
                if (excludeNameRegexStr != null && !excludeNameRegexStr.isEmpty()) {
                    excludeNamePattern = Pattern.compile(excludeNameRegexStr);
                }
            } catch (PatternSyntaxException e) {
                return createErrorResult("Invalid regex pattern: " + e.getMessage());
            }

            // Tag filtering parameters
            List<String> filterByTags = getOptionalStringList(request.arguments(), "filterByTags", null);
            List<String> excludeTags = getOptionalStringList(request.arguments(), "excludeTags", null);
            boolean untagged = getOptionalBoolean(request, "untagged", false);

            // Count range filtering parameters
            Integer minCalleeCount = getOptionalInteger(request.arguments(), "minCalleeCount", null);
            Integer maxCalleeCount = getOptionalInteger(request.arguments(), "maxCalleeCount", null);
            Integer minCallerCount = getOptionalInteger(request.arguments(), "minCallerCount", null);
            Integer maxCallerCount = getOptionalInteger(request.arguments(), "maxCallerCount", null);

            // Sorting parameters
            String sortBy = getOptionalString(request, "sortBy", null);
            String sortOrder = getOptionalString(request, "sortOrder", "ascending");

            // Dependency filtering parameters
            List<String> requireCalleesTagged = getOptionalStringList(request.arguments(), "requireCalleesTagged", null);
            boolean allowExternalCallees = getOptionalBoolean(request, "allowExternalCallees", true);
            boolean allowUntaggedCallees = getOptionalBoolean(request, "allowUntaggedCallees", false);

            // Output options
            boolean verbose = getOptionalBoolean(request, "verbose", false);
            boolean includeCallees = getOptionalBoolean(request, "includeCallees", false);

            // Structure usage filter
            String usesStructureName = getOptionalString(request, "usesStructure", null);
            ghidra.program.model.data.DataType usesStructureType = null;
            if (usesStructureName != null && !usesStructureName.isEmpty()) {
                usesStructureType = findDataTypeByName(program.getDataTypeManager(), usesStructureName);
                if (usesStructureType == null) {
                    return createErrorResult("Structure not found: " + usesStructureName +
                        ". Use list-structures to see available structures.");
                }
            }
            final ghidra.program.model.data.DataType finalUsesStructureType = usesStructureType;

            // Validate mutual exclusivity
            boolean hasFilterByTags = filterByTags != null && !filterByTags.isEmpty();
            if (untagged && hasFilterByTags) {
                return createErrorResult("Cannot use both 'untagged' and 'filterByTags' - they are mutually exclusive");
            }

            logInfo("get-functions: Listing functions in " + program.getName() + " (include=" + include + ")");

            // Get ALL function info from shared cache
            List<Map<String, Object>> allFunctions = getOrBuildFunctionInfoCache(program);

            // Build function tag lookup for dependency filtering (only if needed)
            Map<Address, Set<String>> functionTagLookup = null;
            boolean hasDependencyFilter = requireCalleesTagged != null && !requireCalleesTagged.isEmpty();
            if (hasDependencyFilter) {
                functionTagLookup = buildFunctionTagLookup(program);
            }

            // Apply filters in order of cost (cheap to expensive)
            final String includeFilter = include;
            final Pattern finalNamePattern = namePattern;
            final Pattern finalExcludeNamePattern = excludeNamePattern;
            final List<String> finalFilterByTags = filterByTags;
            final List<String> finalExcludeTags = excludeTags;
            final Map<Address, Set<String>> finalTagLookup = functionTagLookup;

            List<Map<String, Object>> filteredFunctions = allFunctions.stream()
                // Stage 1: Include filter (cheap - string check)
                .filter(f -> shouldIncludeFunctionInfo(f, includeFilter))
                // Stage 2: Name regex filters (cheap - regex match)
                .filter(f -> matchesNameRegex(f, finalNamePattern, finalExcludeNamePattern))
                // Stage 3: Tag filters (cheap - list check)
                .filter(f -> matchesTagFilters(f, finalFilterByTags, finalExcludeTags, untagged))
                // Stage 4: Count range filters (cheap - integer comparison)
                .filter(f -> matchesCountFilters(f, minCalleeCount, maxCalleeCount, minCallerCount, maxCallerCount))
                // Stage 5: Dependency filter (expensive)
                .filter(f -> {
                    if (!hasDependencyFilter) return true;
                    return matchesDependencyFilter(program, f, requireCalleesTagged,
                        allowExternalCallees, allowUntaggedCallees, finalTagLookup);
                })
                // Stage 6: Structure usage filter (expensive - check return type, params, variables)
                .filter(f -> {
                    if (finalUsesStructureType == null) return true;
                    return matchesStructureUsageFilter(program, f, finalUsesStructureType);
                })
                .toList();

            // Apply sorting if requested
            if (sortBy != null && !sortBy.isEmpty()) {
                filteredFunctions = sortFunctions(filteredFunctions, sortBy, sortOrder);
            }

            int totalCount = filteredFunctions.size();

            // Apply pagination
            int startIndex = pagination.startIndex();
            int endIndex = Math.min(startIndex + pagination.maxCount(), totalCount);
            List<Map<String, Object>> paginatedData = startIndex < totalCount
                ? filteredFunctions.subList(startIndex, endIndex)
                : Collections.emptyList();

            // Transform results based on verbose and includeCallees flags
            List<Map<String, Object>> functionData = new ArrayList<>(paginatedData.size());
            for (Map<String, Object> funcInfo : paginatedData) {
                Map<String, Object> outputInfo;

                if (verbose) {
                    // Full: return all cached function info
                    outputInfo = new HashMap<>(funcInfo);
                } else {
                    // Compact: name, address, sizeInBytes, tags, callerCount, calleeCount
                    outputInfo = new HashMap<>();
                    outputInfo.put("name", funcInfo.get("name"));
                    outputInfo.put("address", funcInfo.get("address"));
                    outputInfo.put("sizeInBytes", funcInfo.get("sizeInBytes"));
                    outputInfo.put("tags", funcInfo.get("tags"));
                    outputInfo.put("callerCount", funcInfo.get("callerCount"));
                    outputInfo.put("calleeCount", funcInfo.get("calleeCount"));
                }

                // Add callee details if requested
                if (includeCallees) {
                    String addressStr = (String) funcInfo.get("address");
                    Address funcAddr = program.getAddressFactory().getAddress(addressStr);
                    if (funcAddr != null) {
                        Function function = program.getFunctionManager().getFunctionAt(funcAddr);
                        if (function != null) {
                            outputInfo.put("callees", getCalleeDetails(program, function));
                        }
                    }
                }

                functionData.add(outputInfo);
            }

            // Build metadata
            Map<String, Object> metadataInfo = new HashMap<>();
            metadataInfo.put("startIndex", startIndex);
            metadataInfo.put("requestedCount", pagination.maxCount());
            metadataInfo.put("actualCount", functionData.size());
            metadataInfo.put("nextStartIndex", startIndex + functionData.size());
            metadataInfo.put("totalCount", totalCount);
            metadataInfo.put("include", include);
            metadataInfo.put("verbose", verbose);

            // Add filter metadata
            if (nameRegexStr != null && !nameRegexStr.isEmpty()) {
                metadataInfo.put("nameRegex", nameRegexStr);
            }
            if (excludeNameRegexStr != null && !excludeNameRegexStr.isEmpty()) {
                metadataInfo.put("excludeNameRegex", excludeNameRegexStr);
            }
            if (hasFilterByTags) {
                metadataInfo.put("filterByTags", filterByTags);
            }
            if (excludeTags != null && !excludeTags.isEmpty()) {
                metadataInfo.put("excludeTags", excludeTags);
            }
            if (untagged) {
                metadataInfo.put("untagged", true);
            }
            if (minCalleeCount != null) metadataInfo.put("minCalleeCount", minCalleeCount);
            if (maxCalleeCount != null) metadataInfo.put("maxCalleeCount", maxCalleeCount);
            if (minCallerCount != null) metadataInfo.put("minCallerCount", minCallerCount);
            if (maxCallerCount != null) metadataInfo.put("maxCallerCount", maxCallerCount);
            if (sortBy != null && !sortBy.isEmpty()) {
                metadataInfo.put("sortBy", sortBy);
                metadataInfo.put("sortOrder", sortOrder);
            }
            if (hasDependencyFilter) {
                metadataInfo.put("requireCalleesTagged", requireCalleesTagged);
                metadataInfo.put("allowExternalCallees", allowExternalCallees);
                metadataInfo.put("allowUntaggedCallees", allowUntaggedCallees);
            }
            if (includeCallees) {
                metadataInfo.put("includeCallees", true);
            }

            // Create combined result
            List<Object> resultData = new ArrayList<>();
            resultData.add(metadataInfo);
            resultData.addAll(functionData);
            return createMultiJsonResult(resultData);
        });
    }

    /**
     * Check if a function name matches the regex filters.
     */
    private boolean matchesNameRegex(Map<String, Object> funcInfo,
            Pattern namePattern, Pattern excludeNamePattern) {
        String name = (String) funcInfo.get("name");

        // If namePattern is specified, name must match
        if (namePattern != null && !namePattern.matcher(name).find()) {
            return false;
        }

        // If excludeNamePattern is specified, name must NOT match
        if (excludeNamePattern != null && excludeNamePattern.matcher(name).find()) {
            return false;
        }

        return true;
    }

    /**
     * Check if a function matches tag filter criteria.
     */
    private boolean matchesTagFilters(Map<String, Object> funcInfo,
            List<String> filterByTags, List<String> excludeTags, boolean untagged) {
        @SuppressWarnings("unchecked")
        List<String> tags = (List<String>) funcInfo.get("tags");
        boolean hasTags = tags != null && !tags.isEmpty();

        // Untagged filter: must have no tags
        if (untagged) {
            return !hasTags;
        }

        // filterByTags: must have ANY of the specified tags (OR logic)
        if (filterByTags != null && !filterByTags.isEmpty()) {
            if (!hasTags) return false;
            boolean hasAny = filterByTags.stream().anyMatch(tags::contains);
            if (!hasAny) return false;
        }

        // excludeTags: must NOT have ANY of the specified tags
        if (excludeTags != null && !excludeTags.isEmpty()) {
            if (hasTags) {
                boolean hasExcluded = excludeTags.stream().anyMatch(tags::contains);
                if (hasExcluded) return false;
            }
        }

        return true;
    }

    /**
     * Check if a function matches count range filter criteria.
     */
    private boolean matchesCountFilters(Map<String, Object> funcInfo,
            Integer minCalleeCount, Integer maxCalleeCount,
            Integer minCallerCount, Integer maxCallerCount) {
        int calleeCount = (int) funcInfo.get("calleeCount");
        int callerCount = (int) funcInfo.get("callerCount");

        if (minCalleeCount != null && calleeCount < minCalleeCount) return false;
        if (maxCalleeCount != null && calleeCount > maxCalleeCount) return false;
        if (minCallerCount != null && callerCount < minCallerCount) return false;
        if (maxCallerCount != null && callerCount > maxCallerCount) return false;

        return true;
    }

    /**
     * Check if a function's callees all meet the tag requirements.
     */
    private boolean matchesDependencyFilter(Program program, Map<String, Object> funcInfo,
            List<String> requireCalleesTagged, boolean allowExternalCallees,
            boolean allowUntaggedCallees, Map<Address, Set<String>> tagLookup) {

        String addressStr = (String) funcInfo.get("address");
        Address funcAddr = program.getAddressFactory().getAddress(addressStr);
        if (funcAddr == null) return false;

        Function function = program.getFunctionManager().getFunctionAt(funcAddr);
        if (function == null) return false;

        Set<Address> calleeAddresses = getCalleeAddresses(program, function);

        // If no callees, the function trivially passes (all zero callees have the required tags)
        if (calleeAddresses.isEmpty()) {
            return true;
        }

        FunctionManager funcMgr = program.getFunctionManager();

        for (Address calleeAddr : calleeAddresses) {
            Function callee = funcMgr.getFunctionAt(calleeAddr);

            // Handle external/thunk callees
            if (callee != null && (callee.isExternal() || callee.isThunk())) {
                if (!allowExternalCallees) {
                    return false;
                }
                continue; // External/thunk are exempt from tag requirement
            }

            // Get callee's tags
            Set<String> calleeTags = tagLookup.getOrDefault(calleeAddr, Set.of());

            // Handle untagged callees
            if (calleeTags.isEmpty()) {
                if (allowUntaggedCallees) {
                    continue; // Untagged callees exempt
                }
                return false; // Callee has no tags and allowUntaggedCallees is false
            }

            // Check if callee has ALL required tags
            if (!calleeTags.containsAll(requireCalleesTagged)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Sort functions by the specified field.
     */
    private List<Map<String, Object>> sortFunctions(List<Map<String, Object>> functions,
            String sortBy, String sortOrder) {
        Comparator<Map<String, Object>> comparator = switch (sortBy) {
            case "calleeCount" -> Comparator.comparingInt(f -> (int) f.get("calleeCount"));
            case "callerCount" -> Comparator.comparingInt(f -> (int) f.get("callerCount"));
            case "sizeInBytes" -> Comparator.comparingLong(f -> ((Number) f.get("sizeInBytes")).longValue());
            case "name" -> Comparator.comparing(f -> (String) f.get("name"), String.CASE_INSENSITIVE_ORDER);
            case "address" -> Comparator.comparing(f -> (String) f.get("address"));
            default -> null;
        };

        if (comparator == null) {
            return functions; // Unknown sort field, return unchanged
        }

        if ("descending".equalsIgnoreCase(sortOrder)) {
            comparator = comparator.reversed();
        }

        return functions.stream().sorted(comparator).toList();
    }

    /**
     * Build a lookup map of function address -> tag names for efficient dependency checking.
     */
    private Map<Address, Set<String>> buildFunctionTagLookup(Program program) {
        Map<Address, Set<String>> lookup = new HashMap<>();
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);

        while (functions.hasNext()) {
            Function func = functions.next();
            Set<FunctionTag> tags = func.getTags();
            if (!tags.isEmpty()) {
                Set<String> tagNames = new HashSet<>();
                for (FunctionTag tag : tags) {
                    tagNames.add(tag.getName());
                }
                lookup.put(func.getEntryPoint(), tagNames);
            }
        }

        return lookup;
    }

    /**
     * Get the addresses of all functions called by this function.
     * Uses instruction scanning to catch indirect calls.
     */
    private Set<Address> getCalleeAddresses(Program program, Function function) {
        Set<Address> callees = new HashSet<>();
        AddressSetView body = function.getBody();
        if (body == null) {
            return callees;
        }

        var instructions = program.getListing().getInstructions(body, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            if (instr.getFlowType().isCall()) {
                Address[] flows = instr.getFlows();
                for (Address target : flows) {
                    if (target != null) {
                        callees.add(target);
                    }
                }
            }
        }

        return callees;
    }

    /**
     * Get detailed information about a function's callees.
     */
    private List<Map<String, Object>> getCalleeDetails(Program program, Function function) {
        List<Map<String, Object>> calleeList = new ArrayList<>();
        Set<Address> calleeAddresses = getCalleeAddresses(program, function);
        FunctionManager funcMgr = program.getFunctionManager();

        for (Address calleeAddr : calleeAddresses) {
            Map<String, Object> calleeInfo = new HashMap<>();
            calleeInfo.put("address", AddressUtil.formatAddress(calleeAddr));

            Function callee = funcMgr.getFunctionAt(calleeAddr);
            if (callee != null) {
                calleeInfo.put("name", callee.getName());
                calleeInfo.put("isExternal", callee.isExternal());
                calleeInfo.put("isThunk", callee.isThunk());

                // Include tags
                Set<FunctionTag> tags = callee.getTags();
                List<String> tagNames = tags.stream()
                    .map(FunctionTag::getName)
                    .sorted()
                    .toList();
                calleeInfo.put("tags", tagNames);
            } else {
                calleeInfo.put("name", null);
                calleeInfo.put("isExternal", false);
                calleeInfo.put("isThunk", false);
                calleeInfo.put("tags", List.of());
            }

            calleeList.add(calleeInfo);
        }

        // Sort by address for consistent output
        calleeList.sort(Comparator.comparing(c -> (String) c.get("address")));

        return calleeList;
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

        properties.put("include", IncludeFilterUtil.getIncludePropertyDefinition());

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
            "description", "Return full function details (signature, parameters, etc.). When false (default), returns compact results (name, address, sizeInBytes, tags, callerCount, calleeCount, similarity).",
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
            String include = IncludeFilterUtil.validate(getOptionalString(request, "include", null));
            boolean verbose = getOptionalBoolean(request, "verbose", false);
            String programPath = program.getDomainFile().getPathname();

            if (searchString.trim().isEmpty()) {
                return createErrorResult("Search string cannot be empty");
            }

            logInfo("get-functions-by-similarity: Searching for '" + searchString + "' in " + program.getName() + " (include=" + include + ")");

            // Check similarity cache for existing sorted results (thread-safe read)
            SimilarityCacheKey cacheKey = new SimilarityCacheKey(programPath, searchString, include);
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
                // Get ALL function info FIRST (outside similarityCache lock) to avoid holding
                // the lock during expensive cache-building operations
                List<Map<String, Object>> allFunctions = getOrBuildFunctionInfoCache(program);

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

                        // Apply include filter first
                        final String includeFilter = include;
                        List<Map<String, Object>> filteredFunctions = allFunctions.stream()
                            .filter(f -> shouldIncludeFunctionInfo(f, includeFilter))
                            .toList();

                        // Pre-filter: collect functions that contain search string as substring first
                        // This dramatically reduces the number of functions to sort with expensive LCS
                        String searchLower = searchString.toLowerCase();
                        List<Map<String, Object>> substringMatches = new ArrayList<>();
                        List<Map<String, Object>> nonMatches = new ArrayList<>();

                        for (Map<String, Object> functionInfo : filteredFunctions) {
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
            // Note: callerCount/calleeCount are already in cache (computed fast during cache build)
            String searchLower = searchString.toLowerCase();
            List<Map<String, Object>> transformedResults = new ArrayList<>(paginatedFunctionData.size());
            for (Map<String, Object> funcInfo : paginatedFunctionData) {
                String name = (String) funcInfo.get("name");
                double similarity = SimilarityComparator.calculateLcsSimilarity(searchLower, name.toLowerCase());

                if (verbose) {
                    // Full: all cached function info + similarity
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
                    compactInfo.put("similarity", Math.round(similarity * 100.0) / 100.0);
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
            paginationInfo.put("include", include);
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
     * Create a map of function information (with caller/callee counts).
     * Use createFunctionInfoFast for cache building to skip expensive caller/callee computation.
     *
     * @param function The function to extract information from
     * @param monitor TaskMonitor for cancellation support (can be null for quick operations)
     * @return Immutable map containing function properties
     */
    private Map<String, Object> createFunctionInfo(Function function, TaskMonitor monitor) {
        return createFunctionInfoInternal(function, monitor, true);
    }

    /**
     * Create a map of function information with fast caller/callee counting.
     * Uses reference counting instead of slow getCalledFunctions()/getCallingFunctions().
     * Also catches indirect/virtual calls that the slow methods miss.
     *
     * @param function The function to extract information from
     * @return Immutable map containing function properties with caller/callee counts
     */
    private Map<String, Object> createFunctionInfoFast(Function function) {
        Map<String, Object> functionInfo = createFunctionInfoInternal(function, null, false);

        // Add fast caller/callee counts using reference counting
        // This is much faster than getCalledFunctions()/getCallingFunctions() AND
        // catches indirect/virtual calls that those methods miss
        Program program = function.getProgram();

        // callerCount: count incoming call references to the function's entry point
        int callerCount = countIncomingCallReferences(program, function.getEntryPoint());

        // calleeCount: count CALL instructions in the function body (catches indirect calls)
        int calleeCount = countCallInstructions(program, function);

        // Create a mutable copy to add the counts (since createFunctionInfoInternal returns immutable)
        Map<String, Object> result = new HashMap<>(functionInfo);
        result.put("callerCount", callerCount);
        result.put("calleeCount", calleeCount);

        return Collections.unmodifiableMap(result);
    }

    /**
     * Count incoming call references to an address.
     * Much faster than getCallingFunctions() and gives accurate caller count.
     *
     * @param program The program
     * @param address The address to count references to
     * @return Number of incoming call references
     */
    private int countIncomingCallReferences(Program program, Address address) {
        int count = 0;
        ReferenceManager refMgr = program.getReferenceManager();
        ReferenceIterator refIter = refMgr.getReferencesTo(address);
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref.getReferenceType().isCall()) {
                count++;
            }
        }
        return count;
    }

    /**
     * Count CALL instructions in a function's body.
     * This catches ALL calls including indirect/virtual calls that getCalledFunctions() misses.
     *
     * @param program The program
     * @param function The function to analyze
     * @return Number of call instructions (call sites)
     */
    private int countCallInstructions(Program program, Function function) {
        int count = 0;
        AddressSetView body = function.getBody();
        if (body == null) {
            return 0;
        }

        var instructions = program.getListing().getInstructions(body, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            if (instr.getFlowType().isCall()) {
                count++;
            }
        }
        return count;
    }

    /**
     * Internal implementation for creating function info.
     *
     * @param function The function to extract information from
     * @param monitor TaskMonitor for cancellation support (can be null)
     * @param includeCallerCalleeCounts If true, compute caller/callee counts (expensive)
     * @return Immutable map containing function properties
     */
    private Map<String, Object> createFunctionInfoInternal(Function function, TaskMonitor monitor, boolean includeCallerCalleeCounts) {
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

        // Only compute caller/callee counts when requested (these are VERY slow for large programs)
        if (includeCallerCalleeCounts) {
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
        }
        // When not computing counts, callerCount/calleeCount are simply not included

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
     * Normalize a function signature to handle whitespace issues and calling conventions
     * that can cause parsing failures.
     *
     * <p>Common issues handled:</p>
     * <ul>
     *   <li>"char *funcname" fails parsing (space before * in return type) - converted to "char* funcname"</li>
     *   <li>Calling conventions like __thiscall, __cdecl, etc. are not supported by Ghidra's
     *       FunctionSignatureParser (see Ghidra Issue #8831) - stripped before parsing</li>
     * </ul>
     *
     * @param signature The original C-style function signature
     * @return Normalized signature with whitespace corrected and calling conventions stripped
     * @see <a href="https://github.com/NationalSecurityAgency/ghidra/issues/8831">Ghidra Issue #8831</a>
     */
    private String normalizeFunctionSignature(String signature) {
        if (signature == null || signature.isEmpty()) {
            return signature;
        }

        // Step 1: Handle pointer spacing
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

        // Step 2: Strip calling conventions (workaround for Ghidra Issue #8831)
        // FunctionSignatureParser doesn't recognize calling conventions in signatures
        // See: https://github.com/NationalSecurityAgency/ghidra/issues/8831

        // Match Microsoft conventions: __cdecl, __stdcall, __fastcall, __thiscall, __vectorcall, __regcall, __clrcall
        // Pattern uses \b for word boundaries to avoid matching partial words
        String conventionPattern = "\\b(__cdecl|__stdcall|__fastcall|__thiscall|__vectorcall|__regcall|__clrcall)\\b";
        normalized = normalized.replaceAll(conventionPattern, "");

        // Also match GCC attribute syntax: __attribute__((cdecl)) and similar
        String gccPattern = "__attribute__\\s*\\(\\s*\\(\\s*(cdecl|stdcall|fastcall|thiscall)\\s*\\)\\s*\\)";
        normalized = normalized.replaceAll(gccPattern, "");

        // Clean up multiple consecutive spaces that result from stripping
        normalized = normalized.replaceAll("\\s{2,}", " ").trim();

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
        properties.put("includeDecompilationPreview", Map.of(
            "type", "boolean",
            "description", "Include a decompilation preview after the prototype change. Useful to see the impact of the change immediately.",
            "default", false
        ));
        properties.put("previewLines", Map.of(
            "type", "integer",
            "description", "Number of lines to include in decompilation preview (default: 20). Only used when includeDecompilationPreview is true.",
            "default", 20
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
                boolean includeDecompilationPreview = getOptionalBoolean(request, "includeDecompilationPreview", false);
                int previewLines = getOptionalInt(request, "previewLines", 20);

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

                    // Add decompilation preview if requested
                    // CRITICAL: Must create NEW decompiler AFTER transaction commits
                    if (includeDecompilationPreview) {
                        DecompInterface decompiler = new DecompInterface();
                        try {
                            decompiler.toggleCCode(true);
                            decompiler.toggleSyntaxTree(false); // We only need C code
                            decompiler.setSimplificationStyle("decompile");

                            if (decompiler.openProgram(program)) {
                                DecompileResults decompResults = decompiler.decompileFunction(
                                    function, 30, TaskMonitor.DUMMY);

                                if (decompResults.decompileCompleted() &&
                                    decompResults.getDecompiledFunction() != null) {
                                    String fullDecomp = decompResults.getDecompiledFunction().getC();
                                    // Apply line limit if specified
                                    String preview = applyLineLimit(fullDecomp, previewLines);
                                    result.put("decompilationPreview", preview);
                                } else {
                                    result.put("decompilationPreviewError",
                                        "Decompilation failed: " + decompResults.getErrorMessage());
                                }
                            } else {
                                result.put("decompilationPreviewError",
                                    "Failed to initialize decompiler");
                            }
                        } finally {
                            decompiler.dispose();
                        }
                    }

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
     * Register a tool to batch update function parameter types matching a pattern.
     * Useful for applying common pattern corrections like "char*" -> "MyStruct*".
     */
    private void registerBatchSetFunctionPrototypeTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("nameRegex", Map.of(
            "type", "string",
            "description", "Regular expression pattern to match function names (e.g., 'process.*' or '.*Handler$')"
        ));
        properties.put("parameterIndex", Map.of(
            "type", "integer",
            "description", "0-based parameter index to update. Use -1 for return type."
        ));
        properties.put("oldType", Map.of(
            "type", "string",
            "description", "Only update functions where the parameter currently has this type (e.g., 'void*', 'char*'). If not specified, updates all matching functions."
        ));
        properties.put("newType", Map.of(
            "type", "string",
            "description", "The new type to set (e.g., 'MyStruct*', 'int')"
        ));
        properties.put("dryRun", Map.of(
            "type", "boolean",
            "description", "Preview changes without applying them (default: false)",
            "default", false
        ));
        properties.put("maxUpdates", Map.of(
            "type", "integer",
            "description", "Maximum number of functions to update as a safety limit (default: 50)",
            "default", 50
        ));

        List<String> required = List.of("programPath", "nameRegex", "parameterIndex", "newType");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("batch-set-function-prototype")
            .title("Batch Set Function Prototype")
            .description("Update parameter types for multiple functions matching a pattern. " +
                "Useful for applying common corrections like changing 'void*' to a specific struct type. " +
                "Use dryRun=true to preview changes before applying them.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);
                String programPath = program.getDomainFile().getPathname();
                String nameRegex = getString(request, "nameRegex");
                int parameterIndex = getInt(request, "parameterIndex");
                String oldType = getOptionalString(request, "oldType", null);
                String newType = getString(request, "newType");
                boolean dryRun = getOptionalBoolean(request, "dryRun", false);
                int maxUpdates = getOptionalInt(request, "maxUpdates", 50);

                // Compile regex pattern
                Pattern pattern;
                try {
                    pattern = Pattern.compile(nameRegex);
                } catch (PatternSyntaxException e) {
                    return createErrorResult("Invalid regex pattern: " + e.getMessage());
                }

                // Parse new data type
                ghidra.program.model.data.DataType newDataType;
                try {
                    newDataType = reva.util.DataTypeParserUtil.parseDataTypeObjectFromString(newType, "");
                    if (newDataType == null) {
                        return createErrorResult("Could not find data type: " + newType);
                    }
                } catch (Exception e) {
                    return createErrorResult("Failed to parse newType '" + newType + "': " + e.getMessage());
                }

                // Parse old data type if specified
                ghidra.program.model.data.DataType oldDataType = null;
                if (oldType != null && !oldType.isEmpty()) {
                    try {
                        oldDataType = reva.util.DataTypeParserUtil.parseDataTypeObjectFromString(oldType, "");
                        if (oldDataType == null) {
                            return createErrorResult("Could not find data type: " + oldType);
                        }
                    } catch (Exception e) {
                        return createErrorResult("Failed to parse oldType '" + oldType + "': " + e.getMessage());
                    }
                }

                // Find matching functions
                FunctionManager fm = program.getFunctionManager();
                List<Function> matchingFunctions = new ArrayList<>();
                final ghidra.program.model.data.DataType finalOldDataType = oldDataType;

                for (Function func : fm.getFunctions(true)) {
                    if (!pattern.matcher(func.getName()).matches()) {
                        continue;
                    }

                    // Check parameter exists and type matches
                    if (parameterIndex == -1) {
                        // Return type
                        if (finalOldDataType != null && !func.getReturnType().isEquivalent(finalOldDataType)) {
                            continue;
                        }
                    } else {
                        Parameter[] params = func.getParameters();
                        if (parameterIndex >= params.length) {
                            continue;
                        }
                        if (finalOldDataType != null && !params[parameterIndex].getDataType().isEquivalent(finalOldDataType)) {
                            continue;
                        }
                    }

                    matchingFunctions.add(func);
                    if (matchingFunctions.size() >= maxUpdates * 2) {
                        // Collect some extras to show total, but don't go too far
                        break;
                    }
                }

                int totalMatched = matchingFunctions.size();

                // Limit to maxUpdates
                List<Function> functionsToUpdate = matchingFunctions.subList(0,
                    Math.min(maxUpdates, matchingFunctions.size()));

                List<Map<String, Object>> updates = new ArrayList<>();
                List<Map<String, Object>> errors = new ArrayList<>();

                if (dryRun) {
                    // Preview mode - just report what would be updated
                    for (Function func : functionsToUpdate) {
                        Map<String, Object> updateInfo = new HashMap<>();
                        updateInfo.put("name", func.getName());
                        updateInfo.put("address", AddressUtil.formatAddress(func.getEntryPoint()));

                        if (parameterIndex == -1) {
                            updateInfo.put("currentType", func.getReturnType().getDisplayName());
                            updateInfo.put("field", "returnType");
                        } else {
                            Parameter param = func.getParameters()[parameterIndex];
                            updateInfo.put("currentType", param.getDataType().getDisplayName());
                            updateInfo.put("field", "parameter[" + parameterIndex + "] (" + param.getName() + ")");
                        }
                        updateInfo.put("newType", newDataType.getDisplayName());
                        updateInfo.put("wouldUpdate", true);
                        updates.add(updateInfo);
                    }
                } else {
                    // Execute mode - apply changes in a single transaction
                    int txId = program.startTransaction("Batch update function prototypes");
                    try {
                        for (Function func : functionsToUpdate) {
                            try {
                                Map<String, Object> updateInfo = new HashMap<>();
                                updateInfo.put("name", func.getName());
                                updateInfo.put("address", AddressUtil.formatAddress(func.getEntryPoint()));

                                if (parameterIndex == -1) {
                                    // Update return type
                                    String oldTypeName = func.getReturnType().getDisplayName();
                                    func.setReturnType(newDataType, SourceType.USER_DEFINED);
                                    updateInfo.put("oldType", oldTypeName);
                                    updateInfo.put("field", "returnType");
                                } else {
                                    // Update parameter type
                                    Parameter param = func.getParameters()[parameterIndex];
                                    String oldTypeName = param.getDataType().getDisplayName();
                                    param.setDataType(newDataType, SourceType.USER_DEFINED);
                                    updateInfo.put("oldType", oldTypeName);
                                    updateInfo.put("field", "parameter[" + parameterIndex + "] (" + param.getName() + ")");
                                }
                                updateInfo.put("newType", newDataType.getDisplayName());
                                updateInfo.put("success", true);
                                updates.add(updateInfo);

                            } catch (Exception e) {
                                Map<String, Object> errorInfo = new HashMap<>();
                                errorInfo.put("name", func.getName());
                                errorInfo.put("address", AddressUtil.formatAddress(func.getEntryPoint()));
                                errorInfo.put("reason", e.getMessage());
                                errors.add(errorInfo);
                            }
                        }
                        program.endTransaction(txId, true);

                        // Invalidate caches
                        invalidateFunctionCaches(programPath);

                    } catch (Exception e) {
                        program.endTransaction(txId, false);
                        return createErrorResult("Batch update failed: " + e.getMessage());
                    }
                }

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("dryRun", dryRun);
                result.put("programPath", programPath);
                result.put("pattern", nameRegex);
                result.put("parameterIndex", parameterIndex);
                result.put("newType", newDataType.getDisplayName());
                if (oldType != null) {
                    result.put("oldTypeFilter", oldType);
                }
                result.put("totalMatched", totalMatched);
                result.put("processed", updates.size());
                result.put("errorCount", errors.size());
                if (totalMatched > maxUpdates) {
                    result.put("limitReached", true);
                    result.put("note", String.format("Found %d matches but limited to %d by maxUpdates parameter",
                        totalMatched, maxUpdates));
                }
                result.put("updates", updates);
                if (!errors.isEmpty()) {
                    result.put("errors", errors);
                }

                return createJsonResult(result);

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

                // Invalidate function caches since a new function was created
                invalidateFunctionCaches(programPath);

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

    /**
     * Find a data type by name in all categories of the DataTypeManager.
     */
    private ghidra.program.model.data.DataType findDataTypeByName(
            ghidra.program.model.data.DataTypeManager dtm, String name) {
        // Direct lookup first
        ghidra.program.model.data.DataType dt = dtm.getDataType(name);
        if (dt != null) {
            return dt;
        }

        // Search all categories
        java.util.Iterator<ghidra.program.model.data.DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            ghidra.program.model.data.DataType dataType = iter.next();
            if (dataType.getName().equals(name)) {
                return dataType;
            }
        }

        return null;
    }

    /**
     * Check if a function uses a specific structure in its return type, parameters, or local variables.
     */
    private boolean matchesStructureUsageFilter(Program program, Map<String, Object> funcInfo,
            ghidra.program.model.data.DataType structure) {
        String addressStr = (String) funcInfo.get("address");
        ghidra.program.model.address.Address funcAddr = program.getAddressFactory().getAddress(addressStr);
        if (funcAddr == null) {
            return false;
        }

        ghidra.program.model.listing.Function function = program.getFunctionManager().getFunctionAt(funcAddr);
        if (function == null) {
            return false;
        }

        // Check return type
        if (function.getReturnType().isEquivalent(structure)) {
            return true;
        }

        // Check parameters
        for (ghidra.program.model.listing.Parameter param : function.getParameters()) {
            if (param.getDataType().isEquivalent(structure)) {
                return true;
            }
        }

        // Check local variables
        for (ghidra.program.model.listing.Variable var : function.getAllVariables()) {
            if (var.getDataType().isEquivalent(structure)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Apply a line limit to decompilation output.
     *
     * @param code The full decompilation code
     * @param maxLines Maximum number of lines to return
     * @return The code limited to maxLines, with a note if truncated
     */
    private String applyLineLimit(String code, int maxLines) {
        if (code == null || maxLines <= 0) {
            return code;
        }

        String[] lines = code.split("\n", -1);
        if (lines.length <= maxLines) {
            return code;
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < maxLines; i++) {
            sb.append(lines[i]);
            if (i < maxLines - 1) {
                sb.append("\n");
            }
        }
        sb.append("\n// ... (").append(lines.length - maxLines).append(" more lines)");
        return sb.toString();
    }

}
