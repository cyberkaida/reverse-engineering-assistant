package reva.tools.callgraph;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;

/**
 * Tool provider for call graph analysis operations.
 * Provides tools for analyzing function call relationships and hierarchies.
 *
 * <p>Uses Ghidra's built-in Function.getCallingFunctions() and
 * Function.getCalledFunctions() for accurate call relationship detection.</p>
 */
public class CallGraphToolProvider extends AbstractToolProvider {

    private static final int DEFAULT_MAX_DEPTH = 3;
    private static final int MAX_DEPTH_LIMIT = 10;
    /** Max nodes per direction (callers or callees) for graph view */
    private static final int MAX_NODES_PER_DIRECTION = 250;
    /** Max nodes for tree view - higher because tree allows same function in different branches */
    private static final int MAX_NODES_TREE = 500;
    private static final int DEFAULT_TIMEOUT_SECONDS = 60;

    public CallGraphToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerGetCallGraphTool();
        registerGetCallTreeTool();
        registerFindCommonCallersTool();
    }

    // ========================================================================
    // Tool Registration
    // ========================================================================

    private void registerGetCallGraphTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("functionAddress", Map.of(
            "type", "string",
            "description", "Address or name of the function to analyze"
        ));
        properties.put("depth", Map.of(
            "type", "integer",
            "description", "How many levels of callers/callees to include (default: 1, max: 10)",
            "default", 1
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-call-graph")
            .title("Get Call Graph")
            .description("Get the call graph around a function, showing both callers " +
                "(functions that call this one) and callees (functions this one calls) " +
                "up to the specified depth. Useful for understanding a function's context " +
                "in the overall program flow.")
            .inputSchema(createSchema(properties, List.of("programPath", "functionAddress")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Address address = getAddressFromArgs(request, program, "functionAddress");
            int depth = getOptionalInt(request, "depth", 1);

            depth = clampDepth(depth);

            Function function = resolveFunction(program, address);
            if (function == null) {
                return createErrorResult("No function at address: " +
                    AddressUtil.formatAddress(address));
            }

            return getCallGraph(program, function, depth);
        });
    }

    private void registerGetCallTreeTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("functionAddress", Map.of(
            "type", "string",
            "description", "Address or name of the function to analyze"
        ));
        properties.put("direction", Map.of(
            "type", "string",
            "description", "Direction to traverse: 'callers' (who calls this) or 'callees' (what this calls)",
            "enum", List.of("callers", "callees"),
            "default", "callees"
        ));
        properties.put("maxDepth", Map.of(
            "type", "integer",
            "description", "Maximum depth to traverse (default: 3, max: 10)",
            "default", DEFAULT_MAX_DEPTH
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-call-tree")
            .title("Get Call Tree")
            .description("Get a hierarchical call tree starting from a function. " +
                "Can traverse upward (callers - who calls this function) or downward " +
                "(callees - what functions this calls). Detects and marks cycles.")
            .inputSchema(createSchema(properties, List.of("programPath", "functionAddress")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Address address = getAddressFromArgs(request, program, "functionAddress");
            String direction = getOptionalString(request, "direction", "callees");
            int maxDepth = getOptionalInt(request, "maxDepth", DEFAULT_MAX_DEPTH);

            // Validate direction parameter
            if (!"callers".equalsIgnoreCase(direction) && !"callees".equalsIgnoreCase(direction)) {
                return createErrorResult("Invalid direction: '" + direction +
                    "'. Must be 'callers' or 'callees'.");
            }

            maxDepth = clampDepth(maxDepth);

            Function function = resolveFunction(program, address);
            if (function == null) {
                return createErrorResult("No function at address: " +
                    AddressUtil.formatAddress(address));
            }

            boolean traverseCallers = "callers".equalsIgnoreCase(direction);
            return getCallTree(program, function, maxDepth, traverseCallers);
        });
    }

    private void registerFindCommonCallersTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("functionAddresses", Map.of(
            "type", "array",
            "items", Map.of("type", "string"),
            "description", "List of function addresses or names to find common callers for"
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("find-common-callers")
            .title("Find Common Callers")
            .description("Find functions that call ALL of the specified target functions. " +
                "Useful for finding dispatch points, main loops, or common entry points " +
                "that orchestrate multiple related functions.")
            .inputSchema(createSchema(properties, List.of("programPath", "functionAddresses")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            List<String> addressStrings = getStringList(request.arguments(), "functionAddresses");

            if (addressStrings.isEmpty()) {
                return createErrorResult("At least one function address is required");
            }

            List<Function> targetFunctions = new ArrayList<>();
            for (String addrStr : addressStrings) {
                Address addr = AddressUtil.resolveAddressOrSymbol(program, addrStr);
                if (addr == null) {
                    return createErrorResult("Could not resolve address: " + addrStr);
                }
                Function func = resolveFunction(program, addr);
                if (func == null) {
                    return createErrorResult("No function at address: " + addrStr);
                }
                targetFunctions.add(func);
            }

            return findCommonCallers(program, targetFunctions);
        });
    }

    // ========================================================================
    // Core Analysis Methods
    // ========================================================================

    private McpSchema.CallToolResult getCallGraph(Program program, Function centerFunction, int depth) {
        TaskMonitor monitor = createTimeoutMonitor();

        // Use separate counters for each direction
        int[] callerNodeCount = {0};
        int[] calleeNodeCount = {0};

        // Build caller graph (upward) with its own visited set and counter
        Set<String> callerVisited = new HashSet<>();
        List<Map<String, Object>> callers;
        try {
            callers = buildGraphList(centerFunction, depth, callerVisited,
                callerNodeCount, true, monitor);
        } catch (CancelledException e) {
            return createErrorResult("Operation cancelled or timed out");
        }

        // Build callee graph (downward) with its own visited set and counter
        Set<String> calleeVisited = new HashSet<>();
        List<Map<String, Object>> callees;
        try {
            callees = buildGraphList(centerFunction, depth, calleeVisited,
                calleeNodeCount, false, monitor);
        } catch (CancelledException e) {
            return createErrorResult("Operation cancelled or timed out");
        }

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("centerFunction", Map.of(
            "name", centerFunction.getName(),
            "address", AddressUtil.formatAddress(centerFunction.getEntryPoint())
        ));
        result.put("depth", depth);
        result.put("callerCount", callerNodeCount[0]);
        result.put("calleeCount", calleeNodeCount[0]);
        result.put("callers", callers);
        result.put("callees", callees);

        return createJsonResult(result);
    }

    private McpSchema.CallToolResult getCallTree(Program program, Function rootFunction,
            int maxDepth, boolean traverseCallers) {

        TaskMonitor monitor = createTimeoutMonitor();
        Set<String> visited = new HashSet<>();
        int[] nodeCount = {0};

        Map<String, Object> tree;
        try {
            tree = buildTree(rootFunction, maxDepth, 0, visited,
                nodeCount, traverseCallers, monitor);
        } catch (CancelledException e) {
            return createErrorResult("Operation cancelled or timed out");
        }

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("direction", traverseCallers ? "callers" : "callees");
        result.put("maxDepth", maxDepth);
        result.put("totalNodes", nodeCount[0]);
        result.put("tree", tree);

        return createJsonResult(result);
    }

    private McpSchema.CallToolResult findCommonCallers(Program program, List<Function> targetFunctions) {
        TaskMonitor monitor = createTimeoutMonitor();
        Set<Function> commonCallers = null;

        try {
            for (Function targetFunc : targetFunctions) {
                monitor.checkCancelled();

                Set<Function> callersOfThis = targetFunc.getCallingFunctions(monitor);

                if (commonCallers == null) {
                    commonCallers = new HashSet<>(callersOfThis);
                } else {
                    commonCallers.retainAll(callersOfThis);
                }

                // Early exit if no common callers remain
                if (commonCallers.isEmpty()) {
                    break;
                }
            }
        } catch (CancelledException e) {
            return createErrorResult("Operation cancelled or timed out");
        }

        List<Map<String, Object>> callerList = new ArrayList<>();
        if (commonCallers != null) {
            for (Function caller : commonCallers) {
                Map<String, Object> callerInfo = new HashMap<>();
                callerInfo.put("name", caller.getName());
                callerInfo.put("address", AddressUtil.formatAddress(caller.getEntryPoint()));
                callerList.add(callerInfo);
            }
        }

        // Sort by address - use entry point directly for reliable comparison
        callerList.sort((a, b) -> {
            String addrStrA = (String) a.get("address");
            String addrStrB = (String) b.get("address");
            if (addrStrA == null && addrStrB == null) return 0;
            if (addrStrA == null) return 1;  // Nulls sort to end
            if (addrStrB == null) return -1;
            // Compare hex strings (both have 0x prefix from AddressUtil)
            return addrStrA.compareTo(addrStrB);
        });

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("targetFunctions", targetFunctions.stream()
            .map(f -> Map.of(
                "name", f.getName(),
                "address", AddressUtil.formatAddress(f.getEntryPoint())
            ))
            .toList());
        result.put("commonCallerCount", callerList.size());
        result.put("commonCallers", callerList);

        return createJsonResult(result);
    }

    // ========================================================================
    // Graph/Tree Building Methods
    // ========================================================================

    /**
     * Build a list of callers or callees for the graph view.
     * Uses permanent visited tracking to avoid duplicates across branches.
     */
    private List<Map<String, Object>> buildGraphList(Function function,
            int depth, Set<String> visited, int[] nodeCount, boolean getCallers,
            TaskMonitor monitor) throws CancelledException {

        if (depth <= 0 || nodeCount[0] >= MAX_NODES_PER_DIRECTION) {
            return List.of();
        }

        monitor.checkCancelled();

        List<Map<String, Object>> results = new ArrayList<>();
        Set<Function> related = getCallers
            ? function.getCallingFunctions(monitor)
            : function.getCalledFunctions(monitor);

        for (Function relatedFunc : related) {
            if (nodeCount[0] >= MAX_NODES_PER_DIRECTION) break;
            monitor.checkCancelled();

            String funcKey = getFunctionKey(relatedFunc);
            boolean isCycle = visited.contains(funcKey);

            Map<String, Object> info = new HashMap<>();
            info.put("name", relatedFunc.getName());
            info.put("address", AddressUtil.formatAddress(relatedFunc.getEntryPoint()));

            if (isCycle) {
                info.put("cyclic", true);
            } else {
                visited.add(funcKey);
                nodeCount[0]++;

                if (depth > 1) {
                    List<Map<String, Object>> nested = buildGraphList(relatedFunc,
                        depth - 1, visited, nodeCount, getCallers, monitor);
                    if (!nested.isEmpty()) {
                        info.put(getCallers ? "callers" : "callees", nested);
                    }
                }
            }

            results.add(info);
        }

        return results;
    }

    /**
     * Build a tree structure for the tree view.
     * Uses temporary visited tracking (removes after recursion) to allow
     * the same function to appear in different branches while detecting cycles.
     */
    private Map<String, Object> buildTree(Function function,
            int maxDepth, int currentDepth, Set<String> visited, int[] nodeCount,
            boolean getCallers, TaskMonitor monitor) throws CancelledException {

        monitor.checkCancelled();

        Map<String, Object> node = new HashMap<>();
        node.put("name", function.getName());
        node.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        node.put("depth", currentDepth);

        String funcKey = getFunctionKey(function);

        // Cycle detection within current path
        if (visited.contains(funcKey)) {
            node.put("cyclic", true);
            return node;
        }

        // Depth or node limit reached
        if (currentDepth >= maxDepth || nodeCount[0] >= MAX_NODES_TREE) {
            if (currentDepth >= maxDepth) {
                node.put("truncated", true);
            }
            return node;
        }

        // Mark as visited for this path
        visited.add(funcKey);
        nodeCount[0]++;

        Set<Function> related = getCallers
            ? function.getCallingFunctions(monitor)
            : function.getCalledFunctions(monitor);

        if (!related.isEmpty()) {
            List<Map<String, Object>> childNodes = new ArrayList<>();
            for (Function relatedFunc : related) {
                if (nodeCount[0] >= MAX_NODES_TREE) break;
                monitor.checkCancelled();

                childNodes.add(buildTree(relatedFunc, maxDepth,
                    currentDepth + 1, visited, nodeCount, getCallers, monitor));
            }
            node.put(getCallers ? "callers" : "callees", childNodes);
        }

        // Remove from visited to allow this function in other branches
        visited.remove(funcKey);
        return node;
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /**
     * Resolve a function at or containing the given address.
     */
    private Function resolveFunction(Program program, Address address) {
        Function function = program.getFunctionManager().getFunctionAt(address);
        if (function == null) {
            function = program.getFunctionManager().getFunctionContaining(address);
        }
        return function;
    }

    /**
     * Clamp depth to valid range.
     */
    private int clampDepth(int depth) {
        if (depth < 1) return 1;
        if (depth > MAX_DEPTH_LIMIT) return MAX_DEPTH_LIMIT;
        return depth;
    }

    /**
     * Create a unique key for a function using its entry point address.
     */
    private String getFunctionKey(Function function) {
        return AddressUtil.formatAddress(function.getEntryPoint());
    }

    /**
     * Create a timeout monitor for long-running operations.
     */
    private TaskMonitor createTimeoutMonitor() {
        return TimeoutTaskMonitor.timeoutIn(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }
}
