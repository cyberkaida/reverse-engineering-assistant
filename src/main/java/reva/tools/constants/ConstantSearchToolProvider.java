package reva.tools.constants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;

/**
 * Tool provider for searching and analyzing constant values in a program.
 * Provides tools for finding specific constants, constants in ranges,
 * and identifying commonly used constants.
 */
public class ConstantSearchToolProvider extends AbstractToolProvider {

    private static final int DEFAULT_TIMEOUT_SECONDS = 120;
    private static final int DEFAULT_MAX_RESULTS = 500;
    private static final int DEFAULT_TOP_CONSTANTS = 50;
    /** Maximum allowed value for maxResults/topN to prevent abuse */
    private static final int MAX_RESULTS_LIMIT = 10000;
    /** Safety limit on instructions to process (prevents runaway on huge binaries) */
    private static final int MAX_INSTRUCTIONS = 2_000_000;
    /** Maximum sample locations to collect per constant */
    private static final int MAX_SAMPLE_LOCATIONS = 5;

    public ConstantSearchToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerFindConstantUsesTool();
        registerFindConstantsInRangeTool();
        registerListCommonConstantsTool();
    }

    // ========================================================================
    // Tool Registration
    // ========================================================================

    private void registerFindConstantUsesTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("value", Map.of(
            "type", "string",
            "description", "The constant value to search for. Supports decimal (123), hex (0x7b), " +
                "negative (-1), or named constants. For hex, use 0x prefix."
        ));
        properties.put("maxResults", Map.of(
            "type", "integer",
            "description", "Maximum number of results to return (default: 500)",
            "default", DEFAULT_MAX_RESULTS
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("find-constant-uses")
            .title("Find Constant Uses")
            .description("Find all locations where a specific constant value is used as an " +
                "immediate operand in instructions. Useful for finding magic numbers, " +
                "error codes, buffer sizes, or other significant values.")
            .inputSchema(createSchema(properties, List.of("programPath", "value")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            String valueStr = getString(request, "value");
            int maxResults = getOptionalInt(request, "maxResults", DEFAULT_MAX_RESULTS);

            long value;
            try {
                value = parseConstantValue(valueStr);
            } catch (NumberFormatException e) {
                return createErrorResult("Invalid constant value: '" + valueStr +
                    "'. Use decimal (123), hex (0x7b), or negative (-1) format.");
            }

            return findConstantUses(program, value, maxResults);
        });
    }

    private void registerFindConstantsInRangeTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("minValue", Map.of(
            "type", "string",
            "description", "Minimum value (inclusive). Supports decimal or hex (0x) format."
        ));
        properties.put("maxValue", Map.of(
            "type", "string",
            "description", "Maximum value (inclusive). Supports decimal or hex (0x) format."
        ));
        properties.put("maxResults", Map.of(
            "type", "integer",
            "description", "Maximum number of results to return (default: 500)",
            "default", DEFAULT_MAX_RESULTS
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("find-constants-in-range")
            .title("Find Constants in Range")
            .description("Find all constant values within a specified range. Useful for finding " +
                "error codes (e.g., 400-599 for HTTP errors), enum values, or constants " +
                "that fall within expected bounds.")
            .inputSchema(createSchema(properties, List.of("programPath", "minValue", "maxValue")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            String minStr = getString(request, "minValue");
            String maxStr = getString(request, "maxValue");
            int maxResults = getOptionalInt(request, "maxResults", DEFAULT_MAX_RESULTS);

            long minValue, maxValue;
            try {
                minValue = parseConstantValue(minStr);
                maxValue = parseConstantValue(maxStr);
            } catch (NumberFormatException e) {
                return createErrorResult("Invalid value format. Use decimal (123) or hex (0x7b).");
            }

            if (minValue > maxValue) {
                return createErrorResult("minValue must be less than or equal to maxValue");
            }

            return findConstantsInRange(program, minValue, maxValue, maxResults);
        });
    }

    private void registerListCommonConstantsTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("topN", Map.of(
            "type", "integer",
            "description", "Number of most common constants to return (default: 50)",
            "default", DEFAULT_TOP_CONSTANTS
        ));
        properties.put("minValue", Map.of(
            "type", "string",
            "description", "Optional minimum value to consider (filters out small constants)"
        ));
        properties.put("includeSmallValues", Map.of(
            "type", "boolean",
            "description", "Include small values (0-255) which are often noise (default: false)",
            "default", false
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-common-constants")
            .title("List Common Constants")
            .description("Find the most frequently used constant values in the program. " +
                "Helps identify important magic numbers, sizes, flags, or other significant values. " +
                "By default filters out small values (0-255) which are often noise.")
            .inputSchema(createSchema(properties, List.of("programPath")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            int topN = getOptionalInt(request, "topN", DEFAULT_TOP_CONSTANTS);
            boolean includeSmallValues = getOptionalBoolean(request, "includeSmallValues", false);

            String minValueStr = getOptionalString(request, "minValue", null);
            Long minValue = null;  // null means no explicit minimum
            if (minValueStr != null && !minValueStr.isEmpty()) {
                try {
                    minValue = parseConstantValue(minValueStr);
                } catch (NumberFormatException e) {
                    return createErrorResult("Invalid minValue format.");
                }
            }

            return listCommonConstants(program, topN, minValue, includeSmallValues);
        });
    }

    // ========================================================================
    // Core Analysis Methods
    // ========================================================================

    private McpSchema.CallToolResult findConstantUses(Program program, long targetValue, int maxResults) {
        maxResults = clampMaxResults(maxResults);
        TaskMonitor monitor = createTimeoutMonitor();
        Listing listing = program.getListing();
        List<Map<String, Object>> results = new ArrayList<>();
        int instructionCount = 0;

        try {
            InstructionIterator instructions = listing.getInstructions(true);
            while (instructions.hasNext() && results.size() < maxResults) {
                monitor.checkCancelled();
                if (++instructionCount > MAX_INSTRUCTIONS) {
                    break;
                }
                Instruction instr = instructions.next();

                for (int i = 0; i < instr.getNumOperands(); i++) {
                    Scalar scalar = instr.getScalar(i);
                    if (scalar != null) {
                        long unsignedValue = scalar.getUnsignedValue();
                        long signedValue = scalar.getSignedValue();

                        // Check both interpretations and report the one that matched
                        if (unsignedValue == targetValue) {
                            results.add(buildInstructionResult(program, instr, i, unsignedValue));
                            break; // Only count once per instruction
                        } else if (signedValue == targetValue) {
                            results.add(buildInstructionResult(program, instr, i, signedValue));
                            break;
                        }
                    }
                }
            }
        } catch (CancelledException e) {
            return createErrorResult("Operation cancelled or timed out");
        }

        Map<String, Object> response = new HashMap<>();
        response.put("programPath", program.getDomainFile().getPathname());
        response.put("searchedValue", formatValue(targetValue));
        response.put("resultCount", results.size());
        response.put("truncated", results.size() >= maxResults);
        if (instructionCount > MAX_INSTRUCTIONS) {
            response.put("instructionLimitReached", true);
        }
        response.put("results", results);

        return createJsonResult(response);
    }

    private McpSchema.CallToolResult findConstantsInRange(Program program, long minValue,
            long maxValue, int maxResults) {

        maxResults = clampMaxResults(maxResults);
        TaskMonitor monitor = createTimeoutMonitor();
        Listing listing = program.getListing();
        List<Map<String, Object>> results = new ArrayList<>();
        Map<Long, Integer> valueFrequency = new HashMap<>();
        int instructionCount = 0;

        try {
            InstructionIterator instructions = listing.getInstructions(true);
            while (instructions.hasNext() && results.size() < maxResults) {
                monitor.checkCancelled();
                if (++instructionCount > MAX_INSTRUCTIONS) {
                    break;
                }
                Instruction instr = instructions.next();

                for (int i = 0; i < instr.getNumOperands(); i++) {
                    Scalar scalar = instr.getScalar(i);
                    if (scalar != null) {
                        long unsignedValue = scalar.getUnsignedValue();
                        long signedValue = scalar.getSignedValue();

                        // Check signed interpretation first (most common use case for ranges)
                        // then unsigned with proper unsigned comparison for large values.
                        Long matchedValue = null;
                        if (signedValue >= minValue && signedValue <= maxValue) {
                            matchedValue = signedValue;
                        } else if (Long.compareUnsigned(unsignedValue, minValue) >= 0
                                && Long.compareUnsigned(unsignedValue, maxValue) <= 0) {
                            matchedValue = unsignedValue;
                        }

                        if (matchedValue != null) {
                            results.add(buildInstructionResult(program, instr, i, matchedValue));
                            valueFrequency.put(matchedValue,
                                valueFrequency.getOrDefault(matchedValue, 0) + 1);
                            break; // Only count once per instruction
                        }
                    }
                }
            }
        } catch (CancelledException e) {
            return createErrorResult("Operation cancelled or timed out");
        }

        // Get unique values sorted by frequency
        List<Map<String, Object>> uniqueValues = valueFrequency.entrySet().stream()
            .sorted((a, b) -> b.getValue().compareTo(a.getValue()))
            .map(e -> {
                Map<String, Object> m = new HashMap<>();
                m.put("value", formatValue(e.getKey()));
                m.put("decimal", e.getKey());
                m.put("occurrences", e.getValue());
                return m;
            })
            .collect(Collectors.toList());

        Map<String, Object> response = new HashMap<>();
        response.put("programPath", program.getDomainFile().getPathname());
        response.put("range", Map.of(
            "min", formatValue(minValue),
            "max", formatValue(maxValue)
        ));
        response.put("uniqueValuesFound", uniqueValues.size());
        response.put("totalOccurrences", results.size());
        response.put("truncated", results.size() >= maxResults);
        if (instructionCount > MAX_INSTRUCTIONS) {
            response.put("instructionLimitReached", true);
        }
        response.put("uniqueValues", uniqueValues);
        response.put("results", results);

        return createJsonResult(response);
    }

    private McpSchema.CallToolResult listCommonConstants(Program program, int topN,
            Long minValue, boolean includeSmallValues) {

        topN = clampMaxResults(topN);
        TaskMonitor monitor = createTimeoutMonitor();
        Listing listing = program.getListing();
        Map<Long, ConstantInfo> constantMap = new HashMap<>();
        int instructionCount = 0;

        try {
            InstructionIterator instructions = listing.getInstructions(true);
            while (instructions.hasNext()) {
                monitor.checkCancelled();
                if (++instructionCount > MAX_INSTRUCTIONS) {
                    break;
                }
                Instruction instr = instructions.next();

                for (int i = 0; i < instr.getNumOperands(); i++) {
                    Scalar scalar = instr.getScalar(i);
                    if (scalar != null) {
                        long unsignedValue = scalar.getUnsignedValue();
                        long signedValue = scalar.getSignedValue();

                        // Apply noise filter (checks both representations)
                        if (!includeSmallValues && isNoiseValue(unsignedValue, signedValue)) {
                            continue;
                        }

                        // Apply explicit minValue filter if provided
                        // Skip only if BOTH representations are below minValue
                        // Use unsigned comparison for unsigned value to handle large values correctly
                        if (minValue != null
                                && Long.compareUnsigned(unsignedValue, minValue) < 0
                                && signedValue < minValue) {
                            continue;
                        }

                        // Use unsigned value for tracking (consistent with other tools)
                        ConstantInfo info = constantMap.computeIfAbsent(unsignedValue,
                            k -> new ConstantInfo(unsignedValue));
                        info.addOccurrence(instr.getAddress(), program);
                    }
                }
            }
        } catch (CancelledException e) {
            return createErrorResult("Operation cancelled or timed out");
        }

        // Sort by frequency and take top N
        List<Map<String, Object>> topConstants = constantMap.values().stream()
            .sorted((a, b) -> Integer.compare(b.count, a.count))
            .limit(topN)
            .map(info -> {
                Map<String, Object> m = new HashMap<>();
                m.put("value", formatValue(info.value));
                m.put("decimal", info.value);
                m.put("occurrences", info.count);
                m.put("uniqueFunctions", info.functions.size());
                // Only include description if we have one
                String description = describeConstant(info.value);
                if (description != null) {
                    m.put("description", description);
                }
                m.put("sampleLocations", new ArrayList<>(info.locations));
                return m;
            })
            .collect(Collectors.toList());

        Map<String, Object> response = new HashMap<>();
        response.put("programPath", program.getDomainFile().getPathname());
        response.put("totalUniqueConstants", constantMap.size());
        response.put("returned", topConstants.size());
        String filterDesc = buildFilterDescription(includeSmallValues, minValue);
        response.put("filterApplied", filterDesc);
        if (instructionCount > MAX_INSTRUCTIONS) {
            response.put("instructionLimitReached", true);
        }
        response.put("constants", topConstants);

        return createJsonResult(response);
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    private Map<String, Object> buildInstructionResult(Program program, Instruction instr,
            int operandIndex, long value) {

        Map<String, Object> result = new HashMap<>();
        Address addr = instr.getAddress();
        result.put("address", AddressUtil.formatAddress(addr));
        result.put("mnemonic", instr.getMnemonicString());
        result.put("operandIndex", operandIndex);
        result.put("instruction", instr.toString());
        result.put("value", formatValue(value));

        // Add function context if available
        Function func = program.getFunctionManager().getFunctionContaining(addr);
        if (func != null) {
            result.put("function", func.getName());
            result.put("functionAddress", AddressUtil.formatAddress(func.getEntryPoint()));
        }

        return result;
    }

    private long parseConstantValue(String valueStr) throws NumberFormatException {
        valueStr = valueStr.trim();

        // Handle hex
        if (valueStr.toLowerCase().startsWith("0x")) {
            return Long.parseUnsignedLong(valueStr.substring(2), 16);
        }

        // Handle negative numbers
        if (valueStr.startsWith("-")) {
            return Long.parseLong(valueStr);
        }

        // Handle decimal
        return Long.parseUnsignedLong(valueStr);
    }

    /**
     * Format a constant value for display, showing both hex and decimal.
     * Always includes both representations for values != 0 for consistency.
     */
    private String formatValue(long value) {
        if (value == 0) {
            return "0";
        }
        return String.format("0x%x (%d)", value, value);
    }

    /**
     * Clamp maxResults/topN to valid bounds.
     */
    private int clampMaxResults(int value) {
        if (value <= 0) {
            return DEFAULT_MAX_RESULTS;
        }
        return Math.min(value, MAX_RESULTS_LIMIT);
    }

    /**
     * Check if a value is noise (small values 0-255 or -1).
     * Uses proper unsigned comparison for the small value check.
     */
    private boolean isNoiseValue(long unsignedValue, long signedValue) {
        // Small unsigned values (0-255) are usually noise
        // Use Long.compareUnsigned for correct unsigned comparison
        if (Long.compareUnsigned(unsignedValue, 255) <= 0) {
            return true;
        }
        // -1 in any representation (covers 32-bit and 64-bit -1)
        if (signedValue == -1) {
            return true;
        }
        return false;
    }

    private String buildFilterDescription(boolean includeSmallValues, Long minValue) {
        List<String> filters = new ArrayList<>();
        if (!includeSmallValues) {
            filters.add("excluded noise values (0-255, -1)");
        }
        if (minValue != null) {
            filters.add("min value " + formatValue(minValue));
        }
        return filters.isEmpty() ? "none" : String.join(", ", filters);
    }

    /**
     * Provide helpful descriptions for well-known constants.
     * Returns null if no known description applies.
     *
     * Note: Specific descriptions (like "1 KB") are checked before generic
     * ones (like "power of 2") to provide the most useful information.
     */
    private String describeConstant(long value) {
        // Common sizes - check these FIRST for more specific descriptions
        if (value == 1024) return "1 KB";
        if (value == 4096) return "4 KB (page size)";
        if (value == 8192) return "8 KB";
        if (value == 65536) return "64 KB";
        if (value == 0x100000) return "1 MB";
        if (value == 0x400000) return "4 MB";

        // Bit masks and limits - check before generic power-of-2
        if (value == 0x7fffffff) return "INT32_MAX";
        if (value == 0x80000000L) return "INT32_MIN / sign bit";
        if (value == 0x7fffffffffffffffL) return "INT64_MAX";
        if (value == 0x8000000000000000L) return "INT64_MIN / sign bit";
        if (value == 0xffff) return "16-bit mask";
        if (value == 0xffffff) return "24-bit mask";
        if (value == 0xffffffffL) return "32-bit mask / -1";

        // Generic powers of 2 (after specific sizes checked above)
        // numberOfTrailingZeros returns 0-63 for any non-zero long, so no bounds check needed
        if (value > 0 && (value & (value - 1)) == 0) {
            int power = Long.numberOfTrailingZeros(value);
            return "2^" + power + " (power of 2)";
        }

        // HTTP status codes (100-599 covers informational, success, redirect, client error, server error)
        if (value >= 100 && value < 600) return "Possible HTTP status code";

        // Windows error codes
        if (value >= 0x80000000L && value <= 0x8000ffffL) return "Possible HRESULT/NTSTATUS";

        // Magic numbers / file signatures
        if (value == 0x5a4d) return "MZ header";
        if (value == 0x4550) return "PE signature";
        if (value == 0x464c457f) return "ELF magic";
        if (value == 0xdeadbeefL) return "Debug marker";
        if (value == 0xcafebabe) return "Java class / Mach-O FAT";
        if (value == 0xfeedfaceL) return "Mach-O 32-bit";
        if (value == 0xfeedfacfL) return "Mach-O 64-bit";

        return null;
    }

    private TaskMonitor createTimeoutMonitor() {
        return TimeoutTaskMonitor.timeoutIn(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    // ========================================================================
    // Helper Classes
    // ========================================================================

    /**
     * Tracks occurrences and statistics for a single constant value.
     */
    private static class ConstantInfo {
        final long value;
        int count = 0;
        final List<String> locations = new ArrayList<>();
        final Set<String> functions = new HashSet<>();

        ConstantInfo(long value) {
            this.value = value;
        }

        void addOccurrence(Address addr, Program program) {
            count++;
            // Collect sample locations up to the limit
            if (locations.size() < MAX_SAMPLE_LOCATIONS) {
                locations.add(AddressUtil.formatAddress(addr));
            }
            Function func = program.getFunctionManager().getFunctionContaining(addr);
            if (func != null) {
                functions.add(func.getName());
            }
        }
    }
}
