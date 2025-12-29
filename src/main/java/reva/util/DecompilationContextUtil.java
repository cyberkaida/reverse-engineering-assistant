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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import java.util.concurrent.TimeUnit;
import reva.plugin.ConfigManager;

/**
 * Utility class for working with decompilation context and cross references.
 * Provides methods to map addresses to decompilation line numbers and extract
 * code context around specific lines.
 */
public class DecompilationContextUtil {

    /** Default timeout in seconds when ConfigManager is not available */
    private static final int DEFAULT_TIMEOUT_SECONDS = 10;

    /**
     * Result class containing both line number and context from a single decompilation.
     */
    public static class LineNumberAndContext {
        public final int lineNumber;
        public final String context;
        public final String[] allLines;
        public final List<ClangLine> clangLines;

        public LineNumberAndContext(int lineNumber, String context, String[] allLines, List<ClangLine> clangLines) {
            this.lineNumber = lineNumber;
            this.context = context;
            this.allLines = allLines;
            this.clangLines = clangLines;
        }

        public static LineNumberAndContext failure() {
            return new LineNumberAndContext(-1, null, null, null);
        }

        public boolean isValid() {
            return lineNumber > 0;
        }
    }

    /**
     * Cached decompilation result for a function.
     */
    private static class CachedDecompilation {
        final String[] lines;
        final List<ClangLine> clangLines;
        final long timestamp;

        CachedDecompilation(String[] lines, List<ClangLine> clangLines) {
            this.lines = lines;
            this.clangLines = clangLines;
            this.timestamp = System.currentTimeMillis();
        }

        boolean isExpired() {
            // Cache expires after 30 seconds
            return System.currentTimeMillis() - timestamp > 30000;
        }
    }

    /** Short-lived cache for decompilation results within a single operation */
    private static final Map<String, CachedDecompilation> decompilationCache = new ConcurrentHashMap<>();

    /**
     * Get the configured timeout in seconds, with fallback if ConfigManager is unavailable.
     */
    private static int getTimeoutSeconds() {
        try {
            ConfigManager config = RevaInternalServiceRegistry.getService(ConfigManager.class);
            if (config != null) {
                return config.getDecompilerTimeoutSeconds();
            }
        } catch (Exception e) {
            // Fall through to default
        }
        return DEFAULT_TIMEOUT_SECONDS;
    }

    /**
     * Clear expired entries from the decompilation cache.
     */
    private static void cleanCache() {
        decompilationCache.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }

    /**
     * Generate a cache key for a function.
     */
    private static String getCacheKey(Program program, Function function) {
        return program.getDomainFile().getPathname() + ":" + AddressUtil.formatAddress(function.getEntryPoint());
    }

    /**
     * Get line number AND context for an address in a single decompilation.
     * This is more efficient than calling getLineNumberForAddress and getDecompilationContext separately.
     *
     * @param program The Ghidra program
     * @param function The function containing the address
     * @param address The address to find the line number for
     * @param contextLines Number of lines to include before and after (0 for no context)
     * @return LineNumberAndContext with both pieces of information
     */
    public static LineNumberAndContext getLineNumberAndContext(Program program, Function function,
            Address address, int contextLines) {
        if (program == null || function == null || address == null) {
            return LineNumberAndContext.failure();
        }

        String cacheKey = getCacheKey(program, function);
        CachedDecompilation cached = decompilationCache.get(cacheKey);

        String[] lines;
        List<ClangLine> clangLines;

        if (cached != null && !cached.isExpired()) {
            // Use cached decompilation
            lines = cached.lines;
            clangLines = cached.clangLines;
        } else {
            // Need to decompile
            DecompInterface decompiler = new DecompInterface();
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            decompiler.setSimplificationStyle("decompile");

            if (!decompiler.openProgram(program)) {
                decompiler.dispose(); // Fix memory leak
                return LineNumberAndContext.failure();
            }

            try {
                int timeoutSeconds = getTimeoutSeconds();
                TaskMonitor timeoutMonitor = TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
                DecompileResults decompileResults = decompiler.decompileFunction(function, 0, timeoutMonitor);

                if (timeoutMonitor.isCancelled()) {
                    DebugLogger.debug(DecompilationContextUtil.class,
                        "Decompilation timed out for " + function.getName() + " after " + timeoutSeconds + " seconds");
                    return LineNumberAndContext.failure();
                }
                if (!decompileResults.decompileCompleted()) {
                    return LineNumberAndContext.failure();
                }

                // Get the decompiled code
                DecompiledFunction decompiledFunction = decompileResults.getDecompiledFunction();
                String decompCode = decompiledFunction.getC();
                lines = decompCode.split("\n");

                // Get the markup for line mapping
                ClangTokenGroup markup = decompileResults.getCCodeMarkup();
                clangLines = DecompilerUtils.toLines(markup);

                // Cache the results
                decompilationCache.put(cacheKey, new CachedDecompilation(lines, clangLines));
            } catch (Exception e) {
                Msg.error(DecompilationContextUtil.class, "Error decompiling " + function.getName(), e);
                return LineNumberAndContext.failure();
            } finally {
                decompiler.dispose();
            }
        }

        // Find the line containing this address
        int lineNumber = -1;
        for (ClangLine clangLine : clangLines) {
            List<ClangToken> tokens = clangLine.getAllTokens();
            for (ClangToken token : tokens) {
                Address tokenAddr = token.getMinAddress();
                if (tokenAddr != null && tokenAddr.equals(address)) {
                    lineNumber = clangLine.getLineNumber();
                    break;
                }
            }
            if (lineNumber > 0) break;

            // If no exact match, check if address is within the range of this line
            if (!tokens.isEmpty()) {
                Address closestAddr = DecompilerUtils.getClosestAddress(program, tokens.get(0));
                if (closestAddr != null && closestAddr.equals(address)) {
                    lineNumber = clangLine.getLineNumber();
                    break;
                }
            }
        }

        if (lineNumber <= 0) {
            return LineNumberAndContext.failure();
        }

        // Build context if requested
        String context = null;
        if (contextLines > 0 && lines != null) {
            int startLine = Math.max(0, lineNumber - 1 - contextLines);
            int endLine = Math.min(lines.length - 1, lineNumber - 1 + contextLines);

            StringBuilder contextBuilder = new StringBuilder();
            for (int i = startLine; i <= endLine; i++) {
                if (i > startLine) {
                    contextBuilder.append("\n");
                }
                contextBuilder.append(lines[i]);
            }
            context = contextBuilder.toString();
        }

        return new LineNumberAndContext(lineNumber, context, lines, clangLines);
    }

    /**
     * Get the decompilation line number for a specific address within a function.
     *
     * @param program The Ghidra program
     * @param function The function containing the address
     * @param address The address to find the line number for
     * @return The line number (1-based) or -1 if not found
     */
    public static int getLineNumberForAddress(Program program, Function function, Address address) {
        return getLineNumberAndContext(program, function, address, 0).lineNumber;
    }

    /**
     * Get a context snippet around a specific line in a function's decompilation.
     *
     * @param program The Ghidra program
     * @param function The function to decompile
     * @param lineNumber The target line number (1-based)
     * @param contextLines Number of lines to include before and after the target line
     * @return A string containing the context lines separated by newlines, or null if error
     */
    public static String getDecompilationContext(Program program, Function function, int lineNumber, int contextLines) {
        if (program == null || function == null || lineNumber <= 0 || contextLines < 0) {
            return null;
        }

        String cacheKey = getCacheKey(program, function);
        CachedDecompilation cached = decompilationCache.get(cacheKey);

        String[] lines;

        if (cached != null && !cached.isExpired()) {
            lines = cached.lines;
        } else {
            // Need to decompile
            DecompInterface decompiler = new DecompInterface();
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            decompiler.setSimplificationStyle("decompile");

            if (!decompiler.openProgram(program)) {
                decompiler.dispose(); // Fix memory leak
                return null;
            }

            try {
                int timeoutSeconds = getTimeoutSeconds();
                TaskMonitor timeoutMonitor = TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
                DecompileResults decompileResults = decompiler.decompileFunction(function, 0, timeoutMonitor);

                if (timeoutMonitor.isCancelled()) {
                    DebugLogger.debug(DecompilationContextUtil.class,
                        "Decompilation timed out while getting context after " + timeoutSeconds + " seconds");
                    return null;
                }
                if (!decompileResults.decompileCompleted()) {
                    return null;
                }

                DecompiledFunction decompiledFunction = decompileResults.getDecompiledFunction();
                String decompCode = decompiledFunction.getC();
                lines = decompCode.split("\n");

                // Cache for potential reuse
                ClangTokenGroup markup = decompileResults.getCCodeMarkup();
                List<ClangLine> clangLines = DecompilerUtils.toLines(markup);
                decompilationCache.put(cacheKey, new CachedDecompilation(lines, clangLines));
            } catch (Exception e) {
                Msg.error(DecompilationContextUtil.class, "Error getting decompilation context", e);
                return null;
            } finally {
                decompiler.dispose();
            }
        }

        // Calculate range
        int startLine = Math.max(0, lineNumber - 1 - contextLines);
        int endLine = Math.min(lines.length - 1, lineNumber - 1 + contextLines);

        // Build context string
        StringBuilder context = new StringBuilder();
        for (int i = startLine; i <= endLine; i++) {
            if (i > startLine) {
                context.append("\n");
            }
            context.append(lines[i]);
        }

        return context.toString();
    }

    /**
     * Get enhanced incoming reference information for a function with line numbers and optional context.
     *
     * @param program The Ghidra program
     * @param targetFunction The function to get incoming references for
     * @param includeContext Whether to include code context snippets
     * @return List of enhanced reference maps
     */
    public static List<Map<String, Object>> getEnhancedIncomingReferences(Program program, Function targetFunction, boolean includeContext) {
        // Default to no limit for backwards compatibility
        return getEnhancedIncomingReferences(program, targetFunction, includeContext, -1);
    }

    /**
     * Get enhanced incoming reference information for a function with line numbers and optional context.
     * This overload allows limiting the number of references to prevent performance issues.
     *
     * OPTIMIZED: Uses caching to decompile each calling function only once, even when
     * multiple references come from the same function.
     *
     * @param program The Ghidra program
     * @param targetFunction The function to get incoming references for
     * @param includeContext Whether to include code context snippets
     * @param maxRefs Maximum number of references to return (-1 for no limit)
     * @return List of enhanced reference maps
     */
    public static List<Map<String, Object>> getEnhancedIncomingReferences(Program program, Function targetFunction, boolean includeContext, int maxRefs) {
        List<Map<String, Object>> enhancedRefs = new ArrayList<>();

        if (program == null || targetFunction == null) {
            return enhancedRefs;
        }

        // Clean expired cache entries at the start
        cleanCache();

        try {
            // Get references to this function's entry point
            ReferenceIterator incomingRefs = program.getReferenceManager().getReferencesTo(targetFunction.getEntryPoint());

            // Count total references first for logging (quick iteration)
            int totalRefs = 0;
            var countIterator = program.getReferenceManager().getReferencesTo(targetFunction.getEntryPoint());
            while (countIterator.hasNext()) {
                countIterator.next();
                totalRefs++;
            }

            DebugLogger.debug(DecompilationContextUtil.class,
                String.format("getEnhancedIncomingReferences: Function '%s' has %d total references, processing up to %d with context=%s",
                    targetFunction.getName(), totalRefs, maxRefs > 0 ? maxRefs : totalRefs, includeContext));

            int processed = 0;

            while (incomingRefs.hasNext()) {
                // Stop early if we've reached the limit
                if (maxRefs > 0 && enhancedRefs.size() >= maxRefs) {
                    DebugLogger.debug(DecompilationContextUtil.class,
                        String.format("getEnhancedIncomingReferences: Reached limit of %d references, stopping early", maxRefs));
                    break;
                }

                Reference ref = incomingRefs.next();
                Address fromAddress = ref.getFromAddress();
                Function fromFunction = program.getFunctionManager().getFunctionContaining(fromAddress);
                processed++;

                Map<String, Object> refInfo = new HashMap<>();
                refInfo.put("fromAddress", AddressUtil.formatAddress(fromAddress));
                refInfo.put("referenceType", ref.getReferenceType().toString());

                // Add symbol name if available
                if (fromAddress != null) {
                    Symbol fromSymbol = program.getSymbolTable().getPrimarySymbol(fromAddress);
                    if (fromSymbol != null) {
                        refInfo.put("fromSymbol", fromSymbol.getName());
                        refInfo.put("fromSymbolType", fromSymbol.getSymbolType().toString());
                    }
                }

                if (fromFunction != null) {
                    refInfo.put("fromFunction", fromFunction.getName());

                    // Use the combined method to get both line number and context in ONE decompilation
                    int contextLines = includeContext ? 1 : 0;
                    LineNumberAndContext result = getLineNumberAndContext(program, fromFunction, fromAddress, contextLines);

                    if (result.isValid()) {
                        refInfo.put("fromLine", result.lineNumber);
                        if (includeContext && result.context != null) {
                            refInfo.put("context", result.context);
                        }
                    }
                }

                enhancedRefs.add(refInfo);
            }

            DebugLogger.debug(DecompilationContextUtil.class,
                String.format("getEnhancedIncomingReferences: Completed - processed %d references, returning %d results",
                    processed, enhancedRefs.size()));

        } catch (Exception e) {
            Msg.error(DecompilationContextUtil.class, "Error getting enhanced incoming references", e);
        }

        return enhancedRefs;
    }

    /**
     * Get enhanced reference information for any address with line numbers and optional context.
     * This method can be used by cross reference tools to add decompilation context.
     *
     * @param program The Ghidra program
     * @param targetAddress The address to get references to
     * @param includeContext Whether to include code context snippets
     * @return List of enhanced reference maps
     */
    public static List<Map<String, Object>> getEnhancedReferencesTo(Program program, Address targetAddress, boolean includeContext) {
        List<Map<String, Object>> enhancedRefs = new ArrayList<>();

        if (program == null || targetAddress == null) {
            return enhancedRefs;
        }

        // Clean expired cache entries
        cleanCache();

        try {
            // Get references to this address
            ReferenceIterator refs = program.getReferenceManager().getReferencesTo(targetAddress);

            while (refs.hasNext()) {
                Reference ref = refs.next();
                Address fromAddress = ref.getFromAddress();
                Function fromFunction = program.getFunctionManager().getFunctionContaining(fromAddress);

                Map<String, Object> refInfo = new HashMap<>();
                refInfo.put("fromAddress", AddressUtil.formatAddress(fromAddress));
                refInfo.put("toAddress", AddressUtil.formatAddress(ref.getToAddress()));
                refInfo.put("referenceType", ref.getReferenceType().toString());
                refInfo.put("isPrimary", ref.isPrimary());
                refInfo.put("operandIndex", ref.getOperandIndex());
                refInfo.put("sourceType", ref.getSource().toString());

                if (fromFunction != null) {
                    refInfo.put("fromFunction", fromFunction.getName());

                    // Use combined method for efficiency
                    int contextLines = includeContext ? 1 : 0;
                    LineNumberAndContext result = getLineNumberAndContext(program, fromFunction, fromAddress, contextLines);

                    if (result.isValid()) {
                        refInfo.put("fromLine", result.lineNumber);
                        if (includeContext && result.context != null) {
                            refInfo.put("context", result.context);
                        }
                    }
                }

                enhancedRefs.add(refInfo);
            }
        } catch (Exception e) {
            Msg.error(DecompilationContextUtil.class, "Error getting enhanced references to address", e);
        }

        return enhancedRefs;
    }

    /**
     * Clear the decompilation cache. Call this when program state changes significantly.
     */
    public static void clearCache() {
        decompilationCache.clear();
    }
}
