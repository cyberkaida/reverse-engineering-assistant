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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import reva.decompiler.DecompilationCache;
import reva.decompiler.DecompilationResult;
import reva.decompiler.DecompilationSnapshot;

/**
 * Utility class for working with decompilation context and cross references.
 * Provides methods to map addresses to decompilation line numbers and extract
 * code context around specific lines.
 */
public class DecompilationContextUtil {

    /**
     * Get the decompilation line number for a specific address within a function.
     *
     * @param program The Ghidra program
     * @param function The function containing the address
     * @param address The address to find the line number for
     * @return The line number (1-based) or -1 if not found
     */
    public static int getLineNumberForAddress(Program program, Function function, Address address) {
        if (program == null || function == null || address == null) {
            return -1;
        }

        DecompilationSnapshot snapshot = snapshotFor(program, function);
        return snapshot != null ? snapshot.lineForAddress(address) : -1;
    }

    /** The function's cached decompilation, or null if there is no cache or the decompile failed. */
    private static DecompilationSnapshot snapshotFor(Program program, Function function) {
        DecompilationCache cache = RevaInternalServiceRegistry.getService(DecompilationCache.class);
        if (cache == null) {
            return null;
        }
        try {
            DecompilationResult result = cache.get(program, function);
            return result != null && result.success() ? result.snapshot() : null;
        } catch (Exception e) {
            Msg.error(DecompilationContextUtil.class, "Error reading decompilation for " + function.getName(), e);
            return null;
        }
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

        DecompilationSnapshot snapshot = snapshotFor(program, function);
        return snapshot != null ? snapshot.context(lineNumber, contextLines) : null;
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
     * @param program The Ghidra program
     * @param targetFunction The function to get incoming references for
     * @param includeContext Whether to include code context snippets (expensive - requires decompilation per reference)
     * @param maxRefs Maximum number of references to return (-1 for no limit)
     * @return List of enhanced reference maps
     */
    public static List<Map<String, Object>> getEnhancedIncomingReferences(Program program, Function targetFunction, boolean includeContext, int maxRefs) {
        List<Map<String, Object>> enhancedRefs = new ArrayList<>();

        if (program == null || targetFunction == null) {
            return enhancedRefs;
        }

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
            int contextFetched = 0;

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

                    // Get line number in the source function
                    int lineNumber = getLineNumberForAddress(program, fromFunction, fromAddress);
                    if (lineNumber > 0) {
                        refInfo.put("fromLine", lineNumber);

                        // Add context if requested (this is expensive - requires decompilation)
                        if (includeContext) {
                            contextFetched++;
                            // Log progress every 3 context fetches (each is a decompilation)
                            if (contextFetched % 3 == 0) {
                                DebugLogger.debug(DecompilationContextUtil.class,
                                    String.format("getEnhancedIncomingReferences: Fetched context for %d/%d references (decompiling calling functions)",
                                        contextFetched, maxRefs > 0 ? Math.min(maxRefs, totalRefs) : totalRefs));
                            }

                            String context = getDecompilationContext(program, fromFunction, lineNumber, 1);
                            if (context != null) {
                                refInfo.put("context", context);
                            }
                        }
                    }
                }

                enhancedRefs.add(refInfo);
            }

            DebugLogger.debug(DecompilationContextUtil.class,
                String.format("getEnhancedIncomingReferences: Completed - processed %d references, fetched %d contexts, returning %d results",
                    processed, contextFetched, enhancedRefs.size()));

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

                    // Get line number in the source function
                    int lineNumber = getLineNumberForAddress(program, fromFunction, fromAddress);
                    if (lineNumber > 0) {
                        refInfo.put("fromLine", lineNumber);

                        // Add context if requested
                        if (includeContext) {
                            String context = getDecompilationContext(program, fromFunction, lineNumber, 1);
                            if (context != null) {
                                refInfo.put("context", context);
                            }
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
}