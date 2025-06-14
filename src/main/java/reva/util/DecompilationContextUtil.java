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
import reva.util.RevaInternalServiceRegistry;

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

        // Initialize decompiler
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        if (!decompiler.openProgram(program)) {
            return -1;
        }

        try {
            // Decompile the function with timeout
            int timeoutSeconds = RevaInternalServiceRegistry.getService(ConfigManager.class).getDecompilerTimeoutSeconds();
            TaskMonitor timeoutMonitor = TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
            DecompileResults decompileResults = decompiler.decompileFunction(function, 0, timeoutMonitor);
            if (timeoutMonitor.isCancelled()) {
                Msg.error(DecompilationContextUtil.class, "Decompilation timed out for address " + address + " after " + timeoutSeconds + " seconds");
                return -1;
            }
            if (!decompileResults.decompileCompleted()) {
                return -1;
            }

            // Get the markup for line mapping
            ClangTokenGroup markup = decompileResults.getCCodeMarkup();
            List<ClangLine> clangLines = DecompilerUtils.toLines(markup);

            // Find the line containing this address
            for (ClangLine clangLine : clangLines) {
                List<ClangToken> tokens = clangLine.getAllTokens();
                for (ClangToken token : tokens) {
                    Address tokenAddr = token.getMinAddress();
                    if (tokenAddr != null && tokenAddr.equals(address)) {
                        return clangLine.getLineNumber();
                    }
                }

                // If no exact match, check if address is within the range of this line
                if (!tokens.isEmpty()) {
                    Address closestAddr = DecompilerUtils.getClosestAddress(program, tokens.get(0));
                    if (closestAddr != null && closestAddr.equals(address)) {
                        return clangLine.getLineNumber();
                    }
                }
            }

            return -1;
        } catch (Exception e) {
            Msg.error(DecompilationContextUtil.class, "Error getting line number for address " + address, e);
            return -1;
        } finally {
            decompiler.dispose();
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

        // Initialize decompiler
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        if (!decompiler.openProgram(program)) {
            return null;
        }

        try {
            // Decompile the function with timeout
            int timeoutSeconds = RevaInternalServiceRegistry.getService(ConfigManager.class).getDecompilerTimeoutSeconds();
            TaskMonitor timeoutMonitor = TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
            DecompileResults decompileResults = decompiler.decompileFunction(function, 0, timeoutMonitor);
            if (timeoutMonitor.isCancelled()) {
                Msg.error(DecompilationContextUtil.class, "Decompilation timed out while getting context after " + timeoutSeconds + " seconds");
                return null;
            }
            if (!decompileResults.decompileCompleted()) {
                return null;
            }

            // Get the decompiled code
            DecompiledFunction decompiledFunction = decompileResults.getDecompiledFunction();
            String decompCode = decompiledFunction.getC();
            String[] lines = decompCode.split("\n");

            // Calculate range
            int startLine = Math.max(0, lineNumber - 1 - contextLines); // Convert to 0-based
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
        } catch (Exception e) {
            Msg.error(DecompilationContextUtil.class, "Error getting decompilation context", e);
            return null;
        } finally {
            decompiler.dispose();
        }
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
        List<Map<String, Object>> enhancedRefs = new ArrayList<>();

        if (program == null || targetFunction == null) {
            return enhancedRefs;
        }

        try {
            // Get references to this function's entry point
            ReferenceIterator incomingRefs = program.getReferenceManager().getReferencesTo(targetFunction.getEntryPoint());

            while (incomingRefs.hasNext()) {
                Reference ref = incomingRefs.next();
                Address fromAddress = ref.getFromAddress();
                Function fromFunction = program.getFunctionManager().getFunctionContaining(fromAddress);

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