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
package reva.tools.xrefs;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.DecompilationContextUtil;

/**
 * Tool provider for cross-reference operations.
 * Provides a unified tool to retrieve references to and from addresses or symbols
 * with optional decompilation context snippets.
 */
public class CrossReferencesToolProvider extends AbstractToolProvider {

    /**
     * Constructor
     * @param server The MCP server
     */
    public CrossReferencesToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() throws McpError {
        registerCrossReferencesTool();
    }

    /**
     * Register the unified cross references tool
     * @throws McpError if there's an error registering the tool
     */
    private void registerCrossReferencesTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to get references from"
        ));
        properties.put("location", Map.of(
            "type", "string",
            "description", "Address or symbol name to get references for (e.g., '0x00400123', 'main', 'FUN_00401000')"
        ));
        properties.put("direction", Map.of(
            "type", "string",
            "description", "Direction of references to retrieve: 'to' (incoming), 'from' (outgoing), or 'both' (default)",
            "enum", List.of("to", "from", "both"),
            "default", "both"
        ));
        properties.put("includeFlow", Map.of(
            "type", "boolean",
            "description", "Include flow references (calls, jumps, branches)",
            "default", true
        ));
        properties.put("includeData", Map.of(
            "type", "boolean",
            "description", "Include data references (reads, writes)",
            "default", true
        ));
        properties.put("includeContext", Map.of(
            "type", "boolean",
            "description", "Include decompilation context snippets for code references",
            "default", false
        ));
        properties.put("contextLines", Map.of(
            "type", "integer",
            "description", "Number of lines before and after to include in context snippets",
            "default", 2
        ));
        properties.put("offset", Map.of(
            "type", "integer",
            "description", "Starting offset for pagination (0-based)",
            "default", 0
        ));
        properties.put("limit", Map.of(
            "type", "integer",
            "description", "Maximum number of references to return per direction",
            "default", 100
        ));

        List<String> required = List.of("programPath", "location");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("find-cross-references")
            .description("Find all references to or from a memory location, symbol, or function. Returns incoming and/or outgoing references with optional decompilation context.")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                Address address = getAddressFromArgs(request, program, "location");
                
                // Get parameters
                String direction = getOptionalString(request, "direction", "both");
                boolean includeFlow = getOptionalBoolean(request, "includeFlow", true);
                boolean includeData = getOptionalBoolean(request, "includeData", true);
                boolean includeContext = getOptionalBoolean(request, "includeContext", false);
                int contextLines = getOptionalInt(request, "contextLines", 2);
                int offset = getOptionalInt(request, "offset", 0);
                int limit = getOptionalInt(request, "limit", 100);
                
                // Validate parameters
                if (offset < 0) offset = 0;
                if (limit <= 0) limit = 100;
                if (limit > 1000) limit = 1000; // Cap at reasonable maximum
                
                // Get references based on direction
                boolean includeTo = direction.equals("to") || direction.equals("both");
                boolean includeFrom = direction.equals("from") || direction.equals("both");
                
                // Prepare result containers
                List<Map<String, Object>> referencesTo = new ArrayList<>();
                List<Map<String, Object>> referencesFrom = new ArrayList<>();
                int totalToCount = 0;
                int totalFromCount = 0;
                
                ReferenceManager refManager = program.getReferenceManager();
                SymbolTable symbolTable = program.getSymbolTable();
                
                // Get references TO this address
                if (includeTo && !address.isStackAddress() && !address.isRegisterAddress()) {
                    ReferenceIterator refIter = refManager.getReferencesTo(address);
                    List<Map<String, Object>> allRefsTo = new ArrayList<>();
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        
                        // Apply filters
                        if (!includeFlow && ref.getReferenceType().isFlow()) continue;
                        if (!includeData && !ref.getReferenceType().isFlow()) continue;
                        
                        allRefsTo.add(createReferenceInfo(ref, program, includeContext, contextLines, true));
                    }
                    
                    totalToCount = allRefsTo.size();
                    
                    // Apply pagination
                    int endIndex = Math.min(offset + limit, allRefsTo.size());
                    if (offset < allRefsTo.size()) {
                        referencesTo = allRefsTo.subList(offset, endIndex);
                    }
                }
                
                // Get references FROM this address
                if (includeFrom) {
                    List<Map<String, Object>> allRefsFrom = new ArrayList<>();
                    
                    // Check if this address is within a function
                    Function function = program.getFunctionManager().getFunctionContaining(address);
                    if (function != null) {
                        // Get all addresses in the function body
                        AddressSetView functionBody = function.getBody();
                        for (Address addr : functionBody.getAddresses(true)) {
                            Reference[] refs = refManager.getReferencesFrom(addr);
                            for (Reference ref : refs) {
                                // Apply filters
                                if (!includeFlow && ref.getReferenceType().isFlow()) continue;
                                if (!includeData && !ref.getReferenceType().isFlow()) continue;
                                
                                allRefsFrom.add(createReferenceInfo(ref, program, includeContext, contextLines, false));
                            }
                        }
                    } else {
                        // Not in a function, just get references from the specific address
                        Reference[] refs = refManager.getReferencesFrom(address);
                        for (Reference ref : refs) {
                            // Apply filters
                            if (!includeFlow && ref.getReferenceType().isFlow()) continue;
                            if (!includeData && !ref.getReferenceType().isFlow()) continue;
                            
                            allRefsFrom.add(createReferenceInfo(ref, program, includeContext, contextLines, false));
                        }
                    }
                    
                    totalFromCount = allRefsFrom.size();
                    
                    // Apply pagination
                    int endIndex = Math.min(offset + limit, allRefsFrom.size());
                    if (offset < allRefsFrom.size()) {
                        referencesFrom = allRefsFrom.subList(offset, endIndex);
                    }
                }
                
                // Get symbol information for the target address
                Symbol targetSymbol = symbolTable.getPrimarySymbol(address);
                Map<String, Object> locationInfo = new HashMap<>();
                locationInfo.put("address", AddressUtil.formatAddress(address));
                if (targetSymbol != null) {
                    locationInfo.put("symbol", targetSymbol.getName());
                    locationInfo.put("symbolType", targetSymbol.getSymbolType().toString());
                    if (!targetSymbol.isGlobal()) {
                        locationInfo.put("namespace", targetSymbol.getParentNamespace().getName(true));
                    }
                }
                
                // Check if this is a function
                Function targetFunction = program.getFunctionManager().getFunctionContaining(address);
                if (targetFunction != null) {
                    locationInfo.put("function", targetFunction.getName());
                    if (targetFunction.getEntryPoint().equals(address)) {
                        locationInfo.put("isFunctionEntry", true);
                    }
                }
                
                // Create result data
                Map<String, Object> resultData = new HashMap<>();
                resultData.put("program", program.getName());
                resultData.put("location", locationInfo);
                resultData.put("referencesTo", referencesTo);
                resultData.put("referencesFrom", referencesFrom);
                resultData.put("pagination", Map.of(
                    "offset", offset,
                    "limit", limit,
                    "totalToCount", totalToCount,
                    "totalFromCount", totalFromCount,
                    "hasMoreTo", offset + limit < totalToCount,
                    "hasMoreFrom", offset + limit < totalFromCount
                ));
                
                return createJsonResult(resultData);
                
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                logError("Error getting cross references", e);
                return createErrorResult("Error getting cross references: " + e.getMessage());
            }
        });
    }
    
    /**
     * Create reference information map with optional decompilation context
     * @param ref The reference
     * @param program The program
     * @param includeContext Whether to include decompilation context
     * @param contextLines Number of context lines
     * @param isIncoming Whether this is an incoming reference (to) or outgoing (from)
     * @return Map containing reference information
     */
    private Map<String, Object> createReferenceInfo(Reference ref, Program program, 
                                                    boolean includeContext, int contextLines,
                                                    boolean isIncoming) {
        Map<String, Object> refInfo = new HashMap<>();
        SymbolTable symbolTable = program.getSymbolTable();
        
        // Basic reference information
        refInfo.put("fromAddress", AddressUtil.formatAddress(ref.getFromAddress()));
        refInfo.put("toAddress", AddressUtil.formatAddress(ref.getToAddress()));
        refInfo.put("referenceType", ref.getReferenceType().toString());
        refInfo.put("isPrimary", ref.isPrimary());
        refInfo.put("operandIndex", ref.getOperandIndex());
        refInfo.put("sourceType", ref.getSource().toString());
        refInfo.put("isCall", ref.getReferenceType().isCall());
        refInfo.put("isJump", ref.getReferenceType().isJump());
        refInfo.put("isData", ref.getReferenceType().isData());
        refInfo.put("isRead", ref.getReferenceType().isRead());
        refInfo.put("isWrite", ref.getReferenceType().isWrite());
        
        // Add symbol information for both addresses
        Symbol fromSymbol = symbolTable.getPrimarySymbol(ref.getFromAddress());
        if (fromSymbol != null) {
            Map<String, Object> fromSymbolInfo = new HashMap<>();
            fromSymbolInfo.put("name", fromSymbol.getName());
            fromSymbolInfo.put("type", fromSymbol.getSymbolType().toString());
            if (!fromSymbol.isGlobal()) {
                fromSymbolInfo.put("namespace", fromSymbol.getParentNamespace().getName(true));
            }
            refInfo.put("fromSymbol", fromSymbolInfo);
        }
        
        Symbol toSymbol = symbolTable.getPrimarySymbol(ref.getToAddress());
        if (toSymbol != null) {
            Map<String, Object> toSymbolInfo = new HashMap<>();
            toSymbolInfo.put("name", toSymbol.getName());
            toSymbolInfo.put("type", toSymbol.getSymbolType().toString());
            if (!toSymbol.isGlobal()) {
                toSymbolInfo.put("namespace", toSymbol.getParentNamespace().getName(true));
            }
            refInfo.put("toSymbol", toSymbolInfo);
        }
        
        // Add function information and optional decompilation context
        Address contextAddress = isIncoming ? ref.getFromAddress() : ref.getToAddress();
        Function contextFunction = program.getFunctionManager().getFunctionContaining(contextAddress);
        
        if (contextFunction != null) {
            Map<String, Object> functionInfo = new HashMap<>();
            functionInfo.put("name", contextFunction.getName());
            functionInfo.put("entry", AddressUtil.formatAddress(contextFunction.getEntryPoint()));
            
            // For incoming references, add decompilation context from the calling function
            if (includeContext && ref.getReferenceType().isFlow()) {
                int lineNumber = DecompilationContextUtil.getLineNumberForAddress(
                    program, contextFunction, contextAddress);
                    
                if (lineNumber > 0) {
                    functionInfo.put("line", lineNumber);
                    
                    String context = DecompilationContextUtil.getDecompilationContext(
                        program, contextFunction, lineNumber, contextLines);
                    if (context != null) {
                        functionInfo.put("context", context);
                    }
                }
            }
            
            refInfo.put(isIncoming ? "fromFunction" : "toFunction", functionInfo);
        }
        
        return refInfo;
    }
}