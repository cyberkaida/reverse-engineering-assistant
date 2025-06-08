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
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;

/**
 * Tool provider for cross-reference operations.
 * Provides tools to retrieve references to and from addresses or symbols in a program.
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
        registerReferencesTool();
        registerSymbolReferencesTool();
    }

    /**
     * Register a tool to get all references to and from an address in a single call
     * @throws McpError if there's an error registering the tool
     */
    private void registerReferencesTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to get references from"
        ));
        properties.put("addressOrSymbol", Map.of(
            "type", "string",
            "description", "Address or symbol name to get references to and from (e.g., '0x00400123' or 'main')"
        ));
        properties.put("includeFlow", Map.of(
            "type", "boolean",
            "description", "Whether to include flow references (calls, jumps, etc.)",
            "default", true
        ));
        properties.put("includeData", Map.of(
            "type", "boolean",
            "description", "Whether to include data references",
            "default", true
        ));
        properties.put("includeFromAddress", Map.of(
            "type", "boolean",
            "description", "Whether to include references from the address",
            "default", true
        ));
        properties.put("includeToAddress", Map.of(
            "type", "boolean",
            "description", "Whether to include references to the address",
            "default", true
        ));

        List<String> required = List.of("programPath", "addressOrSymbol");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-references",
            "Get all references to and from a specified address (use this to locate what uses a specific function, or string, or piece of data)",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(args);
            Address address = getAddressFromArgs(args, program, "addressOrSymbol");

            // Get filters
            boolean includeFlow = getOptionalBoolean(args, "includeFlow", true);
            boolean includeData = getOptionalBoolean(args, "includeData", true);
            boolean includeFromAddress = getOptionalBoolean(args, "includeFromAddress", true);
            boolean includeToAddress = getOptionalBoolean(args, "includeToAddress", true);

            // Get the symbol table for looking up symbols
            SymbolTable symbolTable = program.getSymbolTable();
            ReferenceManager refManager = program.getReferenceManager();

            // Prepare result containers
            List<Map<String, Object>> referencesFrom = new ArrayList<>();
            List<Map<String, Object>> referencesTo = new ArrayList<>();

            // Get references from the address if requested
            if (includeFromAddress) {
                Reference[] refs = refManager.getReferencesFrom(address);

                for (Reference ref : refs) {
                    // Skip based on filter settings
                    if (!includeFlow && ref.getReferenceType().isFlow()) {
                        continue;
                    }
                    if (!includeData && !ref.getReferenceType().isFlow()) {
                        continue;
                    }

                    Map<String, Object> refData = new HashMap<>();
                    refData.put("fromAddress", ref.getFromAddress().toString());
                    refData.put("toAddress", ref.getToAddress().toString());
                    refData.put("referenceType", ref.getReferenceType().toString());
                    refData.put("isPrimary", ref.isPrimary());
                    refData.put("operandIndex", ref.getOperandIndex());
                    refData.put("sourceType", ref.getSource().toString());

                    // Add destination symbol information if available
                    Symbol toSymbol = symbolTable.getPrimarySymbol(ref.getToAddress());
                    if (toSymbol != null) {
                        refData.put("toSymbol", toSymbol.getName());
                        refData.put("toSymbolType", toSymbol.getSymbolType().toString());
                        addNamespaceInfo(refData, toSymbol, "toSymbol");
                    }

                    referencesFrom.add(refData);
                }
            }

            // Get references to the address if requested
            if (includeToAddress) {
                // Check if the address is a valid memory address for references to
                if (address.isStackAddress() || address.isRegisterAddress()) {
                    // Just skip this part rather than error, since we may still have from refs
                    logInfo("Skipping references to stack/register address: " + address);
                } else {
                    ReferenceIterator refIter = refManager.getReferencesTo(address);

                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();

                        // Skip based on filter settings
                        if (!includeFlow && ref.getReferenceType().isFlow()) {
                            continue;
                        }
                        if (!includeData && !ref.getReferenceType().isFlow()) {
                            continue;
                        }

                        Map<String, Object> refData = new HashMap<>();
                        refData.put("fromAddress", ref.getFromAddress().toString());
                        refData.put("toAddress", ref.getToAddress().toString());
                        refData.put("referenceType", ref.getReferenceType().toString());
                        refData.put("isPrimary", ref.isPrimary());
                        refData.put("operandIndex", ref.getOperandIndex());
                        refData.put("sourceType", ref.getSource().toString());

                        // Add source symbol information if available
                        Symbol fromSymbol = symbolTable.getPrimarySymbol(ref.getFromAddress());
                        if (fromSymbol != null) {
                            refData.put("fromSymbol", fromSymbol.getName());
                            refData.put("fromSymbolType", fromSymbol.getSymbolType().toString());
                            addNamespaceInfo(refData, fromSymbol, "fromSymbol");
                        }

                        referencesTo.add(refData);
                    }
                }
            }

            // Create result data
            Map<String, Object> resultData = new HashMap<>();
            resultData.put("program", program.getName());
            resultData.put("address", address.toString());
            resultData.put("referencesFrom", referencesFrom);
            resultData.put("referencesTo", referencesTo);
            resultData.put("countFrom", referencesFrom.size());
            resultData.put("countTo", referencesTo.size());
            resultData.put("totalCount", referencesFrom.size() + referencesTo.size());

            return createJsonResult(resultData);
        });
    }

    /**
     * Register a tool to get symbol-based references to and from in a single call
     * @throws McpError if there's an error registering the tool
     */
    private void registerSymbolReferencesTool() throws McpError {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to get references from"
        ));
        properties.put("symbolName", Map.of(
            "type", "string",
            "description", "Name of the symbol to get references to and from"
        ));
        properties.put("namespace", Map.of(
            "type", "string",
            "description", "Optional namespace to restrict the symbol search (e.g., 'namespace1::namespace2')",
            "default", ""
        ));
        properties.put("includeFlow", Map.of(
            "type", "boolean",
            "description", "Whether to include flow references (calls, jumps, etc.)",
            "default", true
        ));
        properties.put("includeData", Map.of(
            "type", "boolean",
            "description", "Whether to include data references",
            "default", true
        ));
        properties.put("exactMatch", Map.of(
            "type", "boolean",
            "description", "Whether the symbol name must match exactly, or can be a partial match",
            "default", true
        ));
        properties.put("includeFromSymbol", Map.of(
            "type", "boolean",
            "description", "Whether to include references from the symbol",
            "default", true
        ));
        properties.put("includeToSymbol", Map.of(
            "type", "boolean",
            "description", "Whether to include references to the symbol",
            "default", true
        ));

        List<String> required = List.of("programPath", "symbolName");

        // Create the tool
        McpSchema.Tool tool = new McpSchema.Tool(
            "get-symbol-references",
            "Get all references to and from a specified symbol (this is not for searching for a symbol, but for finding what uses a specific symbol)",
            createSchema(properties, required)
        );

        // Register the tool with a handler
        registerTool(tool, (exchange, args) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(args);
            String symbolName = getString(args, "symbolName");

            // Get the namespace (if provided)
            String namespaceString = getOptionalString(args, "namespace", "");

            // Get filters
            boolean includeFlow = getOptionalBoolean(args, "includeFlow", true);
            boolean includeData = getOptionalBoolean(args, "includeData", true);
            boolean exactMatch = getOptionalBoolean(args, "exactMatch", true);
            boolean includeFromSymbol = getOptionalBoolean(args, "includeFromSymbol", true);
            boolean includeToSymbol = getOptionalBoolean(args, "includeToSymbol", true);

            // Find the symbol
            SymbolTable symbolTable = program.getSymbolTable();
            List<Symbol> matchingSymbols = new ArrayList<>();

            // Try to resolve the namespace if provided
            Namespace searchNamespace = program.getGlobalNamespace(); // Default to global
            if (!namespaceString.isEmpty()) {
                try {
                    // Find or create the namespace hierarchy
                    searchNamespace = resolveNamespace(namespaceString, program);
                    if (searchNamespace == null) {
                        return createErrorResult("Could not find namespace: " + namespaceString);
                    }
                } catch (Exception e) {
                    return createErrorResult("Error resolving namespace: " + e.getMessage());
                }
            }

            // Find symbols, considering namespace
            if (exactMatch) {
                // Get symbols that match the name in the specified namespace
                List<Symbol> symbols = symbolTable.getSymbols(symbolName, searchNamespace);
                matchingSymbols.addAll(symbols);
            } else {
                // For partial matches, we need to check all symbols in the namespace
                symbolTable.getSymbols(searchNamespace).forEach(symbol -> {
                    if (symbol.getName().contains(symbolName)) {
                        matchingSymbols.add(symbol);
                    }
                });
            }

            if (matchingSymbols.isEmpty()) {
                if (namespaceString.isEmpty()) {
                    return createErrorResult("No symbols found matching: " + symbolName);
                } else {
                    return createErrorResult("No symbols found matching: " + symbolName +
                        " in namespace: " + namespaceString);
                }
            }

            // Prepare result containers
            List<Map<String, Object>> referencesFrom = new ArrayList<>();
            List<Map<String, Object>> referencesTo = new ArrayList<>();
            ReferenceManager refManager = program.getReferenceManager();

            for (Symbol symbol : matchingSymbols) {
                // Get the address of the symbol
                Address symbolAddr = symbol.getAddress();

                // Get references from the symbol if requested
                if (includeFromSymbol) {
                    Reference[] refs = refManager.getReferencesFrom(symbolAddr);

                    // Filter and convert references to a response format
                    for (Reference ref : refs) {
                        // Skip based on filter settings
                        if (!includeFlow && ref.getReferenceType().isFlow()) {
                            continue;
                        }
                        if (!includeData && !ref.getReferenceType().isFlow()) {
                            continue;
                        }

                        Map<String, Object> refData = new HashMap<>();
                        refData.put("symbol", symbol.getName());
                        refData.put("symbolAddress", symbol.getAddress().toString());
                        refData.put("symbolType", symbol.getSymbolType().toString());
                        addNamespaceInfo(refData, symbol, "symbol");

                        refData.put("fromAddress", ref.getFromAddress().toString());
                        refData.put("toAddress", ref.getToAddress().toString());
                        refData.put("referenceType", ref.getReferenceType().toString());
                        refData.put("isPrimary", ref.isPrimary());
                        refData.put("operandIndex", ref.getOperandIndex());
                        refData.put("sourceType", ref.getSource().toString());

                        // Add destination symbol information if available
                        Symbol toSymbol = symbolTable.getPrimarySymbol(ref.getToAddress());
                        if (toSymbol != null) {
                            refData.put("toSymbol", toSymbol.getName());
                            refData.put("toSymbolType", toSymbol.getSymbolType().toString());
                            addNamespaceInfo(refData, toSymbol, "toSymbol");
                        }

                        referencesFrom.add(refData);
                    }
                }

                // Get references to the symbol if requested
                if (includeToSymbol) {
                    // Skip stack or register addresses
                    if (symbolAddr.isStackAddress() || symbolAddr.isRegisterAddress()) {
                        continue;
                    }

                    // Get references to this symbol
                    ReferenceIterator refIter = refManager.getReferencesTo(symbolAddr);

                    // Filter and convert references to a response format
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();

                        // Skip based on filter settings
                        if (!includeFlow && ref.getReferenceType().isFlow()) {
                            continue;
                        }
                        if (!includeData && !ref.getReferenceType().isFlow()) {
                            continue;
                        }

                        Map<String, Object> refData = new HashMap<>();
                        refData.put("symbol", symbol.getName());
                        refData.put("symbolAddress", symbol.getAddress().toString());
                        refData.put("symbolType", symbol.getSymbolType().toString());
                        addNamespaceInfo(refData, symbol, "symbol");

                        refData.put("fromAddress", ref.getFromAddress().toString());
                        refData.put("toAddress", ref.getToAddress().toString());
                        refData.put("referenceType", ref.getReferenceType().toString());
                        refData.put("isPrimary", ref.isPrimary());
                        refData.put("operandIndex", ref.getOperandIndex());
                        refData.put("sourceType", ref.getSource().toString());

                        // Try to get source symbol information
                        Symbol fromSymbol = symbolTable.getPrimarySymbol(ref.getFromAddress());
                        if (fromSymbol != null) {
                            refData.put("fromSymbol", fromSymbol.getName());
                            refData.put("fromSymbolType", fromSymbol.getSymbolType().toString());
                            addNamespaceInfo(refData, fromSymbol, "fromSymbol");
                        }

                        referencesTo.add(refData);
                    }
                }
            }

            // Create result data
            Map<String, Object> resultData = new HashMap<>();
            resultData.put("program", program.getName());
            resultData.put("symbolName", symbolName);
            if (!namespaceString.isEmpty()) {
                resultData.put("namespace", namespaceString);
            }
            resultData.put("matchedSymbols", matchingSymbols.size());
            resultData.put("referencesFrom", referencesFrom);
            resultData.put("referencesTo", referencesTo);
            resultData.put("countFrom", referencesFrom.size());
            resultData.put("countTo", referencesTo.size());
            resultData.put("totalCount", referencesFrom.size() + referencesTo.size());

            return createJsonResult(resultData);
        });
    }

    /**
     * Add namespace information to the reference data for a symbol
     * @param refData Map to add namespace information to
     * @param symbol Symbol to get namespace information from
     * @param prefix Prefix for the keys in the map
     */
    private void addNamespaceInfo(Map<String, Object> refData, Symbol symbol, String prefix) {
        // Add the namespace path if it's not in the global namespace
        if (!symbol.isGlobal()) {
            Namespace parentNamespace = symbol.getParentNamespace();
            if (parentNamespace != null && !parentNamespace.isGlobal()) {
                refData.put(prefix + "Namespace", getNamespacePath(parentNamespace));
            }
        }

        // Include full path with namespaces
        String[] path = symbol.getPath();
        if (path != null && path.length > 0) {
            refData.put(prefix + "Path", String.join("::", path));
        }
    }

    /**
     * Get the full path of a namespace as a string
     * @param namespace The namespace to get the path for
     * @return The namespace path as a string
     */
    private String getNamespacePath(Namespace namespace) {
        if (namespace == null || namespace.isGlobal()) {
            return "";
        }

        StringBuilder path = new StringBuilder();
        buildNamespacePath(namespace, path);
        return path.toString();
    }

    /**
     * Recursively build a namespace path
     * @param namespace The namespace to build the path for
     * @param path The StringBuilder to append to
     */
    private void buildNamespacePath(Namespace namespace, StringBuilder path) {
        if (namespace == null || namespace.isGlobal()) {
            return;
        }

        Namespace parent = namespace.getParentNamespace();
        if (parent != null && !parent.isGlobal()) {
            buildNamespacePath(parent, path);
            path.append("::");
        }
        path.append(namespace.getName());
    }

    /**
     * Resolve a namespace string to a Namespace object
     * @param namespaceString Namespace path string (e.g., "ns1::ns2::ns3")
     * @param program The program to search in
     * @return The resolved Namespace or null if not found
     */
    private Namespace resolveNamespace(String namespaceString, Program program) {
        if (namespaceString == null || namespaceString.isEmpty()) {
            return program.getGlobalNamespace();
        }

        // Split the namespace path
        String[] parts = namespaceString.split("::");

        // Start with the global namespace
        Namespace current = program.getGlobalNamespace();

        // Navigate through the namespace hierarchy
        for (String part : parts) {
            if (part.isEmpty()) continue;

            // Find the child namespace
            Namespace child = program.getSymbolTable().getNamespace(part, current);
            if (child == null) {
                return null; // Namespace not found
            }
            current = child;
        }

        return current;
    }
}
