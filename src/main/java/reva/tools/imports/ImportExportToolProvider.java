package reva.tools.imports;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;

/**
 * Tool provider for import/export analysis.
 * Provides tools for analyzing imported and exported symbols in binaries.
 *
 * <p>For PE files, exports are detected via Ghidra's external entry points mechanism.
 * The PE loader calls {@code SymbolTable.addExternalEntryPoint()} for each exported symbol,
 * so {@code getExternalEntryPointIterator()} correctly returns all PE exports.</p>
 */
public class ImportExportToolProvider extends AbstractToolProvider {

    // Pagination limits
    private static final int DEFAULT_MAX_RESULTS = 500;
    private static final int MAX_IMPORT_RESULTS = 2000;
    private static final int MAX_EXPORT_RESULTS = 2000;
    private static final int MAX_REFERENCE_RESULTS = 500;

    // Thunk resolution limits
    private static final int MAX_THUNK_CHAIN_DEPTH = 10;

    public ImportExportToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerListImportsTool();
        registerListExportsTool();
        registerFindImportReferencesTool();
        registerResolveThunkTool();
    }

    // ========================================================================
    // Tool Registration
    // ========================================================================

    private void registerListImportsTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("libraryFilter", Map.of(
            "type", "string",
            "description", "Optional: filter by library name (case-insensitive partial match)"
        ));
        properties.put("maxResults", Map.of(
            "type", "integer",
            "description", "Maximum number of imports to return (default: 500)",
            "default", 500
        ));
        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (default: 0)",
            "default", 0
        ));
        properties.put("groupByLibrary", Map.of(
            "type", "boolean",
            "description", "Group imports by library name (default: true)",
            "default", true
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-imports")
            .title("List Imports")
            .description("List all imported functions from external libraries. " +
                "Useful for understanding what external APIs a binary uses.")
            .inputSchema(createSchema(properties, List.of("programPath")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            String libraryFilter = getOptionalString(request, "libraryFilter", null);
            int maxResults = clamp(getOptionalInt(request, "maxResults", DEFAULT_MAX_RESULTS), 1, MAX_IMPORT_RESULTS);
            int startIndex = Math.max(0, getOptionalInt(request, "startIndex", 0));
            boolean groupByLibrary = getOptionalBoolean(request, "groupByLibrary", true);

            List<Map<String, Object>> allImports = collectImports(program, libraryFilter);
            List<Map<String, Object>> paginated = paginate(allImports, startIndex, maxResults);

            Map<String, Object> result = new HashMap<>();
            result.put("programPath", program.getDomainFile().getPathname());
            result.put("totalCount", allImports.size());
            result.put("startIndex", startIndex);
            result.put("returnedCount", paginated.size());

            if (groupByLibrary) {
                result.put("libraries", groupImportsByLibrary(paginated));
            } else {
                result.put("imports", paginated);
            }

            return createJsonResult(result);
        });
    }

    private void registerListExportsTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("maxResults", Map.of(
            "type", "integer",
            "description", "Maximum number of exports to return (default: 500)",
            "default", 500
        ));
        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (default: 0)",
            "default", 0
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-exports")
            .title("List Exports")
            .description("List all exported symbols from the binary. " +
                "Shows functions and data that the binary exports for use by other modules.")
            .inputSchema(createSchema(properties, List.of("programPath")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            int maxResults = clamp(getOptionalInt(request, "maxResults", DEFAULT_MAX_RESULTS), 1, MAX_EXPORT_RESULTS);
            int startIndex = Math.max(0, getOptionalInt(request, "startIndex", 0));

            List<Map<String, Object>> allExports = collectExports(program);
            List<Map<String, Object>> paginated = paginate(allExports, startIndex, maxResults);

            return createJsonResult(Map.of(
                "programPath", program.getDomainFile().getPathname(),
                "totalCount", allExports.size(),
                "startIndex", startIndex,
                "returnedCount", paginated.size(),
                "exports", paginated
            ));
        });
    }

    private void registerFindImportReferencesTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("importName", Map.of(
            "type", "string",
            "description", "Name of the imported function to find references for (case-insensitive)"
        ));
        properties.put("libraryName", Map.of(
            "type", "string",
            "description", "Optional: specific library name to narrow search (case-insensitive)"
        ));
        properties.put("maxResults", Map.of(
            "type", "integer",
            "description", "Maximum number of references to return (default: 100)",
            "default", 100
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("find-import-references")
            .title("Find Import References")
            .description("Find all locations where a specific imported function is called. " +
                "Also finds references through thunks (IAT stubs).")
            .inputSchema(createSchema(properties, List.of("programPath", "importName")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            String importName = getString(request, "importName");
            String libraryName = getOptionalString(request, "libraryName", null);
            int maxResults = clamp(getOptionalInt(request, "maxResults", 100), 1, MAX_REFERENCE_RESULTS);

            List<Function> matchingImports = findImportsByName(program, importName, libraryName);
            if (matchingImports.isEmpty()) {
                return createErrorResult("Import not found: " + importName +
                    (libraryName != null ? " in " + libraryName : ""));
            }

            // Build thunk map once for efficiency: external function -> thunks pointing to it
            Map<Function, List<Function>> thunkMap = buildThunkMap(program);

            // Collect references
            List<Map<String, Object>> references = collectImportReferences(
                program, matchingImports, thunkMap, maxResults);

            // Build matched imports info
            List<Map<String, Object>> importInfoList = new ArrayList<>();
            for (Function importFunc : matchingImports) {
                importInfoList.add(buildImportInfo(importFunc));
            }

            return createJsonResult(Map.of(
                "programPath", program.getDomainFile().getPathname(),
                "searchedImport", importName,
                "matchedImports", importInfoList,
                "referenceCount", references.size(),
                "references", references
            ));
        });
    }

    private void registerResolveThunkTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("address", Map.of(
            "type", "string",
            "description", "Address of the thunk or jump stub to resolve"
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("resolve-thunk")
            .title("Resolve Thunk")
            .description("Follow a thunk chain to find the actual target function. " +
                "Thunks are wrapper functions that jump to another location.")
            .inputSchema(createSchema(properties, List.of("programPath", "address")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Address address = getAddressFromArgs(request, program, "address");

            Function function = program.getFunctionManager().getFunctionAt(address);
            if (function == null) {
                function = program.getFunctionManager().getFunctionContaining(address);
            }
            if (function == null) {
                return createErrorResult("No function found at address: " +
                    AddressUtil.formatAddress(address));
            }

            List<Map<String, Object>> chain = buildThunkChain(function);
            Map<String, Object> finalTarget = chain.get(chain.size() - 1);
            boolean isResolved = !Boolean.TRUE.equals(finalTarget.get("isThunk"));

            Map<String, Object> result = new HashMap<>();
            result.put("programPath", program.getDomainFile().getPathname());
            result.put("startAddress", AddressUtil.formatAddress(address));
            result.put("chain", chain);
            result.put("chainLength", chain.size());
            result.put("finalTarget", finalTarget);
            result.put("isResolved", isResolved);

            return createJsonResult(result);
        });
    }

    // ========================================================================
    // Data Collection Methods
    // ========================================================================

    private List<Map<String, Object>> collectImports(Program program, String libraryFilter) {
        List<Map<String, Object>> imports = new ArrayList<>();
        FunctionIterator externalFunctions = program.getFunctionManager().getExternalFunctions();

        while (externalFunctions.hasNext()) {
            Function func = externalFunctions.next();
            ExternalLocation extLoc = func.getExternalLocation();
            String library = extLoc != null ? extLoc.getLibraryName() : "<unknown>";

            // Apply library filter
            if (libraryFilter != null && !libraryFilter.isEmpty() &&
                !library.toLowerCase().contains(libraryFilter.toLowerCase())) {
                continue;
            }

            Map<String, Object> info = new HashMap<>();
            info.put("name", func.getName());
            info.put("library", library);

            Address entryPoint = func.getEntryPoint();
            if (entryPoint != null) {
                info.put("address", AddressUtil.formatAddress(entryPoint));
            }

            if (extLoc != null) {
                String originalName = extLoc.getOriginalImportedName();
                if (originalName != null && !originalName.equals(func.getName())) {
                    info.put("originalName", originalName);
                    if (originalName.startsWith("Ordinal_")) {
                        try {
                            info.put("ordinal", Integer.parseInt(originalName.substring(8)));
                        } catch (NumberFormatException e) {
                            // Not a valid ordinal format
                        }
                    }
                }
            }

            if (func.getSignature() != null) {
                info.put("signature", func.getSignature().getPrototypeString());
            }

            imports.add(info);
        }

        // Sort by library, then name
        imports.sort((a, b) -> {
            int cmp = ((String) a.get("library")).compareToIgnoreCase((String) b.get("library"));
            return cmp != 0 ? cmp : ((String) a.get("name")).compareToIgnoreCase((String) b.get("name"));
        });

        return imports;
    }

    private List<Map<String, Object>> collectExports(Program program) {
        List<Map<String, Object>> exports = new ArrayList<>();
        SymbolTable symbolTable = program.getSymbolTable();
        FunctionManager funcManager = program.getFunctionManager();

        AddressIterator entryPoints = symbolTable.getExternalEntryPointIterator();
        while (entryPoints.hasNext()) {
            Address addr = entryPoints.next();

            Map<String, Object> info = new HashMap<>();
            info.put("address", AddressUtil.formatAddress(addr));

            Symbol symbol = symbolTable.getPrimarySymbol(addr);
            if (symbol != null) {
                info.put("name", symbol.getName());
                info.put("symbolType", symbol.getSymbolType().toString());

                Function function = funcManager.getFunctionAt(addr);
                info.put("isFunction", function != null);
                if (function != null && function.getSignature() != null) {
                    info.put("signature", function.getSignature().getPrototypeString());
                }
            }

            exports.add(info);
        }

        // Sort by name
        exports.sort((a, b) -> {
            String nameA = (String) a.getOrDefault("name", "");
            String nameB = (String) b.getOrDefault("name", "");
            return nameA.compareToIgnoreCase(nameB);
        });

        return exports;
    }

    private List<Function> findImportsByName(Program program, String importName, String libraryName) {
        List<Function> matches = new ArrayList<>();
        FunctionIterator externalFunctions = program.getFunctionManager().getExternalFunctions();

        while (externalFunctions.hasNext()) {
            Function func = externalFunctions.next();

            if (!func.getName().equalsIgnoreCase(importName)) {
                continue;
            }

            if (libraryName != null && !libraryName.isEmpty()) {
                ExternalLocation extLoc = func.getExternalLocation();
                if (extLoc == null || !extLoc.getLibraryName().equalsIgnoreCase(libraryName)) {
                    continue;
                }
            }

            matches.add(func);
        }

        return matches;
    }

    /**
     * Build a map from external functions to thunks that point to them.
     * This is O(n) where n = number of functions, done once per request.
     */
    private Map<Function, List<Function>> buildThunkMap(Program program) {
        Map<Function, List<Function>> thunkMap = new HashMap<>();
        FunctionIterator allFunctions = program.getFunctionManager().getFunctions(true);

        while (allFunctions.hasNext()) {
            Function func = allFunctions.next();
            if (func.isThunk()) {
                Function target = func.getThunkedFunction(true); // Resolve fully
                if (target != null && target.isExternal()) {
                    thunkMap.computeIfAbsent(target, k -> new ArrayList<>()).add(func);
                }
            }
        }

        return thunkMap;
    }

    private List<Map<String, Object>> collectImportReferences(
            Program program,
            List<Function> matchingImports,
            Map<Function, List<Function>> thunkMap,
            int maxResults) {

        List<Map<String, Object>> references = new ArrayList<>();
        ReferenceManager refManager = program.getReferenceManager();
        FunctionManager funcManager = program.getFunctionManager();
        Set<Address> seen = new HashSet<>();

        for (Function importFunc : matchingImports) {
            if (references.size() >= maxResults) break;

            // Collect all addresses to check: the import and its thunks
            List<AddressWithThunkInfo> targets = new ArrayList<>();

            Address importAddr = importFunc.getEntryPoint();
            if (importAddr != null) {
                targets.add(new AddressWithThunkInfo(importAddr, null));
            }

            List<Function> thunks = thunkMap.get(importFunc);
            if (thunks != null) {
                for (Function thunk : thunks) {
                    Address thunkAddr = thunk.getEntryPoint();
                    if (thunkAddr != null) {
                        targets.add(new AddressWithThunkInfo(thunkAddr, thunkAddr));
                    }
                }
            }

            // Get references to all targets
            for (AddressWithThunkInfo target : targets) {
                if (references.size() >= maxResults) break;

                ReferenceIterator refIter = refManager.getReferencesTo(target.address);
                while (refIter.hasNext() && references.size() < maxResults) {
                    Reference ref = refIter.next();
                    Address fromAddr = ref.getFromAddress();

                    if (seen.contains(fromAddr)) continue;
                    seen.add(fromAddr);

                    Map<String, Object> refInfo = new HashMap<>();
                    refInfo.put("fromAddress", AddressUtil.formatAddress(fromAddr));
                    refInfo.put("referenceType", ref.getReferenceType().toString());
                    refInfo.put("isCall", ref.getReferenceType().isCall());

                    Function containingFunc = funcManager.getFunctionContaining(fromAddr);
                    if (containingFunc != null) {
                        refInfo.put("function", containingFunc.getName());
                        refInfo.put("functionAddress",
                            AddressUtil.formatAddress(containingFunc.getEntryPoint()));
                    }

                    refInfo.put("importName", importFunc.getName());
                    ExternalLocation extLoc = importFunc.getExternalLocation();
                    if (extLoc != null) {
                        refInfo.put("library", extLoc.getLibraryName());
                    }

                    if (target.thunkAddress != null) {
                        refInfo.put("viaThunk", true);
                        refInfo.put("thunkAddress", AddressUtil.formatAddress(target.thunkAddress));
                    }

                    references.add(refInfo);
                }
            }
        }

        return references;
    }

    private List<Map<String, Object>> buildThunkChain(Function function) {
        List<Map<String, Object>> chain = new ArrayList<>();
        Function current = function;
        int depth = 0;

        while (current != null && depth < MAX_THUNK_CHAIN_DEPTH) {
            Map<String, Object> info = new HashMap<>();
            info.put("name", current.getName());
            Address entryPoint = current.getEntryPoint();
            if (entryPoint != null) {
                info.put("address", AddressUtil.formatAddress(entryPoint));
            }
            info.put("isThunk", current.isThunk());
            info.put("isExternal", current.isExternal());

            if (current.isExternal()) {
                ExternalLocation extLoc = current.getExternalLocation();
                if (extLoc != null) {
                    info.put("library", extLoc.getLibraryName());
                    String origName = extLoc.getOriginalImportedName();
                    if (origName != null) {
                        info.put("originalName", origName);
                    }
                }
            }

            chain.add(info);

            if (current.isThunk()) {
                Function next = current.getThunkedFunction(false);
                if (next != null && !next.equals(current)) {
                    current = next;
                    depth++;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        return chain;
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    private Map<String, Object> buildImportInfo(Function importFunc) {
        Map<String, Object> info = new HashMap<>();
        info.put("name", importFunc.getName());

        Address entryPoint = importFunc.getEntryPoint();
        if (entryPoint != null) {
            info.put("address", AddressUtil.formatAddress(entryPoint));
        }

        ExternalLocation extLoc = importFunc.getExternalLocation();
        if (extLoc != null) {
            info.put("library", extLoc.getLibraryName());
        }

        return info;
    }

    private List<Map<String, Object>> groupImportsByLibrary(List<Map<String, Object>> imports) {
        Map<String, List<Map<String, Object>>> grouped = new LinkedHashMap<>();
        for (Map<String, Object> imp : imports) {
            String library = (String) imp.get("library");
            grouped.computeIfAbsent(library, k -> new ArrayList<>()).add(imp);
        }

        List<Map<String, Object>> result = new ArrayList<>();
        for (Map.Entry<String, List<Map<String, Object>>> entry : grouped.entrySet()) {
            result.add(Map.of(
                "name", entry.getKey(),
                "importCount", entry.getValue().size(),
                "imports", entry.getValue()
            ));
        }
        return result;
    }

    private <T> List<T> paginate(List<T> list, int startIndex, int maxResults) {
        if (startIndex >= list.size()) {
            return new ArrayList<>();
        }
        int endIndex = Math.min(startIndex + maxResults, list.size());
        return new ArrayList<>(list.subList(startIndex, endIndex));
    }

    private int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(value, max));
    }

    // Simple record to hold address with optional thunk info
    private record AddressWithThunkInfo(Address address, Address thunkAddress) {}
}
