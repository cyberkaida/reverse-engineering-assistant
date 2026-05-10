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
package reva.tools.cheapdiff;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.tools.ProgramValidationException;
import reva.util.AddressUtil;
import reva.util.SymbolUtil;

/**
 * Tier 1 binary-diff tools that compare two programs without requiring a Version
 * Tracking session. These tools operate on per-program metadata that can be
 * compared via simple set operations or field-by-field equality.
 *
 * <p>Convention: dual-program parameters are {@code programA} and {@code programB}
 * — symmetric, no implied direction. (The migration tools use
 * {@code sourceProgramPath}/{@code destinationProgramPath} where direction is
 * semantically meaningful.)</p>
 */
public class CheapDiffToolProvider extends AbstractToolProvider {

    public CheapDiffToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerDiffProgramMetadataTool();
        registerDiffSectionsTool();
        registerDiffSymbolsTool();
        registerDiffExportsTool();
        registerDiffStringsTool();
        registerDiffImportsTool();
    }

    // ========================================================================
    // diff-program-metadata
    // ========================================================================

    private void registerDiffProgramMetadataTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("programA", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the first program (no implied direction)"
        ));
        properties.put("programB", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the second program (no implied direction)"
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-program-metadata")
            .title("Diff Program Metadata")
            .description("Compare top-level metadata of two programs — architecture, compiler, image base, "
                + "executable format, size, etc. Use this BEFORE compare-programs to confirm two binaries "
                + "are sensibly comparable. A languageId mismatch means Version Tracking will refuse to "
                + "correlate them; an imageBase mismatch means address-aligned diffs will be noise.")
            .inputSchema(createSchema(properties, List.of("programA", "programB")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program a = getProgramByKey(request.arguments(), "programA");
            Program b = getProgramByKey(request.arguments(), "programB");

            Map<String, Object> metaA = collectProgramMetadata(a);
            Map<String, Object> metaB = collectProgramMetadata(b);

            List<Map<String, Object>> differences = computeDifferences(metaA, metaB);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programA", metaA);
            result.put("programB", metaB);
            result.put("differences", differences);
            result.put("identical", differences.isEmpty());
            return createJsonResult(result);
        });
    }

    // ========================================================================
    // diff-sections
    // ========================================================================

    private void registerDiffSectionsTool() {
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-sections")
            .title("Diff Memory Sections")
            .description("Compare memory blocks (sections/segments) of two programs by block name. "
                + "Returns blocks only in A, only in B, and in both. Use to spot newly added or removed "
                + "sections (e.g., a new resource section, a packed section).")
            .inputSchema(createSchema(twoProgramSchemaProperties(), List.of("programA", "programB")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program a = getProgramByKey(request.arguments(), "programA");
            Program b = getProgramByKey(request.arguments(), "programB");
            return createJsonResult(buildSetDiff(a, b, collectSections(a), collectSections(b)));
        });
    }

    private Map<String, Map<String, Object>> collectSections(Program p) {
        Map<String, Map<String, Object>> result = new LinkedHashMap<>();
        for (MemoryBlock block : p.getMemory().getBlocks()) {
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("name", block.getName());
            info.put("start", AddressUtil.formatAddress(block.getStart()));
            info.put("size", block.getSize());
            info.put("permissions", permissionString(block));
            info.put("initialized", block.isInitialized());
            result.put(block.getName(), info);
        }
        return result;
    }

    private static String permissionString(MemoryBlock b) {
        StringBuilder sb = new StringBuilder(3);
        sb.append(b.isRead() ? 'r' : '-');
        sb.append(b.isWrite() ? 'w' : '-');
        sb.append(b.isExecute() ? 'x' : '-');
        return sb.toString();
    }

    // ========================================================================
    // diff-symbols
    // ========================================================================

    private void registerDiffSymbolsTool() {
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-symbols")
            .title("Diff User Symbols")
            .description("Compare user-defined named symbols (labels, functions, namespaces) of two "
                + "programs by name. Default Ghidra-generated names (FUN_*, DAT_*, LAB_*) are excluded "
                + "so renames stand out. Use to find newly named functions in B that don't exist in A.")
            .inputSchema(createSchema(twoProgramSchemaProperties(), List.of("programA", "programB")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program a = getProgramByKey(request.arguments(), "programA");
            Program b = getProgramByKey(request.arguments(), "programB");
            return createJsonResult(buildSetDiff(a, b, collectUserSymbols(a), collectUserSymbols(b)));
        });
    }

    private Map<String, Map<String, Object>> collectUserSymbols(Program p) {
        Map<String, Map<String, Object>> result = new LinkedHashMap<>();
        SymbolTable st = p.getSymbolTable();
        SymbolIterator iter = st.getDefinedSymbols();
        while (iter.hasNext()) {
            Symbol s = iter.next();
            String name = s.getName();
            if (SymbolUtil.isDefaultSymbolName(name)) {
                continue;
            }
            // Use the primary symbol per name; if multiple symbols share a name we keep the first.
            if (result.containsKey(name)) {
                continue;
            }
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("name", name);
            info.put("address", AddressUtil.formatAddress(s.getAddress()));
            info.put("type", s.getSymbolType().toString());
            info.put("source", s.getSource().toString());
            result.put(name, info);
        }
        return result;
    }

    // ========================================================================
    // diff-exports
    // ========================================================================

    private void registerDiffExportsTool() {
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-exports")
            .title("Diff Exports")
            .description("Compare exported symbols (external entry points) of two programs by name. "
                + "Useful for libraries/DLLs to spot newly added or removed export interfaces.")
            .inputSchema(createSchema(twoProgramSchemaProperties(), List.of("programA", "programB")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program a = getProgramByKey(request.arguments(), "programA");
            Program b = getProgramByKey(request.arguments(), "programB");
            return createJsonResult(buildSetDiff(a, b, collectExports(a), collectExports(b)));
        });
    }

    private Map<String, Map<String, Object>> collectExports(Program p) {
        Map<String, Map<String, Object>> result = new LinkedHashMap<>();
        SymbolTable st = p.getSymbolTable();
        AddressIterator entryPoints = st.getExternalEntryPointIterator();
        while (entryPoints.hasNext()) {
            Address addr = entryPoints.next();
            Symbol s = st.getPrimarySymbol(addr);
            String name = (s != null) ? s.getName() : ("entry_" + AddressUtil.formatAddress(addr));
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("name", name);
            info.put("address", AddressUtil.formatAddress(addr));
            if (s != null) {
                info.put("symbolType", s.getSymbolType().toString());
            }
            result.put(name, info);
        }
        return result;
    }

    // ========================================================================
    // diff-strings
    // ========================================================================

    private void registerDiffStringsTool() {
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-strings")
            .title("Diff Defined Strings")
            .description("Compare defined string literals of two programs by string value. Strings only "
                + "in B are highly diagnostic for malware variant analysis (new C2 hostnames, new config "
                + "keys, new error messages). Strings only in A may indicate removed functionality.")
            .inputSchema(createSchema(twoProgramSchemaProperties(), List.of("programA", "programB")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program a = getProgramByKey(request.arguments(), "programA");
            Program b = getProgramByKey(request.arguments(), "programB");
            return createJsonResult(buildSetDiff(a, b, collectStrings(a), collectStrings(b)));
        });
    }

    private Map<String, Map<String, Object>> collectStrings(Program p) {
        Map<String, Map<String, Object>> result = new LinkedHashMap<>();
        DataIterator dataIter = p.getListing().getDefinedData(true);
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            if (!StringDataInstance.isString(data)) {
                continue;
            }
            String value = StringDataInstance.getStringDataInstance(data).getStringValue();
            if (value == null || value.isEmpty()) {
                continue;
            }
            // First-occurrence wins on duplicate values.
            if (result.containsKey(value)) {
                continue;
            }
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("value", value);
            info.put("address", AddressUtil.formatAddress(data.getAddress()));
            info.put("length", value.length());
            result.put(value, info);
        }
        return result;
    }

    // ========================================================================
    // diff-imports
    // ========================================================================

    private void registerDiffImportsTool() {
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-imports")
            .title("Diff Imports")
            .description("Compare imported external functions (IAT entries) of two programs. Newly "
                + "imported APIs in B (e.g., WinHttpOpen, CryptEncrypt) often reveal new capabilities.")
            .inputSchema(createSchema(twoProgramSchemaProperties(), List.of("programA", "programB")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program a = getProgramByKey(request.arguments(), "programA");
            Program b = getProgramByKey(request.arguments(), "programB");
            return createJsonResult(buildSetDiff(a, b, collectImports(a), collectImports(b)));
        });
    }

    private Map<String, Map<String, Object>> collectImports(Program p) {
        Map<String, Map<String, Object>> result = new LinkedHashMap<>();
        FunctionIterator iter = p.getFunctionManager().getExternalFunctions();
        while (iter.hasNext()) {
            Function f = iter.next();
            ExternalLocation loc = f.getExternalLocation();
            String library = (loc != null) ? loc.getLibraryName() : "<unknown>";
            String name = f.getName();
            String key = library + "!" + name;
            if (result.containsKey(key)) {
                continue;
            }
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("name", name);
            info.put("library", library);
            if (loc != null && loc.getOriginalImportedName() != null
                    && !loc.getOriginalImportedName().equals(name)) {
                info.put("originalName", loc.getOriginalImportedName());
            }
            result.put(key, info);
        }
        return result;
    }

    // ========================================================================
    // Shared helpers
    // ========================================================================

    private Map<String, Object> twoProgramSchemaProperties() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("programA", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the first program (no implied direction)"
        ));
        properties.put("programB", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the second program (no implied direction)"
        ));
        return properties;
    }

    /**
     * Compute the set difference of two key→info maps and assemble the standard
     * three-bucket response: {@code onlyInA} / {@code onlyInB} / {@code inBoth}.
     * For {@code inBoth} entries the A-side info object is used, augmented with
     * {@code addressB} when both sides have an {@code address}.
     */
    private Map<String, Object> buildSetDiff(Program a, Program b,
            Map<String, Map<String, Object>> mapA, Map<String, Map<String, Object>> mapB) {
        List<Map<String, Object>> onlyInA = new ArrayList<>();
        List<Map<String, Object>> onlyInB = new ArrayList<>();
        List<Map<String, Object>> inBoth = new ArrayList<>();

        for (Map.Entry<String, Map<String, Object>> entry : mapA.entrySet()) {
            Map<String, Object> bEntry = mapB.get(entry.getKey());
            if (bEntry == null) {
                onlyInA.add(entry.getValue());
            } else {
                Map<String, Object> merged = new LinkedHashMap<>(entry.getValue());
                Object addrB = bEntry.get("address");
                if (addrB != null && merged.containsKey("address")) {
                    Object addrA = merged.remove("address");
                    merged.put("addressA", addrA);
                    merged.put("addressB", addrB);
                }
                inBoth.add(merged);
            }
        }
        for (Map.Entry<String, Map<String, Object>> entry : mapB.entrySet()) {
            if (!mapA.containsKey(entry.getKey())) {
                onlyInB.add(entry.getValue());
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("programA", a.getDomainFile().getPathname());
        result.put("programB", b.getDomainFile().getPathname());
        result.put("onlyInA", onlyInA);
        result.put("onlyInB", onlyInB);
        result.put("inBoth", inBoth);
        result.put("countOnlyInA", onlyInA.size());
        result.put("countOnlyInB", onlyInB.size());
        result.put("countInBoth", inBoth.size());
        return result;
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    /**
     * Resolve a {@link Program} from an arguments map under an arbitrary key.
     * The base-class helper {@code getProgramFromArgs} only handles the standard
     * {@code programPath} parameter; diff tools take {@code programA}/{@code programB}.
     */
    private Program getProgramByKey(Map<String, Object> args, String key) throws ProgramValidationException {
        String path = getString(args, key);
        return getValidatedProgram(path);
    }

    /**
     * Build a metadata map for a single program. Order is preserved (LinkedHashMap)
     * so the JSON output is stable and easy to scan.
     */
    private Map<String, Object> collectProgramMetadata(Program program) {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("programPath", program.getDomainFile().getPathname());
        meta.put("name", program.getName());
        meta.put("languageId", program.getLanguageID().getIdAsString());
        meta.put("compilerSpecId", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        meta.put("processor", program.getLanguage().getProcessor().toString());
        meta.put("addressSize", program.getAddressFactory().getDefaultAddressSpace().getSize());
        meta.put("imageBase", AddressUtil.formatAddress(program.getImageBase()));
        meta.put("executableFormat", String.valueOf(program.getExecutableFormat()));
        meta.put("executableMD5", String.valueOf(program.getExecutableMD5()));
        meta.put("executableSHA256", String.valueOf(program.getExecutableSHA256()));
        meta.put("creationDate", String.valueOf(program.getCreationDate()));
        meta.put("functionCount", program.getFunctionManager().getFunctionCount());
        meta.put("symbolCount", program.getSymbolTable().getNumSymbols());
        meta.put("memoryBlockCount", program.getMemory().getBlocks().length);
        return meta;
    }

    /**
     * Compute the set of fields whose values differ between the two metadata maps.
     * Both maps share the same key set (built by {@link #collectProgramMetadata}),
     * so we iterate one and compare.
     */
    private List<Map<String, Object>> computeDifferences(Map<String, Object> a, Map<String, Object> b) {
        List<Map<String, Object>> differences = new ArrayList<>();
        for (Map.Entry<String, Object> entry : a.entrySet()) {
            String field = entry.getKey();
            // programPath and name will always differ between two programs — skip them.
            if ("programPath".equals(field) || "name".equals(field)) {
                continue;
            }
            Object valueA = entry.getValue();
            Object valueB = b.get(field);
            if (!Objects.equals(valueA, valueB)) {
                Map<String, Object> diff = new LinkedHashMap<>();
                diff.put("field", field);
                diff.put("valueA", valueA);
                diff.put("valueB", valueB);
                differences.add(diff);
            }
        }
        return differences;
    }
}
