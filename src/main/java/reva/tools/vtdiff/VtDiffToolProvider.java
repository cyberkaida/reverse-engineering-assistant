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
package reva.tools.vtdiff;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTAssociationManager;
import ghidra.feature.vt.api.main.VTAssociationStatus;
import ghidra.feature.vt.api.main.VTAssociationType;
import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.api.main.VTMarkupItemStatus;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTScore;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.feature.vt.gui.task.ApplyMarkupItemTask;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.options.ToolOptions;
import ghidra.util.task.TimeoutTaskMonitor;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.ConfigManager;
import reva.services.BinaryDiffService;
import reva.tools.AbstractToolProvider;
import reva.tools.ProgramValidationException;
import reva.util.AddressUtil;
import reva.util.RevaInternalServiceRegistry;

/**
 * Tier 2 (VT-backed diff) and Tier 3 (analysis migration) tools. Operates on a
 * persistent {@link VTSession} stored in the project under {@code /VTSessions/}.
 *
 * <p>This provider uses {@code sourceProgramPath} / {@code destinationProgramPath}
 * as parameter names because the migration workflow has a meaningful direction:
 * markup flows from source (analyzed) to destination (new sample). Tier 1 cheap
 * diff tools use the symmetric {@code programA} / {@code programB} convention.</p>
 */
public class VtDiffToolProvider extends AbstractToolProvider {

    public VtDiffToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerCompareProgramsTool();
        registerListChangedFunctionsTool();
        registerListChangedDataTool();
        registerGetFunctionDiffTool();
        registerListMigrationCandidatesTool();
        registerMigrateFunctionAnalysisTool();
        registerMigrateAnalysisTool();
        registerListVtSessionsTool();
        registerDeleteVtSessionTool();
    }

    // ========================================================================
    // compare-programs
    // ========================================================================

    private void registerCompareProgramsTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("sourceProgramPath", Map.of(
            "type", "string",
            "description", "Path to the source program — typically the previously-analyzed binary "
                + "whose markup (names, types, comments) you want to migrate from."
        ));
        properties.put("destinationProgramPath", Map.of(
            "type", "string",
            "description", "Path to the destination program — the new/unknown binary you want to "
                + "annotate. Markup will be applied here when migrate-analysis is called."
        ));
        properties.put("reuseExisting", Map.of(
            "type", "boolean",
            "description", "If a session for this program pair already exists, reopen it instead of "
                + "running correlators again. Default true.",
            "default", true
        ));
        properties.put("aggressive", Map.of(
            "type", "boolean",
            "description", "Loosen correlator score/confidence thresholds to find more (possibly "
                + "lower-quality) matches. Default false (AutoVT defaults).",
            "default", false
        ));
        properties.put("correlatorOptions", Map.of(
            "type", "object",
            "description", "Advanced: raw key/value overrides forwarded to ToolOptions. Keys must "
                + "match VTOptionDefines constants. Unstable contract — prefer 'aggressive'."
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("compare-programs")
            .title("Compare Two Programs (Version Tracking)")
            .description("Create or reuse a Version Tracking session between two programs and run "
                + "correlators (exact symbol/data/function-byte/instruction matchers, plus "
                + "reference-based correlators if seeds exist) to identify matched functions and data. "
                + "Returns a sessionPath used by list-changed-functions, get-function-diff, and the "
                + "migrate-* tools. Idempotent by default — re-running on the same pair reuses the "
                + "existing session unless reuseExisting=false.")
            .inputSchema(createSchema(properties, List.of("sourceProgramPath", "destinationProgramPath")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program source = getProgramByKey(request.arguments(), "sourceProgramPath");
            Program destination = getProgramByKey(request.arguments(), "destinationProgramPath");
            boolean reuseExisting = getOptionalBoolean(request, "reuseExisting", true);
            boolean aggressive = getOptionalBoolean(request, "aggressive", false);
            Map<String, Object> correlatorOptions =
                getOptionalMap(request.arguments(), "correlatorOptions", Map.of());

            BinaryDiffService service = service();
            ProjectData projectData = source.getDomainFile().getParent().getProjectData();

            Optional<DomainFile> existing = service.findSession(projectData, source, destination);
            boolean reused = existing.isPresent() && reuseExisting;

            VTSession session = null;
            try {
                if (reused) {
                    session = service.openSession(existing.get(), this);
                    // Basename-collision guard: two programs in different folders can produce the
                    // same deterministic session name. Validate the opened session actually maps
                    // to this (source, destination) pair; if not, fall through to create a new one
                    // (createSession's uniqueSessionName picks the -2 suffix).
                    String openedSrc = session.getSourceProgram().getDomainFile().getPathname();
                    String openedDst = session.getDestinationProgram().getDomainFile().getPathname();
                    String wantedSrc = source.getDomainFile().getPathname();
                    String wantedDst = destination.getDomainFile().getPathname();
                    if (!openedSrc.equals(wantedSrc) || !openedDst.equals(wantedDst)) {
                        service.closeSession(session, this);
                        session = null;
                        reused = false;
                    }
                }
                if (!reused) {
                    if (existing.isPresent() && !reuseExisting) {
                        // Caller explicitly wants a fresh run; delete the old session first to
                        // avoid name-collision suffixing. (When reused was reset to false by the
                        // basename-collision guard above, reuseExisting is still true — leave the
                        // existing session alone, it belongs to a different program pair.)
                        service.deleteSession(projectData, existing.get().getPathname());
                    }
                    session = service.createSession(projectData, source, destination, this);
                    ToolOptions opts = service.buildAutoVtOptions(aggressive, correlatorOptions);
                    service.runAutoVt(session, opts, TaskMonitor.DUMMY);
                    session.save();
                }
                return createJsonResult(buildSummaryResult(session, reused, source, destination));
            } catch (Exception e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                }
                throw new RuntimeException("compare-programs failed: " + e.getMessage(), e);
            } finally {
                if (session != null) {
                    service.closeSession(session, this);
                }
            }
        });
    }

    // ========================================================================
    // list-changed-functions
    // ========================================================================

    private void registerListChangedFunctionsTool() {
        registerListChangedTool("list-changed-functions",
            "List Changed Functions",
            "List function-level differences between the two programs in a Version Tracking session. "
                + "Use category to filter: 'matched' = functions paired by correlators, 'unmatched-source' "
                + "= functions only in the source program (removed in destination), 'unmatched-destination' "
                + "= functions only in the destination program (NEW in destination — typically the LLM's "
                + "primary target for variant analysis), 'all' = everything tagged with category. "
                + "Paginated; default 100/page.",
            VTAssociationType.FUNCTION);
    }

    private void registerListChangedDataTool() {
        registerListChangedTool("list-changed-data",
            "List Changed Data",
            "List data-level differences between the two programs in a Version Tracking session. "
                + "Same category semantics as list-changed-functions but covers defined data (strings, "
                + "structures, lookup tables, etc.). Useful for spotting changed config blocks or new "
                + "embedded data.",
            VTAssociationType.DATA);
    }

    private void registerListChangedTool(String name, String title, String description,
            VTAssociationType type) {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("sessionPath", Map.of(
            "type", "string",
            "description", "Path to the VT session domain file (returned by compare-programs)."
        ));
        properties.put("category", Map.of(
            "type", "string",
            "description", "Filter: 'matched', 'unmatched-source', 'unmatched-destination', or 'all'.",
            "default", "all"
        ));
        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Pagination offset.",
            "default", 0
        ));
        properties.put("maxCount", Map.of(
            "type", "integer",
            "description", "Max entries to return (default 100).",
            "default", 100
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name(name)
            .title(title)
            .description(description)
            .inputSchema(createSchema(properties, List.of("sessionPath")))
            .build();

        registerTool(tool, (exchange, request) -> {
            String sessionPath = getString(request, "sessionPath");
            String category = getOptionalString(request, "category", "all").toLowerCase();
            int startIndex = Math.max(0, getOptionalInt(request, "startIndex", 0));
            int maxCount = Math.max(1, Math.min(getOptionalInt(request, "maxCount", 100), 1000));

            BinaryDiffService service = service();
            ProjectData projectData = activeProjectData();
            DomainFile sessionFile = projectData.getFile(sessionPath);
            if (sessionFile == null) {
                throw new IllegalArgumentException("VT session not found at " + sessionPath
                    + ". Call compare-programs first to create a session.");
            }

            VTSession session = null;
            try {
                session = service.openSession(sessionFile, this);
                List<Map<String, Object>> entries = collectChangedEntries(session, type, category);

                List<Map<String, Object>> page = paginate(entries, startIndex, maxCount);
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("sessionPath", sessionPath);
                result.put("category", category);
                result.put("totalCount", entries.size());
                result.put("startIndex", startIndex);
                result.put("returnedCount", page.size());
                result.put("hasMore", startIndex + page.size() < entries.size());
                result.put(type == VTAssociationType.FUNCTION ? "functions" : "dataItems", page);
                return createJsonResult(result);
            } catch (Exception e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                }
                throw new RuntimeException(e.getMessage(), e);
            } finally {
                if (session != null) {
                    service.closeSession(session, this);
                }
            }
        });
    }

    /**
     * Collect entries for the given association type and category. Sourced from accepted
     * VT associations plus enumeration of unmatched program-side functions/data.
     */
    private List<Map<String, Object>> collectChangedEntries(VTSession session,
            VTAssociationType type, String category) {
        Program source = session.getSourceProgram();
        Program destination = session.getDestinationProgram();

        // Build dedup index of (srcAddr, dstAddr) pairs we've seen, keeping the highest-similarity entry.
        Map<String, Map<String, Object>> matchedByPair = new LinkedHashMap<>();
        Set<Address> matchedSrcAddrs = new HashSet<>();
        Set<Address> matchedDstAddrs = new HashSet<>();

        for (VTMatchSet matchSet : session.getMatchSets()) {
            String correlatorName = matchSet.getProgramCorrelatorInfo().getName();
            for (VTMatch match : matchSet.getMatches()) {
                VTAssociation assoc = match.getAssociation();
                if (assoc.getType() != type) {
                    continue;
                }
                if (assoc.getStatus() != VTAssociationStatus.ACCEPTED) {
                    continue;
                }
                Address srcAddr = assoc.getSourceAddress();
                Address dstAddr = assoc.getDestinationAddress();
                String key = srcAddr + "->" + dstAddr;
                Map<String, Object> existing = matchedByPair.get(key);
                double thisScore = scoreOf(match.getSimilarityScore());
                if (existing == null || thisScore > ((Number) existing.getOrDefault("similarityScore", -1.0)).doubleValue()) {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("category", "matched");
                    entry.put("sourceAddress", AddressUtil.formatAddress(srcAddr));
                    entry.put("destinationAddress", AddressUtil.formatAddress(dstAddr));
                    entry.put("sourceName", nameAt(source, srcAddr, type));
                    entry.put("destinationName", nameAt(destination, dstAddr, type));
                    entry.put("similarityScore", thisScore);
                    entry.put("confidenceScore", scoreOf(match.getConfidenceScore()));
                    entry.put("matchedBy", correlatorName);
                    matchedByPair.put(key, entry);
                }
                matchedSrcAddrs.add(srcAddr);
                matchedDstAddrs.add(dstAddr);
            }
        }

        List<Map<String, Object>> result = new ArrayList<>();
        boolean wantMatched = category.equals("all") || category.equals("matched");
        boolean wantUnmatchedSource = category.equals("all") || category.equals("unmatched-source");
        boolean wantUnmatchedDest = category.equals("all") || category.equals("unmatched-destination");

        if (wantMatched) {
            result.addAll(matchedByPair.values());
        }
        if (wantUnmatchedSource && type == VTAssociationType.FUNCTION) {
            result.addAll(unmatchedFunctions(source, matchedSrcAddrs, "unmatched-source", true));
        }
        if (wantUnmatchedDest && type == VTAssociationType.FUNCTION) {
            result.addAll(unmatchedFunctions(destination, matchedDstAddrs, "unmatched-destination", false));
        }
        return result;
    }

    private List<Map<String, Object>> unmatchedFunctions(Program program, Set<Address> matchedAddrs,
            String category, boolean isSource) {
        List<Map<String, Object>> entries = new ArrayList<>();
        FunctionIterator iter = program.getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            if (f.isExternal() || f.isThunk()) {
                continue;
            }
            if (matchedAddrs.contains(f.getEntryPoint())) {
                continue;
            }
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("category", category);
            String sideKey = isSource ? "sourceAddress" : "destinationAddress";
            String nameKey = isSource ? "sourceName" : "destinationName";
            entry.put(sideKey, AddressUtil.formatAddress(f.getEntryPoint()));
            entry.put(nameKey, f.getName());
            entry.put("bodySize", f.getBody().getNumAddresses());
            entries.add(entry);
        }
        return entries;
    }

    // ========================================================================
    // get-function-diff
    // ========================================================================

    private void registerGetFunctionDiffTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("sessionPath", Map.of(
            "type", "string",
            "description", "Path to the VT session domain file (returned by compare-programs)."
        ));
        properties.put("sourceAddress", Map.of(
            "type", "string",
            "description", "Address of the function in the source program (hex or symbol)."
        ));
        properties.put("includeDecompilation", Map.of(
            "type", "boolean",
            "description", "Include decompiled C for both sides. Default false — start with the structural "
                + "summary, only opt in when you need the actual code. The LLM should usually call "
                + "get-decompilation on each program directly for this; this flag exists for one-shot "
                + "comparisons.",
            "default", false
        ));
        properties.put("sourceOffset", Map.of(
            "type", "integer",
            "description", "Source decompilation: line offset (1-based). Default 1.",
            "default", 1
        ));
        properties.put("sourceLimit", Map.of(
            "type", "integer",
            "description", "Source decompilation: max lines. Default 50.",
            "default", 50
        ));
        properties.put("destinationOffset", Map.of(
            "type", "integer",
            "description", "Destination decompilation: line offset (1-based). Default 1.",
            "default", 1
        ));
        properties.put("destinationLimit", Map.of(
            "type", "integer",
            "description", "Destination decompilation: max lines. Default 50.",
            "default", 50
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-function-diff")
            .title("Get Function Diff")
            .description("For a matched function pair from a VT session, return the SHAPE of the "
                + "difference: similarity/confidence scores, basic-block and instruction counts on each "
                + "side, and the set of callees only present on each side. Decompilation is opt-in via "
                + "includeDecompilation; default response is small and structured so the LLM can decide "
                + "whether to drill in. To get full decompilation use get-decompilation on each program.")
            .inputSchema(createSchema(properties, List.of("sessionPath", "sourceAddress")))
            .build();

        registerTool(tool, (exchange, request) -> {
            String sessionPath = getString(request, "sessionPath");
            String sourceAddrStr = getString(request, "sourceAddress");
            boolean includeDecompilation = getOptionalBoolean(request, "includeDecompilation", false);
            int srcOffset = Math.max(1, getOptionalInt(request, "sourceOffset", 1));
            int srcLimit = Math.max(1, getOptionalInt(request, "sourceLimit", 50));
            int dstOffset = Math.max(1, getOptionalInt(request, "destinationOffset", 1));
            int dstLimit = Math.max(1, getOptionalInt(request, "destinationLimit", 50));

            BinaryDiffService service = service();
            ProjectData projectData = activeProjectData();
            DomainFile sessionFile = projectData.getFile(sessionPath);
            if (sessionFile == null) {
                throw new IllegalArgumentException("VT session not found at " + sessionPath
                    + ". Call compare-programs first.");
            }

            VTSession session = null;
            try {
                session = service.openSession(sessionFile, this);
                Program source = session.getSourceProgram();
                Program destination = session.getDestinationProgram();

                Address srcAddr = getAddressFromArgs(request.arguments(), source, "sourceAddress");

                VTAssociationManager am = session.getAssociationManager();
                Collection<VTAssociation> related = am.getRelatedAssociationsBySourceAddress(srcAddr);
                // get-function-diff uses the permissive picker — AVAILABLE matches are still
                // useful to inspect; the response's match.status field tells the LLM whether
                // the match was accepted by AutoVT or is a lower-confidence candidate.
                VTAssociation chosen = pickAnyFunctionAssociation(related);
                if (chosen == null) {
                    throw new IllegalArgumentException(
                        "No function association at source address " + sourceAddrStr
                        + ". Use list-changed-functions to find matched pairs.");
                }

                Address dstAddr = chosen.getDestinationAddress();
                Function srcFn = source.getFunctionManager().getFunctionAt(srcAddr);
                Function dstFn = destination.getFunctionManager().getFunctionAt(dstAddr);
                if (srcFn == null || dstFn == null) {
                    throw new IllegalArgumentException(
                        "Function lookup failed for matched pair " + srcAddr + " <-> " + dstAddr);
                }

                Map<String, Object> result = buildFunctionDiffSummary(session, chosen, srcFn, dstFn);
                if (includeDecompilation) {
                    result.put("sourceDecompilation",
                        decompilationSlice(source, srcFn, srcOffset, srcLimit));
                    result.put("destinationDecompilation",
                        decompilationSlice(destination, dstFn, dstOffset, dstLimit));
                }
                return createJsonResult(result);
            } catch (Exception e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                }
                throw new RuntimeException(e.getMessage(), e);
            } finally {
                if (session != null) {
                    service.closeSession(session, this);
                }
            }
        });
    }

    /**
     * Used by {@code get-function-diff}: prefer ACCEPTED, fall back to any FUNCTION
     * association (e.g., AVAILABLE) so the LLM can still inspect a candidate match.
     * The caller's response includes the actual {@code status} so the LLM can see
     * whether the match was accepted.
     */
    private VTAssociation pickAnyFunctionAssociation(Collection<VTAssociation> candidates) {
        for (VTAssociation a : candidates) {
            if (a.getType() == VTAssociationType.FUNCTION
                    && a.getStatus() == VTAssociationStatus.ACCEPTED) {
                return a;
            }
        }
        for (VTAssociation a : candidates) {
            if (a.getType() == VTAssociationType.FUNCTION) {
                return a;
            }
        }
        return null;
    }

    /**
     * Used by {@code migrate-function-analysis}: only ACCEPTED or AVAILABLE.
     * Rejecting BLOCKED/REJECTED associations is correct — the migration tool
     * accepts AVAILABLE (and applies markup) but should never silently revive
     * a previously rejected match.
     */
    private VTAssociation pickMigrationFunctionAssociation(Collection<VTAssociation> candidates) {
        for (VTAssociation a : candidates) {
            if (a.getType() != VTAssociationType.FUNCTION) {
                continue;
            }
            VTAssociationStatus s = a.getStatus();
            if (s == VTAssociationStatus.ACCEPTED || s == VTAssociationStatus.AVAILABLE) {
                return a;
            }
        }
        return null;
    }

    private Map<String, Object> buildFunctionDiffSummary(VTSession session, VTAssociation assoc,
            Function srcFn, Function dstFn) {
        // Match metadata (highest-scoring match across all match sets touching this association)
        VTMatch best = null;
        for (VTMatch m : session.getMatches(assoc)) {
            if (best == null || scoreOf(m.getSimilarityScore()) > scoreOf(best.getSimilarityScore())) {
                best = m;
            }
        }

        Map<String, Object> match = new LinkedHashMap<>();
        match.put("status", assoc.getStatus().toString());
        match.put("sourceAddress", AddressUtil.formatAddress(assoc.getSourceAddress()));
        match.put("destinationAddress", AddressUtil.formatAddress(assoc.getDestinationAddress()));
        match.put("sourceName", srcFn.getName());
        match.put("destinationName", dstFn.getName());
        if (best != null) {
            match.put("similarityScore", scoreOf(best.getSimilarityScore()));
            match.put("confidenceScore", scoreOf(best.getConfidenceScore()));
        }

        Map<String, Object> structural = new LinkedHashMap<>();
        FunctionStats srcStats = analyzeFunction(srcFn);
        FunctionStats dstStats = analyzeFunction(dstFn);
        structural.put("basicBlockCountSource", srcStats.basicBlocks);
        structural.put("basicBlockCountDestination", dstStats.basicBlocks);
        structural.put("instructionCountSource", srcStats.instructions);
        structural.put("instructionCountDestination", dstStats.instructions);
        structural.put("bodySizeSource", srcFn.getBody().getNumAddresses());
        structural.put("bodySizeDestination", dstFn.getBody().getNumAddresses());

        // Callee-name set difference. Names are address-independent so this is a
        // robust LLM-readable summary even when call-targets resolve to different addresses.
        Set<String> srcCallees = calleeNames(srcFn);
        Set<String> dstCallees = calleeNames(dstFn);
        Set<String> onlyInSource = new LinkedHashSet<>(srcCallees);
        onlyInSource.removeAll(dstCallees);
        Set<String> onlyInDest = new LinkedHashSet<>(dstCallees);
        onlyInDest.removeAll(srcCallees);
        structural.put("calleesOnlyInSource", new ArrayList<>(onlyInSource));
        structural.put("calleesOnlyInDestination", new ArrayList<>(onlyInDest));
        structural.put("commonCalleeCount", srcCallees.size() - onlyInSource.size());

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("sessionPath", session.getDomainFile().getPathname());
        result.put("match", match);
        result.put("structuralDelta", structural);
        return result;
    }

    private record FunctionStats(int basicBlocks, int instructions) {}

    private FunctionStats analyzeFunction(Function fn) {
        Program p = fn.getProgram();
        AddressSetView body = fn.getBody();
        int instr = 0;
        InstructionIterator instIter = p.getListing().getInstructions(body, true);
        while (instIter.hasNext()) {
            instIter.next();
            instr++;
        }
        int blocks = 0;
        try {
            BasicBlockModel bbm = new BasicBlockModel(p);
            CodeBlockIterator bbIter = bbm.getCodeBlocksContaining(body, TaskMonitor.DUMMY);
            while (bbIter.hasNext()) {
                @SuppressWarnings("unused")
                CodeBlock cb = bbIter.next();
                blocks++;
            }
        } catch (Exception e) {
            // Leave blocks at 0 on any model failure
        }
        return new FunctionStats(blocks, instr);
    }

    private Set<String> calleeNames(Function fn) {
        Set<String> names = new LinkedHashSet<>();
        for (Function callee : fn.getCalledFunctions(TaskMonitor.DUMMY)) {
            names.add(callee.getName());
        }
        return names;
    }

    private Map<String, Object> decompilationSlice(Program program, Function fn, int offset, int limit) {
        Map<String, Object> result = new LinkedHashMap<>();
        DecompInterface decompiler = new DecompInterface();
        // Honour the project-wide decompiler timeout from ConfigManager (matches the convention
        // used by DecompilerToolProvider and others). Fall back to 30s if the service is absent.
        ConfigManager config = RevaInternalServiceRegistry.getService(ConfigManager.class);
        int timeoutSeconds = (config != null) ? config.getDecompilerTimeoutSeconds() : 30;
        try {
            decompiler.openProgram(program);
            DecompileResults dr = decompiler.decompileFunction(fn, timeoutSeconds,
                TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS));
            if (!dr.decompileCompleted()) {
                result.put("error", "decompilation failed: " + dr.getErrorMessage());
                return result;
            }
            String full = dr.getDecompiledFunction().getC();
            String[] allLines = full.split("\n", -1);
            int startIdx = Math.max(0, offset - 1);
            int endIdx = Math.min(allLines.length, startIdx + limit);
            List<String> lines = new ArrayList<>(endIdx - startIdx);
            for (int i = startIdx; i < endIdx; i++) {
                lines.add(allLines[i]);
            }
            result.put("totalLines", allLines.length);
            result.put("offset", offset);
            result.put("returnedLines", lines.size());
            result.put("hasMore", endIdx < allLines.length);
            result.put("lines", lines);
        } finally {
            decompiler.dispose();
        }
        return result;
    }

    // ========================================================================
    // list-migration-candidates
    // ========================================================================

    private void registerListMigrationCandidatesTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("sessionPath", Map.of(
            "type", "string",
            "description", "Path to the VT session domain file (returned by compare-programs)."
        ));
        properties.put("startIndex", Map.of(
            "type", "integer",
            "default", 0
        ));
        properties.put("maxCount", Map.of(
            "type", "integer",
            "description", "Max candidates to return (default 100).",
            "default", 100
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-migration-candidates")
            .title("List Migration Candidates")
            .description("List VT associations that are AVAILABLE (not yet accepted) and could be "
                + "migrated. compare-programs runs AutoVT which auto-accepts high-confidence matches "
                + "and applies their markup; remaining AVAILABLE associations are lower-confidence "
                + "candidates the LLM can review and selectively accept via migrate-function-analysis.")
            .inputSchema(createSchema(properties, List.of("sessionPath")))
            .build();

        registerTool(tool, (exchange, request) -> {
            String sessionPath = getString(request, "sessionPath");
            int startIndex = Math.max(0, getOptionalInt(request, "startIndex", 0));
            int maxCount = Math.max(1, Math.min(getOptionalInt(request, "maxCount", 100), 1000));

            BinaryDiffService service = service();
            DomainFile sessionFile = activeProjectData().getFile(sessionPath);
            if (sessionFile == null) {
                throw new IllegalArgumentException("VT session not found at " + sessionPath);
            }
            VTSession session = null;
            try {
                session = service.openSession(sessionFile, this);
                List<Map<String, Object>> candidates = collectMigrationCandidates(session);

                List<Map<String, Object>> page = paginate(candidates, startIndex, maxCount);
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("sessionPath", sessionPath);
                result.put("totalCount", candidates.size());
                result.put("startIndex", startIndex);
                result.put("returnedCount", page.size());
                result.put("hasMore", startIndex + page.size() < candidates.size());
                result.put("candidates", page);
                return createJsonResult(result);
            } catch (Exception e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                }
                throw new RuntimeException(e.getMessage(), e);
            } finally {
                if (session != null) {
                    service.closeSession(session, this);
                }
            }
        });
    }

    private List<Map<String, Object>> collectMigrationCandidates(VTSession session) {
        Program source = session.getSourceProgram();
        Program destination = session.getDestinationProgram();
        Map<String, Map<String, Object>> byPair = new LinkedHashMap<>();

        for (VTMatchSet matchSet : session.getMatchSets()) {
            String correlatorName = matchSet.getProgramCorrelatorInfo().getName();
            for (VTMatch match : matchSet.getMatches()) {
                VTAssociation assoc = match.getAssociation();
                if (assoc.getStatus() != VTAssociationStatus.AVAILABLE) {
                    continue;
                }
                String key = assoc.getSourceAddress() + "->" + assoc.getDestinationAddress();
                Map<String, Object> existing = byPair.get(key);
                double thisScore = scoreOf(match.getSimilarityScore());
                if (existing == null
                        || thisScore > ((Number) existing.getOrDefault("similarityScore", -1.0)).doubleValue()) {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("type", assoc.getType().toString());
                    entry.put("sourceAddress", AddressUtil.formatAddress(assoc.getSourceAddress()));
                    entry.put("destinationAddress", AddressUtil.formatAddress(assoc.getDestinationAddress()));
                    entry.put("sourceName", nameAt(source, assoc.getSourceAddress(), assoc.getType()));
                    entry.put("destinationName", nameAt(destination, assoc.getDestinationAddress(), assoc.getType()));
                    entry.put("similarityScore", thisScore);
                    entry.put("confidenceScore", scoreOf(match.getConfidenceScore()));
                    entry.put("matchedBy", correlatorName);
                    byPair.put(key, entry);
                }
            }
        }
        return new ArrayList<>(byPair.values());
    }

    // ========================================================================
    // migrate-function-analysis
    // ========================================================================

    private void registerMigrateFunctionAnalysisTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("sessionPath", Map.of(
            "type", "string",
            "description", "Path to the VT session domain file."
        ));
        properties.put("sourceAddress", Map.of(
            "type", "string",
            "description", "Address (or symbol) in the source program identifying the function pair."
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("migrate-function-analysis")
            .title("Migrate Single Function Analysis")
            .description("Accept the function-level VT association at sourceAddress (if AVAILABLE) and "
                + "apply its markup (function name, signature, parameters, comments, datatypes) to "
                + "the destination program. Idempotent — re-applying already-applied markup is a no-op.")
            .inputSchema(createSchema(properties, List.of("sessionPath", "sourceAddress")))
            .build();

        registerTool(tool, (exchange, request) -> {
            String sessionPath = getString(request, "sessionPath");
            String sourceAddrStr = getString(request, "sourceAddress");

            BinaryDiffService service = service();
            DomainFile sessionFile = activeProjectData().getFile(sessionPath);
            if (sessionFile == null) {
                throw new IllegalArgumentException("VT session not found at " + sessionPath);
            }

            VTSession session = null;
            try {
                session = service.openSession(sessionFile, this);
                Program source = session.getSourceProgram();
                Address srcAddr = getAddressFromArgs(request.arguments(), source, "sourceAddress");

                Collection<VTAssociation> related =
                    session.getAssociationManager().getRelatedAssociationsBySourceAddress(srcAddr);
                // migrate-function-analysis uses the strict picker — never silently revives
                // a BLOCKED or REJECTED association. AVAILABLE is acceptable; setAccepted()
                // is called inside migrateAssociation.
                VTAssociation assoc = pickMigrationFunctionAssociation(related);
                if (assoc == null) {
                    throw new IllegalArgumentException(
                        "No function association at source address " + sourceAddrStr
                        + " in ACCEPTED or AVAILABLE state. Use list-migration-candidates.");
                }

                MigrationResult mr = migrateAssociation(session, assoc);
                session.save();
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", true);
                result.put("sessionPath", sessionPath);
                result.put("sourceAddress", AddressUtil.formatAddress(assoc.getSourceAddress()));
                result.put("destinationAddress", AddressUtil.formatAddress(assoc.getDestinationAddress()));
                result.put("status", assoc.getStatus().toString());
                result.put("markupItemsApplied", mr.applied);
                result.put("markupItemsSkipped", mr.skipped);
                result.put("markupItemsFailed", mr.failed);
                return createJsonResult(result);
            } catch (Exception e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                }
                throw new RuntimeException(e.getMessage(), e);
            } finally {
                if (session != null) {
                    service.closeSession(session, this);
                }
            }
        });
    }

    // ========================================================================
    // migrate-analysis
    // ========================================================================

    private void registerMigrateAnalysisTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("sessionPath", Map.of(
            "type", "string",
            "description", "Path to the VT session domain file."
        ));
        properties.put("acceptAvailable", Map.of(
            "type", "boolean",
            "description", "If true, accept AVAILABLE associations (without competing accepted "
                + "siblings) and apply their markup. Default false — only re-apply markup for "
                + "already-ACCEPTED associations.",
            "default", false
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("migrate-analysis")
            .title("Migrate All Analysis")
            .description("Bulk-apply VT markup across the entire session. By default operates only "
                + "on already-ACCEPTED associations (re-application is a no-op for already-applied "
                + "items). Set acceptAvailable=true to also accept lower-confidence AVAILABLE "
                + "associations and apply their markup. Returns aggregate counts.")
            .inputSchema(createSchema(properties, List.of("sessionPath")))
            .build();

        registerTool(tool, (exchange, request) -> {
            String sessionPath = getString(request, "sessionPath");
            boolean acceptAvailable = getOptionalBoolean(request, "acceptAvailable", false);

            BinaryDiffService service = service();
            DomainFile sessionFile = activeProjectData().getFile(sessionPath);
            if (sessionFile == null) {
                throw new IllegalArgumentException("VT session not found at " + sessionPath);
            }

            VTSession session = null;
            try {
                session = service.openSession(sessionFile, this);
                MigrationResult totals = new MigrationResult();
                int functionsTouched = 0;

                Set<String> seenPairs = new HashSet<>();
                for (VTMatchSet matchSet : session.getMatchSets()) {
                    for (VTMatch match : matchSet.getMatches()) {
                        VTAssociation assoc = match.getAssociation();
                        String key = assoc.getSourceAddress() + "->" + assoc.getDestinationAddress();
                        if (!seenPairs.add(key)) {
                            continue;
                        }
                        VTAssociationStatus status = assoc.getStatus();
                        if (status == VTAssociationStatus.BLOCKED
                                || status == VTAssociationStatus.REJECTED) {
                            continue;
                        }
                        if (status == VTAssociationStatus.AVAILABLE && !acceptAvailable) {
                            continue;
                        }
                        try {
                            MigrationResult mr = migrateAssociation(session, assoc);
                            totals.applied += mr.applied;
                            totals.skipped += mr.skipped;
                            totals.failed += mr.failed;
                            functionsTouched++;
                        } catch (RuntimeException e) {
                            totals.failed++;
                        }
                    }
                }

                // Persist association-status and markup-status changes to the session DB.
                // Without this, accept() and apply() bookkeeping is lost on closeSession.
                session.save();

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", true);
                result.put("sessionPath", sessionPath);
                result.put("associationsTouched", functionsTouched);
                result.put("markupItemsApplied", totals.applied);
                result.put("markupItemsSkipped", totals.skipped);
                result.put("markupItemsFailed", totals.failed);
                return createJsonResult(result);
            } catch (Exception e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                }
                throw new RuntimeException(e.getMessage(), e);
            } finally {
                if (session != null) {
                    service.closeSession(session, this);
                }
            }
        });
    }

    /**
     * Accumulator for {@link #migrateAssociation(VTSession, VTAssociation)} results.
     */
    private static final class MigrationResult {
        int applied;
        int skipped;
        int failed;
    }

    /**
     * Accept the association if AVAILABLE, then apply any unapplied markup items
     * via {@link ApplyMarkupItemTask}. Wrapped in a session transaction.
     */
    private MigrationResult migrateAssociation(VTSession session, VTAssociation assoc) throws Exception {
        MigrationResult mr = new MigrationResult();
        int txId = session.startTransaction("ReVa: migrate analysis");
        boolean ok = false;
        try {
            if (assoc.getStatus() == VTAssociationStatus.AVAILABLE) {
                try {
                    assoc.setAccepted();
                } catch (Exception e) {
                    mr.failed++;
                    ok = true; // commit the empty txn
                    return mr;
                }
            }
            if (assoc.getStatus() != VTAssociationStatus.ACCEPTED) {
                mr.skipped++;
                ok = true;
                return mr;
            }

            Collection<VTMarkupItem> items = assoc.getMarkupItems(TaskMonitor.DUMMY);
            List<VTMarkupItem> unapplied = new ArrayList<>();
            for (VTMarkupItem item : items) {
                VTMarkupItemStatus status = item.getStatus();
                if (status == VTMarkupItemStatus.UNAPPLIED) {
                    unapplied.add(item);
                } else {
                    mr.skipped++;
                }
            }
            if (!unapplied.isEmpty()) {
                ApplyMarkupItemTask task = new ApplyMarkupItemTask(session, unapplied,
                    new VTOptions("ReVa migrate"));
                task.run(TaskMonitor.DUMMY);
                // Recount by post-apply status — the task's hasErrors() flag tells us
                // SOME failed but not how many, and a subset of items may have applied
                // before the failure point. Inspect each item's final status instead.
                int appliedCount = 0;
                int failedCount = 0;
                for (VTMarkupItem item : unapplied) {
                    VTMarkupItemStatus s = item.getStatus();
                    if (s == VTMarkupItemStatus.UNAPPLIED) {
                        failedCount++;
                    } else {
                        appliedCount++;
                    }
                }
                mr.applied += appliedCount;
                mr.failed += failedCount;
            }
            ok = true;
            return mr;
        } finally {
            session.endTransaction(txId, ok);
        }
    }

    // ========================================================================
    // list-vt-sessions
    // ========================================================================

    private void registerListVtSessionsTool() {
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-vt-sessions")
            .title("List VT Sessions")
            .description("List all Version Tracking sessions stored in the project under /VTSessions/. "
                + "Each entry includes the session path and the source/destination program paths so the "
                + "LLM can pick the right one without re-running compare-programs.")
            .inputSchema(createSchema(new LinkedHashMap<>(), List.of()))
            .build();

        registerTool(tool, (exchange, request) -> {
            BinaryDiffService service = service();
            List<DomainFile> files = service.listSessions(activeProjectData());
            List<Map<String, Object>> entries = new ArrayList<>(files.size());
            for (DomainFile file : files) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("sessionPath", file.getPathname());
                entry.put("name", file.getName());
                entries.add(entry);
            }
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("sessionsFolder", BinaryDiffService.SESSIONS_FOLDER);
            result.put("count", entries.size());
            result.put("sessions", entries);
            return createJsonResult(result);
        });
    }

    // ========================================================================
    // delete-vt-session
    // ========================================================================

    private void registerDeleteVtSessionTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("sessionPath", Map.of(
            "type", "string",
            "description", "Path to the VT session to delete."
        ));
        properties.put("confirm", Map.of(
            "type", "boolean",
            "description", "Required confirmation. Must be true to actually delete."
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("delete-vt-session")
            .title("Delete VT Session")
            .description("Delete a Version Tracking session domain file from the project. Requires "
                + "confirm=true. NOTE: this does NOT roll back any markup that was already applied to "
                + "the destination program; that lives in the destination program's own undo stack.")
            .inputSchema(createSchema(properties, List.of("sessionPath", "confirm")))
            .build();

        registerTool(tool, (exchange, request) -> {
            String sessionPath = getString(request, "sessionPath");
            boolean confirm = getOptionalBoolean(request, "confirm", false);
            if (!confirm) {
                throw new IllegalArgumentException(
                    "delete-vt-session requires confirm=true to actually delete the session.");
            }
            BinaryDiffService service = service();
            try {
                boolean deleted = service.deleteSession(activeProjectData(), sessionPath);
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", deleted);
                result.put("sessionPath", sessionPath);
                result.put("deleted", deleted);
                if (!deleted) {
                    result.put("note", "Session was not present at the given path.");
                }
                return createJsonResult(result);
            } catch (java.io.IOException e) {
                throw new RuntimeException("Failed to delete session: " + e.getMessage(), e);
            }
        });
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    private BinaryDiffService service() {
        BinaryDiffService svc = RevaInternalServiceRegistry.getService(BinaryDiffService.class);
        if (svc == null) {
            throw new IllegalStateException(
                "BinaryDiffService not registered — server initialization may be incomplete");
        }
        return svc;
    }

    private Program getProgramByKey(Map<String, Object> args, String key) throws ProgramValidationException {
        return getValidatedProgram(getString(args, key));
    }

    /**
     * Resolve the active project's {@link ProjectData} for session-path lookups.
     * Uses {@link AppInfo#getActiveProject()} so we don't depend on a program
     * being opened in any tool — sessions live in the project, not in tools.
     */
    private ProjectData activeProjectData() {
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            throw new IllegalStateException(
                "No active Ghidra project — open a project before invoking VT-backed tools.");
        }
        return project.getProjectData();
    }

    private static double scoreOf(VTScore score) {
        return score == null ? 0.0 : score.getScore();
    }

    private static String nameAt(Program p, Address addr, VTAssociationType type) {
        if (type == VTAssociationType.FUNCTION) {
            Function f = p.getFunctionManager().getFunctionAt(addr);
            if (f != null) {
                return f.getName();
            }
        }
        ghidra.program.model.symbol.Symbol s = p.getSymbolTable().getPrimarySymbol(addr);
        return (s != null) ? s.getName() : AddressUtil.formatAddress(addr);
    }

    private static <T> List<T> paginate(List<T> all, int startIndex, int maxCount) {
        if (startIndex >= all.size()) {
            return List.of();
        }
        int end = Math.min(startIndex + maxCount, all.size());
        return new ArrayList<>(all.subList(startIndex, end));
    }

    /**
     * Build the {@code compare-programs} response: session location, source/dest
     * program identification, and aggregate match counts.
     */
    private Map<String, Object> buildSummaryResult(VTSession session, boolean reused,
            Program source, Program destination) {
        int totalMatches = 0;
        int totalAccepted = 0;
        int totalFunctionMatches = 0;
        int acceptedFunctionMatches = 0;
        int totalDataMatches = 0;
        int acceptedDataMatches = 0;

        for (VTMatchSet matchSet : session.getMatchSets()) {
            for (VTMatch match : matchSet.getMatches()) {
                totalMatches++;
                VTAssociation assoc = match.getAssociation();
                boolean accepted = assoc.getStatus() == VTAssociationStatus.ACCEPTED;
                if (accepted) {
                    totalAccepted++;
                }
                if (assoc.getType() == VTAssociationType.FUNCTION) {
                    totalFunctionMatches++;
                    if (accepted) {
                        acceptedFunctionMatches++;
                    }
                } else if (assoc.getType() == VTAssociationType.DATA) {
                    totalDataMatches++;
                    if (accepted) {
                        acceptedDataMatches++;
                    }
                }
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("sessionPath", session.getDomainFile().getPathname());
        result.put("status", reused ? "reused" : "created");
        result.put("sourceProgramPath", source.getDomainFile().getPathname());
        result.put("destinationProgramPath", destination.getDomainFile().getPathname());
        result.put("totalMatches", totalMatches);
        result.put("totalAccepted", totalAccepted);
        result.put("totalFunctionMatches", totalFunctionMatches);
        result.put("acceptedFunctionMatches", acceptedFunctionMatches);
        result.put("totalDataMatches", totalDataMatches);
        result.put("acceptedDataMatches", acceptedDataMatches);
        return result;
    }
}
