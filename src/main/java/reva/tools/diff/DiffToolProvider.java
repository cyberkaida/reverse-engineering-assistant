package reva.tools.diff;

import java.io.IOException;
import java.util.*;

import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;

import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import reva.services.DiffJob;
import reva.services.DiffJobKind;
import reva.services.DiffJobManager;
import reva.services.JobLog;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.RevaInternalServiceRegistry;
import reva.util.VersionTrackingUtil;
import reva.util.VersionTrackingUtil.MatchInfo;

/** MCP tools for diffing two programs via Ghidra Version Tracking. */
public class DiffToolProvider extends AbstractToolProvider {

    public DiffToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerCreateSessionTool();
        registerSummaryTool();
        registerListFunctionsTool();
        registerFunctionDiffTool();
        registerStringsTool();
        registerDataTool();
        registerTransferMarkupTool();
        registerApplyMatchTool();
        registerListSessionsTool();
        registerDeleteSessionTool();
        registerStatusTool();
        registerCancelTool();
    }

    // ---- diff-list-sessions / diff-delete-session ----------------------

    private void registerListSessionsTool() {
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-list-sessions")
            .title("List Diff Sessions")
            .description("List cached diff sessions (source/destination pairs and the correlators run).")
            .inputSchema(createSchema(new HashMap<>(), List.of()))
            .build();
        registerTool(tool, (exchange, request) -> {
            List<Map<String, Object>> sessions = new ArrayList<>();
            for (DiffSession ds : DiffSessionManager.list()) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("sourceProgramPath", ds.sourcePath);
                row.put("destinationProgramPath", ds.destinationPath);
                row.put("correlatorsRun", ds.correlatorsRun);
                sessions.add(row);
            }
            return createJsonResult(Map.of("success", true, "sessions", sessions));
        });
    }

    private void registerDeleteSessionTool() {
        Map<String, Object> properties = new HashMap<>();
        putPairProperties(properties);
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-delete-session")
            .title("Delete Diff Session")
            .description("Drop a cached diff session so the next create-session re-correlates fresh.")
            .inputSchema(createSchema(properties, List.of("sourceProgramPath", "destinationProgramPath")))
            .build();
        registerTool(tool, (exchange, request) -> {
            String srcPath = getString(request, "sourceProgramPath");
            String dstPath = getString(request, "destinationProgramPath");
            boolean deleted = DiffSessionManager.delete(srcPath, dstPath);
            return createJsonResult(Map.of("success", true, "deleted", deleted));
        });
    }

    // ---- shared helpers -------------------------------------------------

    /** Resolve the cached DiffSession for the source/dest paths in the request. */
    private DiffSession requireSession(CallToolRequest request) {
        String srcPath = getString(request, "sourceProgramPath");
        String dstPath = getString(request, "destinationProgramPath");
        DiffSession ds = DiffSessionManager.get(srcPath, dstPath);
        if (ds == null) {
            throw new IllegalArgumentException("No diff session for source '" + srcPath
                + "' and destination '" + dstPath + "'. Run diff-create-session first.");
        }
        return ds;
    }

    /** Standard pair-of-paths schema fields, reused by every diff tool. */
    private void putPairProperties(Map<String, Object> properties) {
        properties.put("sourceProgramPath", Map.of("type", "string",
            "description", "Project path of the trusted/analyzed/old program (markup flows FROM here)."));
        properties.put("destinationProgramPath", Map.of("type", "string",
            "description", "Project path of the variant/new/patched program (markup flows TO here; changes are relative to source)."));
    }

    /** Reject programs with zero functions (likely unanalyzed). */
    private void requireAnalyzed(Program program) {
        if (program.getFunctionManager().getFunctionCount() == 0) {
            throw new IllegalArgumentException("Program '" + program.getDomainFile().getPathname()
                + "' has no functions — analyze it before diffing (ReVa does not auto-analyze).");
        }
    }

    /**
     * Resolved callee-name delta for a matched pair: which called symbols were added
     * or removed between source and destination. {@code changed} is true when the sets
     * differ. This catches changes VT scores as identical — above all a relocation-only
     * patch (identical instruction bytes, one swapped call target). See
     * {@link VersionTrackingUtil#calleeNames}.
     */
    private Map<String, Object> calleeDelta(DiffSession ds, MatchInfo mi) {
        java.util.SortedSet<String> src =
            VersionTrackingUtil.calleeNames(ds.sourceProgram, mi.sourceAddress, TaskMonitor.DUMMY);
        java.util.SortedSet<String> dst =
            VersionTrackingUtil.calleeNames(ds.destinationProgram, mi.destinationAddress, TaskMonitor.DUMMY);
        List<String> added = new ArrayList<>();
        for (String s : dst) if (!src.contains(s)) added.add(s);
        List<String> removed = new ArrayList<>();
        for (String s : src) if (!dst.contains(s)) removed.add(s);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("changed", !added.isEmpty() || !removed.isEmpty());
        out.put("added", added);
        out.put("removed", removed);
        return out;
    }

    /** Number of bytes in a function's body (address-independent: a shifted but
     *  unchanged function has the same size). 0 if no function at {@code entry}. */
    private int functionSize(Program program, Address entry) {
        ghidra.program.model.listing.Function fn =
            program.getFunctionManager().getFunctionAt(entry);
        return fn != null ? (int) fn.getBody().getNumAddresses() : 0;
    }

    /** Raw instruction bytes over a function's body, in address order (empty on error). */
    private byte[] functionBytes(Program program, Address entry) {
        ghidra.program.model.listing.Function fn =
            program.getFunctionManager().getFunctionAt(entry);
        if (fn == null) return new byte[0];
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (ghidra.program.model.address.AddressRange range : fn.getBody()) {
            int len = (int) range.getLength();
            byte[] buf = new byte[len];
            try {
                program.getMemory().getBytes(range.getMinAddress(), buf);
                out.write(buf, 0, len);
            } catch (ghidra.program.model.mem.MemoryAccessException e) {
                return new byte[0];
            }
        }
        return out.toByteArray();
    }

    /** True if the matched pair's raw body bytes differ. Address-DEPENDENT: reliable on
     *  relocatable objects (.ko — functions at the same address) but noisy on fully-linked
     *  images where unchanged functions shift, so this is an opt-in recall signal. */
    private boolean bodyBytesDiffer(DiffSession ds, MatchInfo mi) {
        if (functionSize(ds.sourceProgram, mi.sourceAddress)
                != functionSize(ds.destinationProgram, mi.destinationAddress)) {
            return true;
        }
        return !java.util.Arrays.equals(
            functionBytes(ds.sourceProgram, mi.sourceAddress),
            functionBytes(ds.destinationProgram, mi.destinationAddress));
    }

    /**
     * Typed difference profile for one matched pair. Rather than a single changed/identical
     * verdict from one configuration, we surface orthogonal signals and let the agent
     * interpret: {@code changeTypes} lists which lenses fired —
     * <ul>
     *   <li>{@code similarity} — VT structural similarity below the identical threshold</li>
     *   <li>{@code callees} — the resolved callee symbol-name set changed (call-target swap;
     *       relocation-only patches)</li>
     *   <li>{@code size} — the function body grew or shrank (added/removed code)</li>
     *   <li>{@code body-bytes} — raw instruction bytes differ (operand/control-flow tweaks
     *       VT scores as identical; opt-in via {@code includeBodyBytes} because it is
     *       address-dependent and noisy on linked images)</li>
     * </ul>
     * similarity/callees/size are precision signals (address-independent, scale-safe) and
     * always evaluated; body-bytes is the recall knob. A pair is "changed" iff any type fired.
     */
    private Map<String, Object> changeProfile(DiffSession ds, MatchInfo mi, boolean includeBodyBytes) {
        List<String> types = new ArrayList<>();
        if (!mi.isIdentical()) types.add("similarity");
        Map<String, Object> callee = calleeDelta(ds, mi);
        if (Boolean.TRUE.equals(callee.get("changed"))) types.add("callees");
        int sizeDelta = functionSize(ds.destinationProgram, mi.destinationAddress)
            - functionSize(ds.sourceProgram, mi.sourceAddress);
        if (sizeDelta != 0) types.add("size");
        boolean bodyBytes = false;
        if (includeBodyBytes) {
            bodyBytes = bodyBytesDiffer(ds, mi);
            if (bodyBytes) types.add("body-bytes");
        }
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("changeTypes", types);
        p.put("sizeDelta", sizeDelta);
        if (Boolean.TRUE.equals(callee.get("changed"))) {
            p.put("calleeChanges", Map.of("added", callee.get("added"), "removed", callee.get("removed")));
        }
        if (includeBodyBytes) {
            p.put("bodyBytesChanged", bodyBytes);
        }
        return p;
    }

    @SuppressWarnings("unchecked")
    private boolean isChanged(Map<String, Object> profile) {
        return !((List<String>) profile.get("changeTypes")).isEmpty();
    }

    /** Build the summary-counts map shared by create-session and diff-summary. */
    private Map<String, Object> summarize(DiffSession ds, boolean includeBodyBytes) {
        List<MatchInfo> matches = VersionTrackingUtil.collectFunctionMatches(ds.vtSession);
        Set<Address> matchedSrc = new HashSet<>();
        Set<Address> matchedDst = new HashSet<>();
        int identical = 0, changed = 0;
        for (MatchInfo mi : matches) {
            matchedSrc.add(mi.sourceAddress);
            matchedDst.add(mi.destinationAddress);
            if (isChanged(changeProfile(ds, mi, includeBodyBytes))) changed++; else identical++;
        }
        int removed = VersionTrackingUtil.unmatchedFunctions(ds.sourceProgram, matchedSrc).size();
        int added = VersionTrackingUtil.unmatchedFunctions(ds.destinationProgram, matchedDst).size();

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("sourceProgramPath", ds.sourcePath);
        out.put("destinationProgramPath", ds.destinationPath);
        out.put("sourceFunctions", ds.sourceProgram.getFunctionManager().getFunctionCount());
        out.put("destinationFunctions", ds.destinationProgram.getFunctionManager().getFunctionCount());
        out.put("matched", Map.of("identical", identical, "changed", changed));
        out.put("unmatchedInSource", removed); // removed
        out.put("unmatchedInDestination", added);     // added
        out.put("correlatorsRun", ds.correlatorsRun);
        return out;
    }

    // ---- diff-summary --------------------------------------------------

    private void registerSummaryTool() {
        Map<String, Object> properties = new HashMap<>();
        putPairProperties(properties);
        properties.put("topN", Map.of("type", "integer",
            "description", "How many most-changed matched functions to include in the teaser.",
            "default", 10));
        properties.put("includeBodyByteChanges", Map.of("type", "boolean",
            "description", "Recall knob (default false). Also flag matched functions whose raw "
                + "instruction bytes differ — catches operand/control-flow tweaks that VT scores "
                + "as identical (changeType 'body-bytes'). Precise on relocatable objects (.ko); "
                + "noisy on fully-linked images where unchanged functions shift, so the "
                + "agent enables it deliberately and filters the residual.",
            "default", false));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-summary")
            .title("Binary Diff Summary")
            .description("Counts plus a ranked teaser of the most-changed matched functions, each "
                + "tagged with a changeTypes profile (similarity/callees/size, plus body-bytes when "
                + "includeBodyByteChanges=true). The 'what changed?' entry point.")
            .inputSchema(createSchema(properties, List.of("sourceProgramPath", "destinationProgramPath")))
            .build();

        registerTool(tool, (exchange, request) -> {
            DiffSession ds = requireSession(request);
            int topN = getOptionalInt(request, "topN", 10);
            boolean includeBodyBytes = getOptionalBoolean(request, "includeBodyByteChanges", false);

            Map<String, Object> out = new LinkedHashMap<>(summarize(ds, includeBodyBytes));

            // Recall-knob hint: when the precision lenses find nothing changed and the body-bytes
            // knob was off, point the agent at the knob so it doesn't conclude "no changes."
            @SuppressWarnings("unchecked")
            Map<String, Object> matched = (Map<String, Object>) out.get("matched");
            int changedCount = ((Number) matched.get("changed")).intValue();
            if (changedCount == 0 && !includeBodyBytes) {
                out.put("hint", "0 changed under the precision lenses (similarity/callees/size). "
                    + "Operand/control-flow tweaks that VT scores as identical are not counted here "
                    + "— set includeBodyByteChanges=true to also check raw instruction bytes (a recall "
                    + "knob; precise on relocatable .ko, noisier on fully-linked images).");
            }

            List<MatchInfo> matches = VersionTrackingUtil.collectFunctionMatches(ds.vtSession);
            matches.sort(Comparator.comparingDouble(m -> m.similarity)); // most-changed first
            List<Map<String, Object>> teaser = new ArrayList<>();
            for (MatchInfo mi : matches) {
                if (teaser.size() >= topN) break;
                Map<String, Object> profile = changeProfile(ds, mi, includeBodyBytes);
                if (!isChanged(profile)) continue;
                teaser.add(matchRow(ds, mi, profile));
            }
            out.put("mostChanged", teaser);
            return createJsonResult(out);
        });
    }

    // ---- diff-list-functions -------------------------------------------

    private void registerListFunctionsTool() {
        Map<String, Object> properties = new HashMap<>();
        putPairProperties(properties);
        properties.put("category", Map.of("type", "string",
            "description", "changed | added | removed | identical", "default", "changed"));
        properties.put("sortBy", Map.of("type", "string",
            "description", "similarity | name | address", "default", "similarity"));
        properties.put("startIndex", Map.of("type", "integer", "description", "Pagination start.", "default", 0));
        properties.put("maxCount", Map.of("type", "integer", "description", "Page size.", "default", 50));
        properties.put("includeBodyByteChanges", Map.of("type", "boolean",
            "description", "Recall knob (default false). Also treat matched functions whose raw "
                + "instruction bytes differ as changed (changeType 'body-bytes') — catches "
                + "operand/control-flow tweaks VT scores as identical. Precise on .ko; noisy on "
                + "linked images. Affects which rows land in the changed vs identical category.",
            "default", false));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-list-functions")
            .title("List Diffed Functions")
            .description("Paginated list of function diff rows for one category "
                + "(changed/added/removed/identical). Each matched row carries a changeTypes "
                + "profile (similarity/callees/size, plus body-bytes when includeBodyByteChanges=true), "
                + "sizeDelta, and any calleeChanges — no bodies.")
            .inputSchema(createSchema(properties, List.of("sourceProgramPath", "destinationProgramPath")))
            .build();

        registerTool(tool, (exchange, request) -> {
            DiffSession ds = requireSession(request);
            String category = getOptionalString(request, "category", "changed");
            String sortBy = getOptionalString(request, "sortBy", "similarity");
            int start = getOptionalInt(request, "startIndex", 0);
            int max = getOptionalInt(request, "maxCount", 50);
            boolean includeBodyBytes = getOptionalBoolean(request, "includeBodyByteChanges", false);

            List<Map<String, Object>> rows = buildRows(ds, category, sortBy, includeBodyBytes);
            int end = Math.min(rows.size(), start + max);
            List<Map<String, Object>> page = start < rows.size()
                ? rows.subList(start, end) : List.of();

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("success", true);
            out.put("sourceProgramPath", ds.sourcePath);
            out.put("destinationProgramPath", ds.destinationPath);
            out.put("category", category);
            out.put("functions", new ArrayList<>(page));
            out.put("pagination", Map.of("startIndex", start, "returned", page.size(),
                "total", rows.size()));
            return createJsonResult(out);
        });
    }

    private List<Map<String, Object>> buildRows(DiffSession ds, String category, String sortBy,
            boolean includeBodyBytes) {
        List<MatchInfo> matches = VersionTrackingUtil.collectFunctionMatches(ds.vtSession);
        Set<ghidra.program.model.address.Address> matchedSrc = new HashSet<>();
        Set<ghidra.program.model.address.Address> matchedDst = new HashSet<>();
        for (MatchInfo mi : matches) { matchedSrc.add(mi.sourceAddress); matchedDst.add(mi.destinationAddress); }

        List<Map<String, Object>> rows = new ArrayList<>();
        if (category.equals("changed") || category.equals("identical")) {
            for (MatchInfo mi : matches) {
                Map<String, Object> profile = changeProfile(ds, mi, includeBodyBytes);
                boolean changed = isChanged(profile);
                if (category.equals("changed") && !changed) continue;
                if (category.equals("identical") && changed) continue;
                rows.add(matchRow(ds, mi, profile));
            }
        } else if (category.equals("removed")) {
            for (ghidra.program.model.listing.Function fn :
                    VersionTrackingUtil.unmatchedFunctions(ds.sourceProgram, matchedSrc))
                rows.add(unmatchedRow(fn, "source"));
        } else if (category.equals("added")) {
            for (ghidra.program.model.listing.Function fn :
                    VersionTrackingUtil.unmatchedFunctions(ds.destinationProgram, matchedDst))
                rows.add(unmatchedRow(fn, "destination"));
        } else {
            throw new IllegalArgumentException("Invalid category '" + category
                + "'. Must be changed | added | removed | identical.");
        }
        sortRows(rows, sortBy);
        return rows;
    }

    private Map<String, Object> matchRow(DiffSession ds, MatchInfo mi, Map<String, Object> profile) {
        ghidra.program.model.listing.Function sf =
            ds.sourceProgram.getFunctionManager().getFunctionAt(mi.sourceAddress);
        ghidra.program.model.listing.Function df =
            ds.destinationProgram.getFunctionManager().getFunctionAt(mi.destinationAddress);
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("sourceName", sf != null ? sf.getName() : null);
        r.put("sourceAddress", AddressUtil.formatAddress(mi.sourceAddress));
        r.put("destName", df != null ? df.getName() : null);
        r.put("destAddress", AddressUtil.formatAddress(mi.destinationAddress));
        r.put("similarity", mi.similarity);
        r.put("correlator", mi.correlatorName);
        // Typed difference profile: changeTypes + sizeDelta (+ calleeChanges / bodyBytesChanged).
        // The agent reads which lenses fired and decides whether/where to drill in.
        r.putAll(profile);
        return r;
    }

    private Map<String, Object> unmatchedRow(ghidra.program.model.listing.Function fn, String side) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("name", fn.getName());
        r.put("address", AddressUtil.formatAddress(fn.getEntryPoint()));
        r.put("side", side);
        return r;
    }

    private void sortRows(List<Map<String, Object>> rows, String sortBy) {
        Comparator<Map<String, Object>> c;
        switch (sortBy) {
            case "name": c = Comparator.comparing(r ->
                String.valueOf(r.getOrDefault("sourceName", r.get("name")))); break;
            case "address": c = Comparator.comparing(r ->
                String.valueOf(r.getOrDefault("sourceAddress", r.get("address")))); break;
            case "similarity":
            default: c = Comparator.comparingDouble(r ->
                r.get("similarity") instanceof Number n ? n.doubleValue() : 1.0); break;
        }
        rows.sort(c);
    }

    // ---- decompile helper -----------------------------------------------

    /**
     * Build a DecompInterface configured to match ReVa's get-decompilation behavior
     * (preserves unreachable code; see commit fb15188). Mirrors DecompilerToolProvider's
     * createConfiguredDecompiler. Returns null if the program fails to open.
     * Caller must dispose.
     */
    private ghidra.app.decompiler.DecompInterface configuredDecompiler(Program program) {
        ghidra.app.decompiler.DecompInterface decompiler = new ghidra.app.decompiler.DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        ghidra.app.decompiler.DecompileOptions options = new ghidra.app.decompiler.DecompileOptions();
        options.setEliminateUnreachable(false);
        decompiler.setOptions(options);

        if (!decompiler.openProgram(program)) {
            decompiler.dispose();
            return null;
        }
        return decompiler;
    }

    /** Configured decompiler timeout in seconds (falls back to 30 if the service is unavailable). */
    private int decompilerTimeoutSeconds() {
        reva.plugin.ConfigManager config =
            reva.util.RevaInternalServiceRegistry.getService(reva.plugin.ConfigManager.class);
        return config != null ? config.getDecompilerTimeoutSeconds() : 30;
    }

    /** Decompile a function to C text, or return null on failure. Disposes the interface. */
    private String decompileToText(Program program, ghidra.program.model.listing.Function fn) {
        ghidra.app.decompiler.DecompInterface decompiler = configuredDecompiler(program);
        if (decompiler == null) return null;
        try {
            ghidra.app.decompiler.DecompileResults res =
                decompiler.decompileFunction(fn, decompilerTimeoutSeconds(), TaskMonitor.DUMMY);
            if (!res.decompileCompleted()) return null;
            ghidra.app.decompiler.DecompiledFunction df = res.getDecompiledFunction();
            return df != null ? df.getC() : null;
        } finally {
            decompiler.dispose();
        }
    }

    // ---- diff-function --------------------------------------------------

    private void registerFunctionDiffTool() {
        Map<String, Object> properties = new HashMap<>();
        putPairProperties(properties);
        properties.put("function", Map.of("type", "string",
            "description", "Function name or address on EITHER side; the matched counterpart is resolved via the session."));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-function")
            .title("Diff One Function Pair")
            .description("Side-by-side decompiler diff for one matched function pair: changed-line "
                + "snippets, similarity, matching correlator, and both signatures.")
            .inputSchema(createSchema(properties,
                List.of("sourceProgramPath", "destinationProgramPath", "function")))
            .build();

        registerTool(tool, (exchange, request) -> {
            DiffSession ds = requireSession(request);
            String fnRef = getString(request, "function");

            MatchInfo match = resolveMatch(ds, fnRef);
            if (match == null) {
                return createErrorResult("No matched function pair found for '" + fnRef
                    + "'. It may be added/removed (use diff-list-functions) or unmatched.");
            }
            ghidra.program.model.listing.Function sf =
                ds.sourceProgram.getFunctionManager().getFunctionAt(match.sourceAddress);
            ghidra.program.model.listing.Function df =
                ds.destinationProgram.getFunctionManager().getFunctionAt(match.destinationAddress);
            if (sf == null || df == null) {
                return createErrorResult("Matched addresses no longer resolve to functions.");
            }
            String before = decompileToText(ds.sourceProgram, sf);
            if (before == null) {
                return createErrorResult("Decompilation failed or timed out for source function '" + sf.getName() + "'.");
            }
            String after = decompileToText(ds.destinationProgram, df);
            if (after == null) {
                return createErrorResult("Decompilation failed or timed out for destination function '" + df.getName() + "'.");
            }
            reva.util.DecompilationDiffUtil.DiffResult diff =
                reva.util.DecompilationDiffUtil.createDiff(before, after);

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("success", true);
            out.put("sourceProgramPath", ds.sourcePath);
            out.put("destinationProgramPath", ds.destinationPath);
            out.put("sourceName", sf.getName());
            out.put("sourceAddress", AddressUtil.formatAddress(match.sourceAddress));
            out.put("destName", df.getName());
            out.put("destAddress", AddressUtil.formatAddress(match.destinationAddress));
            out.put("similarity", match.similarity);
            out.put("correlator", match.correlatorName);
            out.put("sourceSignature", sf.getPrototypeString(true, false));
            out.put("destSignature", df.getPrototypeString(true, false));
            out.put("diff", reva.util.DecompilationDiffUtil.toMap(diff));
            // Full typed profile for the drilled-in pair (body-bytes included — cheap for one
            // function). changeTypes/sizeDelta/calleeChanges explain WHY it differs, including
            // relocation-only and operand-only patches the decompiled text alone may bury.
            out.putAll(changeProfile(ds, match, true));
            return createJsonResult(out);
        });
    }

    /** Find the function match whose source OR dest function matches the given name/address. */
    private MatchInfo resolveMatch(DiffSession ds, String fnRef) {
        ghidra.program.model.address.Address srcAddr =
            normalizeToEntry(ds.sourceProgram, tryResolve(ds.sourceProgram, fnRef));
        ghidra.program.model.address.Address dstAddr =
            normalizeToEntry(ds.destinationProgram, tryResolve(ds.destinationProgram, fnRef));
        for (MatchInfo mi : VersionTrackingUtil.collectFunctionMatches(ds.vtSession)) {
            if (srcAddr != null && mi.sourceAddress.equals(srcAddr)) return mi;
            if (dstAddr != null && mi.destinationAddress.equals(dstAddr)) return mi;
            ghidra.program.model.listing.Function sf =
                ds.sourceProgram.getFunctionManager().getFunctionAt(mi.sourceAddress);
            ghidra.program.model.listing.Function df =
                ds.destinationProgram.getFunctionManager().getFunctionAt(mi.destinationAddress);
            if (sf != null && sf.getName().equals(fnRef)) return mi;
            if (df != null && df.getName().equals(fnRef)) return mi;
        }
        return null;
    }

    private ghidra.program.model.address.Address tryResolve(Program p, String ref) {
        try { return AddressUtil.resolveAddressOrSymbol(p, ref); }
        catch (Exception e) { return null; }
    }

    /**
     * If {@code addr} falls inside a function, return that function's entry point so a
     * mid-function address still matches the match's (entry-point) source/dest address.
     * Returns {@code addr} unchanged if it is null or not within a function.
     */
    private ghidra.program.model.address.Address normalizeToEntry(
            Program p, ghidra.program.model.address.Address addr) {
        if (addr == null) return null;
        ghidra.program.model.listing.Function fn = p.getFunctionManager().getFunctionContaining(addr);
        return fn != null ? fn.getEntryPoint() : addr;
    }

    // ---- diff-strings / diff-data --------------------------------------

    /** Collect defined string values from a program (value -> address). If the same
     *  string value appears at multiple addresses, the last one wins — fine for an
     *  added/removed signal where the value, not its location, is what matters. */
    private Map<String, String> collectStrings(Program program) {
        Map<String, String> out = new LinkedHashMap<>();
        ghidra.program.model.listing.DataIterator it =
            program.getListing().getDefinedData(true);
        while (it.hasNext()) {
            ghidra.program.model.listing.Data d = it.next();
            // A defined datum is a string iff its value is a String; testing the value
            // directly avoids silently dropping string-typed data whose getValue() isn't.
            if (d.getValue() instanceof String s) {
                out.put(s, AddressUtil.formatAddress(d.getAddress()));
            }
        }
        return out;
    }

    /** Build added/removed (present on only one side) diff of two value->address maps. */
    private Map<String, Object> diffValueMaps(Map<String, String> srcVals, Map<String, String> dstVals) {
        List<Map<String, Object>> added = new ArrayList<>();
        List<Map<String, Object>> removed = new ArrayList<>();
        for (Map.Entry<String, String> e : dstVals.entrySet())
            if (!srcVals.containsKey(e.getKey()))
                added.add(Map.of("value", e.getKey(), "address", e.getValue()));
        for (Map.Entry<String, String> e : srcVals.entrySet())
            if (!dstVals.containsKey(e.getKey()))
                removed.add(Map.of("value", e.getKey(), "address", e.getValue()));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("added", added);
        out.put("removed", removed);
        return out;
    }

    private void registerStringsTool() {
        Map<String, Object> properties = new HashMap<>();
        putPairProperties(properties);
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-strings")
            .title("Diff Strings")
            .description("Added/removed defined strings between source and destination. "
                + "Signal for signature updates and C2/protocol changes.")
            .inputSchema(createSchema(properties, List.of("sourceProgramPath", "destinationProgramPath")))
            .build();
        registerTool(tool, (exchange, request) -> {
            DiffSession ds = requireSession(request);
            Map<String, Object> out = new LinkedHashMap<>(diffValueMaps(
                collectStrings(ds.sourceProgram), collectStrings(ds.destinationProgram)));
            out.put("success", true);
            out.put("sourceProgramPath", ds.sourcePath);
            out.put("destinationProgramPath", ds.destinationPath);
            return createJsonResult(out);
        });
    }

    private void registerDataTool() {
        Map<String, Object> properties = new HashMap<>();
        putPairProperties(properties);
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-data")
            .title("Diff Defined Data")
            .description("Added/removed defined data (by representation + address) between source and destination.")
            .inputSchema(createSchema(properties, List.of("sourceProgramPath", "destinationProgramPath")))
            .build();
        registerTool(tool, (exchange, request) -> {
            DiffSession ds = requireSession(request);
            Map<String, Object> out = new LinkedHashMap<>(diffValueMaps(
                collectDefinedData(ds.sourceProgram), collectDefinedData(ds.destinationProgram)));
            out.put("success", true);
            out.put("sourceProgramPath", ds.sourcePath);
            out.put("destinationProgramPath", ds.destinationPath);
            return createJsonResult(out);
        });
    }

    /** Defined non-string data as representation -> address. */
    private Map<String, String> collectDefinedData(Program program) {
        Map<String, String> out = new LinkedHashMap<>();
        ghidra.program.model.listing.DataIterator it = program.getListing().getDefinedData(true);
        while (it.hasNext()) {
            ghidra.program.model.listing.Data d = it.next();
            if (d.getValue() instanceof String) continue; // handled by diff-strings
            String repr = d.getDataType().getName() + "@" + AddressUtil.formatAddress(d.getAddress())
                + "=" + d.getDefaultValueRepresentation();
            out.put(repr, AddressUtil.formatAddress(d.getAddress()));
        }
        return out;
    }

    // ---- diff-transfer-markup ------------------------------------------

    /**
     * Apply VT markup from source to destination for every FUNCTION match at/above {@code floor},
     * collecting below-floor matches as proposals. Checks {@code monitor} between matches so the
     * job can be cancelled; throws CancelledException if cancelled mid-run.
     */
    private Map<String, Object> transferMarkup(DiffSession ds, double floor, TaskMonitor monitor)
            throws CancelledException {
        ghidra.framework.options.ToolOptions applyOpts = VersionTrackingUtil.defaultApplyOptions();

        Map<String, ghidra.feature.vt.api.main.VTMatch> best = new LinkedHashMap<>();
        for (ghidra.feature.vt.api.main.VTMatchSet ms : ds.vtSession.getMatchSets()) {
            for (ghidra.feature.vt.api.main.VTMatch m : ms.getMatches()) {
                if (m.getAssociation().getType() != ghidra.feature.vt.api.main.VTAssociationType.FUNCTION) continue;
                String key = m.getAssociation().getSourceAddress() + " "
                    + m.getAssociation().getDestinationAddress();
                ghidra.feature.vt.api.main.VTMatch prev = best.get(key);
                if (prev == null || m.getSimilarityScore().getScore() > prev.getSimilarityScore().getScore())
                    best.put(key, m);
            }
        }

        List<Map<String, Object>> applied = new ArrayList<>();
        List<Map<String, Object>> skipped = new ArrayList<>();
        List<Map<String, Object>> proposed = new ArrayList<>();
        Program dest = ds.destinationProgram;
        int sTx = ds.vtSession.startTransaction("ReVa diff transfer markup");
        int pTx = dest.startTransaction("ReVa diff transfer markup");
        boolean ok = false;
        try {
            for (ghidra.feature.vt.api.main.VTMatch m : best.values()) {
                monitor.checkCancelled();
                ghidra.feature.vt.api.main.VTAssociation a = m.getAssociation();
                double sim = m.getSimilarityScore().getScore();
                Map<String, Object> row = transferRow(ds, m, sim);
                if (sim >= floor) {
                    boolean did;
                    try {
                        did = VersionTrackingUtil.acceptAndApplyMarkup(ds.vtSession, a, applyOpts, monitor);
                    } catch (CancelledException e) {
                        did = false;
                    }
                    if (did) applied.add(row); else skipped.add(row);
                } else {
                    proposed.add(row);
                }
            } // end for
            // Cancellation can fire inside the final match's acceptAndApplyMarkup, where the inner
            // catch swallows it. Re-check here so a late cancel unwinds through the finally with
            // ok=false (rolling back ALL markup applied this run) instead of committing partial
            // state under a CANCELLED status. Transfer is all-or-nothing on cancel.
            monitor.checkCancelled();
            ok = true;
        } finally {
            dest.endTransaction(pTx, ok);
            ds.vtSession.endTransaction(sTx, ok);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("sourceProgramPath", ds.sourcePath);
        out.put("destinationProgramPath", ds.destinationPath);
        out.put("appliedCount", applied.size());
        out.put("skippedCount", skipped.size());
        out.put("proposedCount", proposed.size());
        out.put("applied", applied);
        out.put("skipped", skipped);
        out.put("proposed", proposed);
        return out;
    }

    private void registerTransferMarkupTool() {
        Map<String, Object> properties = new HashMap<>();
        putPairProperties(properties);
        properties.put("confidence", Map.of("type", "number",
            "description", "Similarity floor for auto-apply (0..1). Matches below are returned as proposals.",
            "default", VersionTrackingUtil.IDENTICAL_THRESHOLD));

        Map<String, Object> waitProp = new HashMap<>();
        waitProp.put("type", "integer");
        waitProp.put("minimum", 0);
        waitProp.put("default", 10);
        waitProp.put("description",
            "Seconds to wait inline for the transfer to finish before returning a job handle. "
            + "Small match sets finish in this window; large-image transfers return "
            + "{status:running, jobId} to poll via diff-status.");
        properties.put("waitSeconds", waitProp);

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-transfer-markup")
            .title("Transfer Analysis Markup")
            .description("Auto-apply VT markup (names/prototypes/datatypes/comments) from source to "
                + "destination for matches at/above the confidence floor, in a transaction. Returns "
                + "applied matches and the below-floor proposals for selective review. Runs as a "
                + "background job: waits inline up to waitSeconds, then returns {status:running, jobId} "
                + "for large match sets.")
            .inputSchema(createSchema(properties, List.of("sourceProgramPath", "destinationProgramPath")))
            .build();

        registerTool(tool, (exchange, request) -> {
            DiffSession ds = requireSession(request);
            double floor = getOptionalDouble(request, "confidence", VersionTrackingUtil.IDENTICAL_THRESHOLD);
            int waitSeconds = getOptionalInt(request, "waitSeconds", 10);
            if (waitSeconds < 0) {
                return createErrorResult("waitSeconds must be >= 0; got " + waitSeconds);
            }
            DiffJobManager mgr = RevaInternalServiceRegistry.getService(DiffJobManager.class);
            if (mgr == null) {
                return createErrorResult("background diff service unavailable");
            }
            DiffJob job = mgr.startOrAttach(DiffJobKind.TRANSFER_MARKUP, ds.sourcePath, ds.destinationPath,
                () -> (monitor) -> transferMarkup(ds, floor, monitor), -1);
            return awaitDiffJob(exchange, request, job, waitSeconds, ds.sourcePath, ds.destinationPath,
                "Markup transfer still running. Poll diff-status with this jobId and "
                + "sinceLogSeq=logCursor; or call diff-cancel to stop.");
        });
    }

    private Map<String, Object> transferRow(DiffSession ds, ghidra.feature.vt.api.main.VTMatch m, double sim) {
        ghidra.program.model.address.Address sa = m.getAssociation().getSourceAddress();
        ghidra.program.model.address.Address da = m.getAssociation().getDestinationAddress();
        ghidra.program.model.listing.Function sf = ds.sourceProgram.getFunctionManager().getFunctionAt(sa);
        ghidra.program.model.listing.Function df = ds.destinationProgram.getFunctionManager().getFunctionAt(da);
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("sourceName", sf != null ? sf.getName() : null);
        r.put("sourceAddress", AddressUtil.formatAddress(sa));
        r.put("destName", df != null ? df.getName() : null);
        r.put("destAddress", AddressUtil.formatAddress(da));
        r.put("similarity", sim);
        r.put("correlator", m.getMatchSet().getProgramCorrelatorInfo().getName());
        return r;
    }

    // ---- diff-apply-match ---------------------------------------------

    private void registerApplyMatchTool() {
        Map<String, Object> properties = new HashMap<>();
        putPairProperties(properties);
        properties.put("sourceAddress", Map.of("type", "string",
            "description", "Source function address of the match to apply."));
        properties.put("destinationAddress", Map.of("type", "string",
            "description", "Destination function address of the match to apply."));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-apply-match")
            .title("Apply One Diff Match")
            .description("Apply VT markup for exactly one matched function pair (a proposal the agent chose). "
                + "Mutates the destination program in a transaction.")
            .inputSchema(createSchema(properties, List.of("sourceProgramPath",
                "destinationProgramPath", "sourceAddress", "destinationAddress")))
            .build();

        registerTool(tool, (exchange, request) -> {
            DiffSession ds = requireSession(request);
            Address srcAddr = AddressUtil.resolveAddressOrSymbol(ds.sourceProgram, getString(request, "sourceAddress"));
            Address dstAddr = AddressUtil.resolveAddressOrSymbol(ds.destinationProgram, getString(request, "destinationAddress"));
            if (srcAddr == null || dstAddr == null) {
                return createErrorResult("Could not resolve sourceAddress/destinationAddress.");
            }

            ghidra.feature.vt.api.main.VTAssociation target = null;
            for (ghidra.feature.vt.api.main.VTMatchSet ms : ds.vtSession.getMatchSets()) {
                for (ghidra.feature.vt.api.main.VTMatch m : ms.getMatches()) {
                    ghidra.feature.vt.api.main.VTAssociation a = m.getAssociation();
                    if (a.getSourceAddress().equals(srcAddr) && a.getDestinationAddress().equals(dstAddr)) {
                        target = a;
                        break;
                    }
                }
                if (target != null) break;
            }
            if (target == null) {
                return createErrorResult("No match found for that source/destination address pair.");
            }

            Program dest = ds.destinationProgram;
            int sTx = ds.vtSession.startTransaction("ReVa diff apply single match");
            int pTx = dest.startTransaction("ReVa diff apply single match");
            boolean applied = false;
            boolean ok = false;
            try {
                applied = VersionTrackingUtil.acceptAndApplyMarkup(
                    ds.vtSession, target, VersionTrackingUtil.defaultApplyOptions(), TaskMonitor.DUMMY);
                ok = true;
            } catch (CancelledException e) {
                // treated as not applied
            } finally {
                dest.endTransaction(pTx, ok);
                ds.vtSession.endTransaction(sTx, ok);
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("success", true);
            out.put("applied", applied);
            out.put("sourceAddress", AddressUtil.formatAddress(srcAddr));
            out.put("destinationAddress", AddressUtil.formatAddress(dstAddr));
            return createJsonResult(out);
        });
    }

    // ---- diff-status / diff-cancel -------------------------------------

    /** diff-status: log-tailing long-poll over a diff job until it terminates. */
    private void registerStatusTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("jobId", Map.of("type", "string",
            "description", "The diff job to poll (e.g. 'diff-3'), as returned by diff-create-session "
                + "or diff-transfer-markup. Provide jobId, or the source+destination pair."));
        putPairProperties(properties); // sourceProgramPath/destinationProgramPath (optional here)
        Map<String, Object> sinceProp = new HashMap<>();
        sinceProp.put("type", "integer");
        sinceProp.put("minimum", 0);
        sinceProp.put("default", 0);
        sinceProp.put("description", "Return only log entries with seq greater than this cursor "
            + "(feed back the previous logCursor).");
        properties.put("sinceLogSeq", sinceProp);
        Map<String, Object> waitProp = new HashMap<>();
        waitProp.put("type", "integer");
        waitProp.put("minimum", 0);
        waitProp.put("default", 10);
        waitProp.put("description", "Seconds to long-poll; returns the instant the job terminates. "
            + "Keep below your MCP client tool-call timeout.");
        properties.put("waitSeconds", waitProp);
        properties.put("maxLogEntries", Map.of("type", "integer", "minimum", 1, "default", 50,
            "description", "Max log entries per call; drain more with sinceLogSeq=logCursor."));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-status")
            .title("Poll Diff Job")
            .description("Poll a background diff job (correlation or markup transfer) started by "
                + "diff-create-session / diff-transfer-markup. Returns new log lines since the cursor "
                + "and, when terminal, the full result (the summary, or the applied/proposed markup). "
                + "Identify by jobId, or by the source+destination pair (resolves to the latest job).")
            .inputSchema(createSchema(properties, List.of()))
            .build();

        registerTool(tool, (exchange, request) -> {
            DiffJobManager mgr = RevaInternalServiceRegistry.getService(DiffJobManager.class);
            if (mgr == null) {
                return createErrorResult("background diff service unavailable");
            }
            String jobId = getOptionalString(request, "jobId", null);
            DiffJob job;
            if (jobId != null) {
                job = mgr.get(jobId);
                if (job == null) {
                    return createErrorResult("No diff job with id '" + jobId + "'.");
                }
            } else {
                String srcPath = getString(request, "sourceProgramPath");
                String dstPath = getString(request, "destinationProgramPath");
                job = mgr.latestForPair(srcPath, dstPath);
                if (job == null) {
                    return createErrorResult("No diff job for that source/destination pair. "
                        + "Run diff-create-session first.");
                }
            }
            int sinceLogSeq = getOptionalInt(request, "sinceLogSeq", 0);
            int waitSeconds = getOptionalInt(request, "waitSeconds", 10);
            if (waitSeconds < 0) {
                return createErrorResult("waitSeconds must be >= 0; got " + waitSeconds);
            }
            int maxLogEntries = getOptionalInt(request, "maxLogEntries", 50);
            if (sinceLogSeq < 0) {
                return createErrorResult("sinceLogSeq must be >= 0; got " + sinceLogSeq);
            }
            if (maxLogEntries < 1) {
                return createErrorResult("maxLogEntries must be >= 1; got " + maxLogEntries);
            }

            // Long-poll: return immediately when terminal, else hold until the window elapses.
            long deadline = System.currentTimeMillis() + (long) waitSeconds * 1000L;
            while (!job.getStatus().isTerminal() && System.currentTimeMillis() < deadline) {
                try {
                    Thread.sleep(250L);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            JobLog.LogPage page = job.logSince(sinceLogSeq, maxLogEntries);
            List<Map<String, Object>> log = renderLogPage(page);

            Map<String, Object> out;
            if (job.getStatus().isTerminal() && job.getResult() != null) {
                out = new LinkedHashMap<>(job.getResult());
            } else if (job.getStatus().isTerminal()) {
                // Terminal with no result payload => failed / cancelled / timed_out.
                out = new LinkedHashMap<>();
                out.put("success", false);
                out.put("sourceProgramPath", job.getSourcePath());
                out.put("destinationProgramPath", job.getDestinationPath());
                if (job.getError() != null) {
                    out.put("error", job.getError());
                }
            } else {
                // Still running.
                out = new LinkedHashMap<>();
                out.put("success", true);
                out.put("sourceProgramPath", job.getSourcePath());
                out.put("destinationProgramPath", job.getDestinationPath());
            }
            out.put("jobId", job.getJobId());
            out.put("kind", job.getKind().name().toLowerCase());
            out.put("status", job.getStatus().name().toLowerCase());
            out.put("log", log);
            out.put("logCursor", page.nextCursor);
            out.put("truncated", page.truncated);
            return createJsonResult(out);
        });
    }

    /** diff-cancel: request async cancellation of a running diff job. */
    private void registerCancelTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("jobId", Map.of("type", "string",
            "description", "The diff job to cancel (e.g. 'diff-3')."));
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-cancel")
            .title("Cancel Diff Job")
            .description("Request cancellation of a running diff job started by diff-create-session "
                + "or diff-transfer-markup. Asynchronous: poll diff-status until status is cancelled. "
                + "A cancelled markup transfer rolls back (all-or-nothing).")
            .inputSchema(createSchema(properties, List.of("jobId")))
            .build();

        registerTool(tool, (exchange, request) -> {
            DiffJobManager mgr = RevaInternalServiceRegistry.getService(DiffJobManager.class);
            if (mgr == null) {
                return createErrorResult("background diff service unavailable");
            }
            String jobId = getString(request, "jobId");
            DiffJob job = mgr.get(jobId);
            if (job == null) {
                return createErrorResult("No diff job with id '" + jobId + "'.");
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("jobId", jobId);
            if (job.getStatus().isTerminal()) {
                out.put("success", true);
                out.put("alreadyTerminal", true);
                out.put("status", job.getStatus().name().toLowerCase());
                out.put("message", "Job already finished; nothing to cancel.");
            } else {
                job.requestCancel();
                out.put("success", true);
                out.put("alreadyTerminal", false);
                out.put("status", job.getStatus().name().toLowerCase());
                out.put("message", "Cancellation requested. Poll diff-status until status is cancelled.");
            }
            return createJsonResult(out);
        });
    }

    // ---- diff-create-session -------------------------------------------

    private void registerCreateSessionTool() {
        Map<String, Object> properties = new HashMap<>();
        putPairProperties(properties);
        properties.put("force", Map.of("type", "boolean",
            "description", "Re-correlate even if a session already exists for this pair.",
            "default", false));
        properties.put("correlators", Map.of(
            "type", "array",
            "items", Map.of("type", "string", "enum", VersionTrackingUtil.CORRELATOR_KEYS_AVAILABLE),
            "description", "Ordered VT correlators to run. Omit for the default sequence: "
                + VersionTrackingUtil.CORRELATOR_KEYS + ". Drop 'symbol-name' to match by "
                + "structure/bytes instead of trusting symbol names (e.g. when names are stripped, "
                + "unreliable, or you want a body-based diff that surfaces decompilation changes). "
                + "'combined-reference' is an opt-in reference-based correlator (not in the default "
                + "sequence) that can match functions across body changes when their call/data "
                + "references are stable — useful for stripped binaries; caveat: leaf functions with "
                + "no references still won't match (Ghidra VT has no body-similarity correlator). "
                + "Changing the selection re-correlates this pair."));

        Map<String, Object> waitProp = new HashMap<>();
        waitProp.put("type", "integer");
        waitProp.put("minimum", 0);
        waitProp.put("default", 10);
        waitProp.put("description",
            "Seconds to wait inline for correlation to finish before returning a job handle. "
            + "Small binaries finish in this window and return the full summary; large ones "
            + "return {status:running, jobId} to poll via diff-status. Keep below your "
            + "MCP client tool-call timeout.");
        properties.put("waitSeconds", waitProp);
        properties.put("timeoutSeconds", Map.of("type", "integer",
            "description", "Hard cap on correlation time in seconds; -1 (default) for unlimited.",
            "default", -1));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("diff-create-session")
            .title("Create Binary Diff Session")
            .description("Correlate two programs with Ghidra Version Tracking and cache the result as a "
                + "background job. Waits inline up to waitSeconds (default 10): small binaries finish in "
                + "that window and return the full summary; large binaries return "
                + "{status:running, jobId} to poll via diff-status. Idempotent unless force=true or the "
                + "correlators selection changes. Both programs must already be analyzed. NOTE: if a "
                + "correlation for this same pair is already running, this call attaches to that in-flight "
                + "job and the force/correlators overrides on this call are ignored until it finishes. "
                + "Returns summary counts and the correlators that ran.")
            .inputSchema(createSchema(properties, List.of("sourceProgramPath", "destinationProgramPath")))
            .build();

        registerTool(tool, (exchange, request) -> {
            String srcPath = getString(request, "sourceProgramPath");
            String dstPath = getString(request, "destinationProgramPath");
            boolean force = getOptionalBoolean(request, "force", false);
            List<String> correlatorKeys = getOptionalStringList(request.arguments(), "correlators", List.of());
            int waitSeconds = getOptionalInt(request, "waitSeconds", 10);
            if (waitSeconds < 0) {
                return createErrorResult("waitSeconds must be >= 0; got " + waitSeconds);
            }
            int timeoutSeconds = getOptionalInt(request, "timeoutSeconds", -1);
            if (timeoutSeconds == 0 || (timeoutSeconds < 0 && timeoutSeconds != -1)) {
                return createErrorResult("timeoutSeconds must be a positive integer or -1 (no timeout); got "
                    + timeoutSeconds);
            }
            Program source = getValidatedProgram(srcPath);
            Program dest = getValidatedProgram(dstPath);
            requireAnalyzed(source);
            requireAnalyzed(dest);

            DiffJobManager mgr = RevaInternalServiceRegistry.getService(DiffJobManager.class);
            if (mgr == null) {
                return createErrorResult("background diff service unavailable");
            }

            List<VTProgramCorrelatorFactory> factories =
                VersionTrackingUtil.correlatorSequence(correlatorKeys);
            // The work closure owns the domain logic: correlate (caching the session as a side
            // effect) then build today's summary. Runs on the worker with a real, cancellable
            // monitor — never TaskMonitor.DUMMY.
            DiffJob job = mgr.startOrAttach(DiffJobKind.CORRELATE, srcPath, dstPath,
                () -> (monitor) -> {
                    DiffSession ds = DiffSessionManager.getOrCreate(source, dest, factories, force, monitor);
                    return summarize(ds, false);
                }, timeoutSeconds);

            return awaitDiffJob(exchange, request, job, waitSeconds, srcPath, dstPath,
                "Correlation still running. Poll diff-status with this jobId and "
                + "sinceLogSeq=logCursor; or call diff-cancel to stop.");
        });
    }

    /** Serialize a job log page to the MCP wire shape (seq/elapsedMs/message per entry). */
    private List<Map<String, Object>> renderLogPage(JobLog.LogPage page) {
        List<Map<String, Object>> log = new ArrayList<>();
        for (JobLog.LogEntry entry : page.entries) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("seq", entry.seq);
            e.put("elapsedMs", entry.elapsedMs);
            e.put("message", entry.message);
            log.add(e);
        }
        return log;
    }

    /**
     * Inline long-poll: wait up to waitSeconds for the diff job to terminate, emitting best-effort
     * progress notifications when the client opted in. On terminal, return the job's result map
     * (today's tool shape) plus jobId/status; otherwise return a running handle to poll.
     */
    private McpSchema.CallToolResult awaitDiffJob(
            McpSyncServerExchange exchange,
            McpSchema.CallToolRequest request, DiffJob job, int waitSeconds,
            String srcPath, String dstPath, String runningHint) {
        Object progressToken = request.progressToken();
        boolean emitProgress = progressToken != null && exchange != null;

        long deadline = System.currentTimeMillis() + (long) waitSeconds * 1000L;
        while (!job.getStatus().isTerminal() && System.currentTimeMillis() < deadline) {
            if (emitProgress) {
                try {
                    String latest = job.getLatestLogMessage();
                    String msg = (latest != null) ? latest : job.getStatus().name().toLowerCase();
                    exchange.progressNotification(new McpSchema.ProgressNotification(
                        progressToken, 0.5, 1.0, msg));
                } catch (Exception ignore) {
                    // best-effort
                }
            }
            try {
                Thread.sleep(250L);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        if (job.getStatus().isTerminal()) {
            Map<String, Object> result;
            Map<String, Object> jobResult = job.getResult();
            if (jobResult == null) {
                result = new LinkedHashMap<>();
                result.put("success", false);
                result.put("sourceProgramPath", srcPath);
                result.put("destinationProgramPath", dstPath);
                if (job.getError() != null) {
                    result.put("error", job.getError());
                }
            } else {
                result = new LinkedHashMap<>(jobResult);
            }
            result.put("jobId", job.getJobId());
            result.put("status", job.getStatus().name().toLowerCase());
            if (emitProgress) {
                try {
                    exchange.progressNotification(new McpSchema.ProgressNotification(
                        progressToken, 1.0, 1.0, "Diff " + job.getStatus().name().toLowerCase()));
                } catch (Exception ignore) {
                    // best-effort
                }
            }
            return createJsonResult(result);
        }

        JobLog.LogPage page = job.logSince(0, 50);
        List<Map<String, Object>> log = renderLogPage(page);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("sourceProgramPath", srcPath);
        result.put("destinationProgramPath", dstPath);
        result.put("jobId", job.getJobId());
        result.put("status", "running");
        result.put("log", log);
        result.put("logCursor", page.nextCursor);
        result.put("truncated", page.truncated);
        result.put("hint", runningHint);
        return createJsonResult(result);
    }
}
