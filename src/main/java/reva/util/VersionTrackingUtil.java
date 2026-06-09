package reva.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import ghidra.feature.vt.api.correlator.program.*;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.feature.vt.gui.task.ApplyMarkupItemTask;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Stateless orchestration of Ghidra Version Tracking for ReVa's diff tools. */
public final class VersionTrackingUtil {
    public static final double IDENTICAL_THRESHOLD = 0.9999;

    private VersionTrackingUtil() {}

    /** Stable, ordered keys for the DEFAULT correlator sequence, exact-first then references. */
    public static final List<String> CORRELATOR_KEYS = List.of(
        "symbol-name", "exact-bytes", "exact-instructions",
        "exact-mnemonics", "duplicate-instructions", "function-reference");

    /**
     * All correlator keys an agent may SELECT — the default sequence plus opt-in correlators
     * that do not run by default. {@code combined-reference} is reference-based (fuzzy): it can
     * pair functions whose bodies changed when their call/data references are stable, so it is
     * useful on stripped binaries but is left out of {@link #CORRELATOR_KEYS} (the default).
     */
    public static final List<String> CORRELATOR_KEYS_AVAILABLE;
    static {
        List<String> all = new ArrayList<>(CORRELATOR_KEYS);
        all.add("combined-reference");
        CORRELATOR_KEYS_AVAILABLE = List.copyOf(all);
    }

    /** Build a single correlator factory from its stable key. */
    public static VTProgramCorrelatorFactory correlatorForKey(String key) {
        switch (key) {
            case "symbol-name": return new SymbolNameProgramCorrelatorFactory();
            case "exact-bytes": return new ExactMatchBytesProgramCorrelatorFactory();
            case "exact-instructions": return new ExactMatchInstructionsProgramCorrelatorFactory();
            case "exact-mnemonics": return new ExactMatchMnemonicsProgramCorrelatorFactory();
            case "duplicate-instructions": return new DuplicateFunctionMatchProgramCorrelatorFactory();
            case "function-reference": return new FunctionReferenceProgramCorrelatorFactory();
            case "combined-reference": return new CombinedFunctionAndDataReferenceProgramCorrelatorFactory();
            default:
                throw new IllegalArgumentException("Unknown correlator '" + key
                    + "'. Valid keys: " + CORRELATOR_KEYS_AVAILABLE);
        }
    }

    /** Conservative v1 correlator sequence (exact-first, then references). */
    public static List<VTProgramCorrelatorFactory> defaultCorrelatorSequence() {
        return correlatorSequence(CORRELATOR_KEYS);
    }

    /**
     * Resolve an ordered list of correlator keys into factories. A null/empty selection
     * falls back to {@link #defaultCorrelatorSequence()}. Letting the agent choose the
     * sequence is how it can, e.g., drop {@code symbol-name} so matching relies on
     * structure/bytes rather than trusting (possibly unreliable) symbol names.
     */
    public static List<VTProgramCorrelatorFactory> correlatorSequence(List<String> keys) {
        if (keys == null || keys.isEmpty()) {
            keys = CORRELATOR_KEYS;
        }
        List<VTProgramCorrelatorFactory> f = new ArrayList<>();
        for (String key : keys) {
            f.add(correlatorForKey(key));
        }
        return f;
    }

    /** Run each factory's correlator against the session in order.
     *  The minimum function size filter is lowered to 1 so that all functions,
     *  including very small ones, are considered for matching. */
    public static List<String> runCorrelators(VTSession session, Program source, Program dest,
            List<VTProgramCorrelatorFactory> factories, TaskMonitor monitor)
            throws CancelledException {
        AddressSetView srcSet = source.getMemory().getLoadedAndInitializedAddressSet();
        AddressSetView dstSet = dest.getMemory().getLoadedAndInitializedAddressSet();
        List<String> ran = new ArrayList<>();
        int txId = session.startTransaction("ReVa diff correlation");
        boolean ok = false;
        try {
            for (VTProgramCorrelatorFactory factory : factories) {
                monitor.checkCancelled();
                VTOptions opts = factory.createDefaultOptions();
                // Lower the minimum function size to 1 so small functions are not filtered out.
                if (opts.contains(ExactMatchBytesProgramCorrelatorFactory.FUNCTION_MINIMUM_SIZE)) {
                    opts.setInt(ExactMatchBytesProgramCorrelatorFactory.FUNCTION_MINIMUM_SIZE, 1);
                }
                VTProgramCorrelator correlator =
                    factory.createCorrelator(source, srcSet, dest, dstSet, opts);
                correlator.correlate(session, monitor);
                ran.add(factory.getName());
            }
            ok = true;
        } finally {
            session.endTransaction(txId, ok);
        }
        return ran;
    }

    /** Flattened, deduped view of one function match. */
    public static final class MatchInfo {
        public final Address sourceAddress;
        public final Address destinationAddress;
        public final double similarity;
        public final String correlatorName;
        public MatchInfo(Address s, Address d, double sim, String corr) {
            this.sourceAddress = s; this.destinationAddress = d;
            this.similarity = sim; this.correlatorName = corr;
        }
        public boolean isIdentical() { return similarity >= IDENTICAL_THRESHOLD; }
    }

    /**
     * 1:1 greedy assignment of FUNCTION matches — each source address and each destination
     * address is used at most once, collapsing the many-to-many fan-out that the exact
     * correlators produce on large/stripped binaries (one byte-identical function pairs with
     * several counterparts, inflating counts and double-counting functions).
     * <p>
     * Match sets are iterated in correlator-run order, so earlier sets are higher priority
     * (e.g. {@code symbol-name} before {@code exact-bytes}); within a set, FUNCTION matches are
     * taken best-similarity-first. A candidate pair {@code (sa, da)} is accepted only when
     * neither {@code sa} nor {@code da} has already been taken; both are then marked taken and a
     * single {@link MatchInfo} is emitted. Non-FUNCTION associations are skipped.
     * <p>
     * This is <b>greedy</b> (first-come by correlator priority, then by similarity), not an
     * optimal assignment: when several candidates tie at the same similarity the resolution is
     * arbitrary among them. It preserves correct named matches because {@code symbol-name} runs
     * first, and it collapses fan-out to a single best pair per function. The returned list is
     * in acceptance order.
     */
    public static List<MatchInfo> collectFunctionMatches(VTSession session) {
        Set<Address> takenSrc = new HashSet<>();
        Set<Address> takenDst = new HashSet<>();
        List<MatchInfo> accepted = new ArrayList<>();
        for (VTMatchSet ms : session.getMatchSets()) {
            String corr = ms.getProgramCorrelatorInfo().getName();
            // Sort this correlator's FUNCTION matches by similarity DESC so the best candidate
            // within a correlator claims its addresses first.
            List<VTMatch> functionMatches = new ArrayList<>();
            for (VTMatch m : ms.getMatches()) {
                if (m.getAssociation().getType() == VTAssociationType.FUNCTION) {
                    functionMatches.add(m);
                }
            }
            functionMatches.sort((a, b) -> Double.compare(
                b.getSimilarityScore().getScore(), a.getSimilarityScore().getScore()));
            for (VTMatch m : functionMatches) {
                VTAssociation a = m.getAssociation();
                Address sa = a.getSourceAddress();
                Address da = a.getDestinationAddress();
                if (takenSrc.contains(sa) || takenDst.contains(da)) continue;
                takenSrc.add(sa);
                takenDst.add(da);
                accepted.add(new MatchInfo(sa, da, m.getSimilarityScore().getScore(), corr));
            }
        }
        return accepted;
    }

    /**
     * Resolved outgoing callee symbol names for the function at {@code entry}
     * (address-independent; thunk callees forward to their target's name).
     * Returns an empty set if no function is defined at {@code entry}.
     * <p>
     * This is the cheap, scalable signal for semantic changes that byte/instruction
     * correlators are blind to — most importantly a relocation-only patch that keeps
     * identical instruction bytes but swaps one called symbol for another,
     * both explicitly named. Comparing names rather than
     * addresses makes it robust to layout shifts between builds, and it is O(refs) so it
     * scales to whole-program diffs where decompiling every matched function would not.
     */
    public static SortedSet<String> calleeNames(Program program, Address entry, TaskMonitor monitor) {
        SortedSet<String> names = new TreeSet<>();
        if (program == null || entry == null) {
            return names;
        }
        Function fn = program.getFunctionManager().getFunctionAt(entry);
        if (fn == null) {
            return names;
        }
        for (Function callee : fn.getCalledFunctions(monitor)) {
            names.add(callee.getName());
        }
        return names;
    }

    /** Functions in {@code program} whose entry point is not in {@code matched}. */
    public static List<Function> unmatchedFunctions(Program program, Set<Address> matched) {
        List<Function> out = new ArrayList<>();
        var it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function fn = it.next();
            if (fn.isExternal()) continue;
            if (!matched.contains(fn.getEntryPoint())) out.add(fn);
        }
        return out;
    }

    /** Apply options seeded with Ghidra VT defaults so markup actually applies. */
    public static ToolOptions defaultApplyOptions() {
        ToolOptions o = new ToolOptions("ReVa VT Apply");
        o.setEnum(VTOptionDefines.FUNCTION_NAME, VTOptionDefines.DEFAULT_OPTION_FOR_FUNCTION_NAME);
        o.setEnum(VTOptionDefines.FUNCTION_SIGNATURE, VTOptionDefines.DEFAULT_OPTION_FOR_FUNCTION_SIGNATURE);
        o.setEnum(VTOptionDefines.FUNCTION_RETURN_TYPE, VTOptionDefines.DEFAULT_OPTION_FOR_FUNCTION_RETURN_TYPE);
        o.setEnum(VTOptionDefines.CALLING_CONVENTION, VTOptionDefines.DEFAULT_OPTION_FOR_CALLING_CONVENTION);
        o.setEnum(VTOptionDefines.INLINE, VTOptionDefines.DEFAULT_OPTION_FOR_INLINE);
        o.setEnum(VTOptionDefines.NO_RETURN, VTOptionDefines.DEFAULT_OPTION_FOR_NO_RETURN);
        o.setEnum(VTOptionDefines.CALL_FIXUP, VTOptionDefines.DEFAULT_OPTION_FOR_CALL_FIXUP);
        o.setEnum(VTOptionDefines.VAR_ARGS, VTOptionDefines.DEFAULT_OPTION_FOR_VAR_ARGS);
        o.setEnum(VTOptionDefines.PARAMETER_DATA_TYPES, VTOptionDefines.DEFAULT_OPTION_FOR_PARAMETER_DATA_TYPES);
        o.setEnum(VTOptionDefines.PARAMETER_NAMES, VTOptionDefines.DEFAULT_OPTION_FOR_PARAMETER_NAMES);
        o.setEnum(VTOptionDefines.HIGHEST_NAME_PRIORITY, VTOptionDefines.DEFAULT_OPTION_FOR_HIGHEST_NAME_PRIORITY);
        o.setBoolean(VTOptionDefines.PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY,
            VTOptionDefines.DEFAULT_OPTION_FOR_PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY);
        o.setEnum(VTOptionDefines.PARAMETER_COMMENTS, VTOptionDefines.DEFAULT_OPTION_FOR_PARAMETER_COMMENTS);
        o.setEnum(VTOptionDefines.LABELS, VTOptionDefines.DEFAULT_OPTION_FOR_LABELS);
        o.setEnum(VTOptionDefines.PLATE_COMMENT, VTOptionDefines.DEFAULT_OPTION_FOR_PLATE_COMMENTS);
        o.setEnum(VTOptionDefines.PRE_COMMENT, VTOptionDefines.DEFAULT_OPTION_FOR_PRE_COMMENTS);
        o.setEnum(VTOptionDefines.END_OF_LINE_COMMENT, VTOptionDefines.DEFAULT_OPTION_FOR_EOL_COMMENTS);
        o.setEnum(VTOptionDefines.REPEATABLE_COMMENT, VTOptionDefines.DEFAULT_OPTION_FOR_REPEATABLE_COMMENTS);
        o.setEnum(VTOptionDefines.POST_COMMENT, VTOptionDefines.DEFAULT_OPTION_FOR_POST_COMMENTS);
        o.setEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE, VTOptionDefines.DEFAULT_OPTION_FOR_DATA_MATCH_DATA_TYPE);
        o.setBoolean(VTOptionDefines.IGNORE_INCOMPLETE_MARKUP_ITEMS,
            VTOptionDefines.DEFAULT_OPTION_FOR_IGNORE_INCOMPLETE_MARKUP_ITEMS);
        o.setBoolean(VTOptionDefines.IGNORE_EXCLUDED_MARKUP_ITEMS,
            VTOptionDefines.DEFAULT_OPTION_FOR_IGNORE_EXCLUDED_MARKUP_ITEMS);
        return o;
    }

    /**
     * Accept the association and apply its markup items using the given options.
     * Returns true if markup was applied without errors. Caller must hold a session
     * transaction and a destination-program transaction; ApplyMarkupItemTask accepts
     * each association and applies its markup.
     */
    public static boolean acceptAndApplyMarkup(VTSession session, VTAssociation assoc,
            ToolOptions applyOptions, TaskMonitor monitor) throws CancelledException {
        if (!assoc.getStatus().canApply()) return false;
        Collection<VTMarkupItem> items = assoc.getMarkupItems(monitor);
        if (items == null || items.isEmpty()) return false;
        ApplyMarkupItemTask task = new ApplyMarkupItemTask(session, items, applyOptions);
        task.run(monitor);
        return !task.hasErrors();
    }
}
