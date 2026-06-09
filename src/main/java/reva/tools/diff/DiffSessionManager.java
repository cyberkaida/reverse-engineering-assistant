package reva.tools.diff;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import reva.util.VersionTrackingUtil;

/** In-memory cache of {@link DiffSession}s keyed by (sourcePath, destinationPath). */
public final class DiffSessionManager {
    private static final Map<String, DiffSession> CACHE = new ConcurrentHashMap<>();

    private DiffSessionManager() {}

    private static String key(String srcPath, String dstPath) {
        return srcPath + "\0" + dstPath;
    }

    public static DiffSession get(String srcPath, String dstPath) {
        return CACHE.get(key(srcPath, dstPath));
    }

    public static List<DiffSession> list() {
        return new ArrayList<>(CACHE.values());
    }

    /** Returns the cached session, or correlates and caches a new one. */
    public static synchronized DiffSession getOrCreate(Program source, Program dest,
            List<VTProgramCorrelatorFactory> factories, boolean force, TaskMonitor monitor)
            throws IOException, CancelledException {
        String srcPath = source.getDomainFile().getPathname();
        String dstPath = dest.getDomainFile().getPathname();
        String k = key(srcPath, dstPath);
        // Names of the correlators the caller wants to run, in order. A cached session is
        // only reusable if it ran exactly this selection — otherwise the agent changed the
        // correlator set (e.g. dropped symbol-name) and we must re-correlate.
        List<String> requestedNames = new ArrayList<>();
        for (VTProgramCorrelatorFactory f : factories) {
            requestedNames.add(f.getName());
        }
        DiffSession existing = CACHE.get(k);
        if (existing != null && !force && existing.correlatorsRun.equals(requestedNames)) {
            return existing;
        }
        if (existing != null) {
            delete(srcPath, dstPath); // force OR different correlator selection: release old VT session
        }
        VTSession vt = new VTSessionDB(
            "ReVa diff: " + source.getName() + " -> " + dest.getName(),
            source, dest, DiffSessionManager.class);
        List<String> ran;
        try {
            ran = VersionTrackingUtil.runCorrelators(vt, source, dest, factories, monitor);
        } catch (RuntimeException | CancelledException e) {
            ((VTSessionDB) vt).release(DiffSessionManager.class);
            throw e;
        }
        DiffSession ds = new DiffSession(source, dest, srcPath, dstPath, vt, ran);
        CACHE.put(k, ds);
        return ds;
    }

    public static synchronized boolean delete(String srcPath, String dstPath) {
        DiffSession removed = CACHE.remove(key(srcPath, dstPath));
        if (removed == null) return false;
        ((VTSessionDB) removed.vtSession).release(DiffSessionManager.class);
        return true;
    }

    /** Test/teardown hook: drop all cached sessions. */
    public static synchronized void clearAll() {
        for (String k : new ArrayList<>(CACHE.keySet())) {
            DiffSession ds = CACHE.remove(k);
            if (ds != null) ((VTSessionDB) ds.vtSession).release(DiffSessionManager.class);
        }
    }
}
