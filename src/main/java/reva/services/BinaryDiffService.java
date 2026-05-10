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
package reva.services;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import ghidra.feature.vt.api.db.VTSessionContentHandler;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.feature.vt.gui.actions.AutoVersionTrackingTask;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ProjectData;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Domain service for ReVa's binary-diff feature. Owns the lifecycle of
 * Ghidra Version Tracking ({@link VTSession}) sessions stored in the project,
 * and runs the {@link AutoVersionTrackingTask} pipeline against them.
 *
 * <p>Sessions are persistent {@code VTSession} domain objects under the
 * conventional project folder {@code /VTSessions/}. The deterministic name is
 * {@code <sourceBasename>__vs__<destBasename>}; on collision a numeric suffix
 * ({@code -2}, {@code -3}, ...) is appended.</p>
 *
 * <p>Tool handlers should follow this lifecycle per call:
 * <pre>
 *   VTSession session = service.openSession(file, this);
 *   try {
 *       // read or modify ...
 *   } finally {
 *       service.closeSession(session, this);
 *   }
 * </pre>
 * Per-call open+close keeps the {@code addSynchronizedDomainObject} write-lock
 * on the destination program scoped to a single tool invocation, eliminating
 * a class of multi-tool coordination bugs.</p>
 */
public class BinaryDiffService {

    /** Project folder where all VT sessions live. */
    public static final String SESSIONS_FOLDER = "/VTSessions";
    private static final String SESSION_NAME_SEPARATOR = "__vs__";

    /**
     * Compute the deterministic base session name for a (source, destination) pair.
     * Does not include the {@link #SESSIONS_FOLDER} prefix.
     */
    public static String computeBaseSessionName(Program source, Program destination) {
        return basename(source) + SESSION_NAME_SEPARATOR + basename(destination);
    }

    private static String basename(Program p) {
        String pathname = p.getDomainFile().getPathname();
        int slash = pathname.lastIndexOf('/');
        return (slash >= 0) ? pathname.substring(slash + 1) : pathname;
    }

    /**
     * Find an existing session for this program pair if one is present.
     * Walks {@link #SESSIONS_FOLDER} and matches by base name (and any
     * collision-suffix variants).
     */
    public Optional<DomainFile> findSession(ProjectData projectData, Program source, Program destination) {
        DomainFolder folder = projectData.getFolder(SESSIONS_FOLDER);
        if (folder == null) {
            return Optional.empty();
        }
        String baseName = computeBaseSessionName(source, destination);
        // Exact match wins. We do not auto-detect collision-suffix variants here because
        // we cannot tell which prior session corresponds to this exact (src, dst) pair
        // without inspecting it. The caller can pass an explicit sessionPath to disambiguate.
        DomainFile exact = folder.getFile(baseName);
        if (exact != null && VTSessionContentHandler.CONTENT_TYPE.equals(exact.getContentType())) {
            return Optional.of(exact);
        }
        return Optional.empty();
    }

    /**
     * Open an existing session domain file for read/write. Caller must call
     * {@link #closeSession(VTSession, Object)} with the same {@code consumer}.
     */
    public VTSession openSession(DomainFile sessionFile, Object consumer) throws Exception {
        if (!VTSessionContentHandler.CONTENT_TYPE.equals(sessionFile.getContentType())) {
            throw new IllegalArgumentException(
                "File is not a Version Tracking session: " + sessionFile.getPathname());
        }
        // upgrade=true so older session schemas open transparently in headless tests too
        return (VTSession) sessionFile.getDomainObject(consumer, true, false, TaskMonitor.DUMMY);
    }

    /**
     * Create a new session for the given program pair, save it to the project at
     * {@link #SESSIONS_FOLDER}, and return it open. Suffixes the session name
     * with {@code -2}, {@code -3}, ... if a base-name collision exists.
     *
     * @param consumer object that becomes the session's open-consumer; pass the
     *     same value to {@link #closeSession(VTSession, Object)}
     */
    public VTSession createSession(ProjectData projectData, Program source, Program destination,
            Object consumer) throws Exception {
        DomainFolder folder = ensureFolder(projectData, SESSIONS_FOLDER);
        String name = uniqueSessionName(folder, computeBaseSessionName(source, destination));

        VTSessionDB session = new VTSessionDB(name, source, destination, consumer);
        try {
            folder.createFile(name, session, TaskMonitor.DUMMY);
        } catch (Exception e) {
            // Creation failed — release the in-memory session before propagating.
            session.release(consumer);
            throw e;
        }
        return session;
    }

    /**
     * Run the canonical {@link AutoVersionTrackingTask} pipeline against an
     * already-open session. The destination program is mutated and the session
     * is updated; {@code session.save()} should be called by the caller after
     * inspecting the results.
     *
     * @param toolOptions option overrides; may be the result of
     *     {@link #defaultAutoVtOptions(boolean)}
     */
    public void runAutoVt(VTSession session, ToolOptions toolOptions, TaskMonitor monitor)
            throws CancelledException {
        AutoVersionTrackingTask task = new AutoVersionTrackingTask(session, toolOptions);
        // task.run handles transactions and event suppression internally
        task.run(monitor != null ? monitor : TaskMonitor.DUMMY);
        String status = task.getStatusMsg();
        if (status != null) {
            Msg.info(BinaryDiffService.class, status);
        }
    }

    /**
     * Build a {@link ToolOptions} object with AutoVT defaults. The
     * {@code aggressive} flag relaxes the reference-correlator score/confidence
     * thresholds, finding more (possibly lower-quality) matches.
     */
    public ToolOptions defaultAutoVtOptions(boolean aggressive) {
        ToolOptions opts = new VTOptions("ReVa AutoVT");
        opts.setBoolean(VTOptionDefines.RUN_EXACT_SYMBOL_OPTION, true);
        opts.setBoolean(VTOptionDefines.RUN_EXACT_DATA_OPTION, true);
        opts.setBoolean(VTOptionDefines.RUN_EXACT_FUNCTION_BYTES_OPTION, true);
        opts.setBoolean(VTOptionDefines.RUN_EXACT_FUNCTION_INST_OPTION, true);
        opts.setBoolean(VTOptionDefines.RUN_DUPE_FUNCTION_OPTION, true);
        opts.setBoolean(VTOptionDefines.RUN_REF_CORRELATORS_OPTION, true);
        opts.setBoolean(VTOptionDefines.CREATE_IMPLIED_MATCHES_OPTION, true);
        opts.setBoolean(VTOptionDefines.APPLY_IMPLIED_MATCHES_OPTION, true);
        opts.setInt(VTOptionDefines.MIN_VOTES_OPTION, aggressive ? 1 : 2);
        opts.setInt(VTOptionDefines.MAX_CONFLICTS_OPTION, aggressive ? 2 : 0);
        opts.setInt(VTOptionDefines.SYMBOL_CORRELATOR_MIN_LEN_OPTION, 3);
        opts.setInt(VTOptionDefines.DATA_CORRELATOR_MIN_LEN_OPTION, 5);
        opts.setInt(VTOptionDefines.FUNCTION_CORRELATOR_MIN_LEN_OPTION, 10);
        opts.setInt(VTOptionDefines.DUPE_FUNCTION_CORRELATOR_MIN_LEN_OPTION, aggressive ? 10 : 25);
        opts.setDouble(VTOptionDefines.REF_CORRELATOR_MIN_SCORE_OPTION, aggressive ? 0.5 : 0.95);
        opts.setDouble(VTOptionDefines.REF_CORRELATOR_MIN_CONF_OPTION, aggressive ? 1.0 : 10.0);
        return opts;
    }

    /**
     * Apply caller-supplied raw option overrides on top of {@link #defaultAutoVtOptions(boolean)}.
     * Keys must match {@link VTOptionDefines} constants. Unknown keys are silently ignored
     * (the underlying {@code ToolOptions} accepts arbitrary keys).
     */
    public ToolOptions buildAutoVtOptions(boolean aggressive, java.util.Map<String, Object> overrides) {
        ToolOptions opts = defaultAutoVtOptions(aggressive);
        if (overrides == null) {
            return opts;
        }
        for (java.util.Map.Entry<String, Object> entry : overrides.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Boolean) {
                opts.setBoolean(entry.getKey(), (Boolean) value);
            } else if (value instanceof Integer) {
                opts.setInt(entry.getKey(), (Integer) value);
            } else if (value instanceof Long) {
                opts.setInt(entry.getKey(), ((Long) value).intValue());
            } else if (value instanceof Number) {
                opts.setDouble(entry.getKey(), ((Number) value).doubleValue());
            } else if (value != null) {
                opts.setString(entry.getKey(), value.toString());
            }
        }
        return opts;
    }

    /**
     * Release a session opened via {@link #openSession(DomainFile, Object)} or
     * {@link #createSession(ProjectData, Program, Program, Object)}. Caller is
     * expected to have already called {@code session.save()} if desired.
     */
    public void closeSession(VTSession session, Object consumer) {
        if (session != null) {
            session.release(consumer);
        }
    }

    /**
     * Delete a session domain file from the project. Returns true if the file
     * existed and was deleted; false if it was missing.
     */
    public boolean deleteSession(ProjectData projectData, String sessionPath) throws IOException {
        DomainFile file = projectData.getFile(sessionPath);
        if (file == null) {
            return false;
        }
        if (!VTSessionContentHandler.CONTENT_TYPE.equals(file.getContentType())) {
            throw new IllegalArgumentException(
                "File is not a Version Tracking session: " + sessionPath);
        }
        file.delete();
        return true;
    }

    /**
     * List all session domain files currently present under
     * {@link #SESSIONS_FOLDER}.
     */
    public List<DomainFile> listSessions(ProjectData projectData) {
        DomainFolder folder = projectData.getFolder(SESSIONS_FOLDER);
        if (folder == null) {
            return List.of();
        }
        List<DomainFile> result = new ArrayList<>();
        for (DomainFile file : folder.getFiles()) {
            if (VTSessionContentHandler.CONTENT_TYPE.equals(file.getContentType())) {
                result.add(file);
            }
        }
        return result;
    }

    // ---- helpers ----------------------------------------------------------

    private static DomainFolder ensureFolder(ProjectData projectData, String path)
            throws InvalidNameException, IOException {
        DomainFolder existing = projectData.getFolder(path);
        if (existing != null) {
            return existing;
        }
        // path always begins with "/"
        String name = path.substring(path.lastIndexOf('/') + 1);
        return projectData.getRootFolder().createFolder(name);
    }

    private static String uniqueSessionName(DomainFolder folder, String baseName) {
        if (folder.getFile(baseName) == null) {
            return baseName;
        }
        for (int i = 2; i < 1000; i++) {
            String candidate = baseName + "-" + i;
            if (folder.getFile(candidate) == null) {
                return candidate;
            }
        }
        throw new IllegalStateException("Could not allocate a unique VT session name under " + baseName);
    }
}
