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
package reva.tools.scripts;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

import generic.jar.ResourceFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reva.plugin.ConfigManager;
import reva.server.McpServerManager;
import reva.tools.AbstractToolProvider;
import reva.tools.ProgramBusyException;
import reva.tools.scripts.PythonScriptExecutor.Result;
import reva.tools.scripts.ScriptFileEditor.EditResult;
import reva.tools.scripts.ScriptFileEditor.RenderedView;
import reva.util.RevaInternalServiceRegistry;
import reva.util.SchemaUtil;

/**
 * MCP tool provider for writing, reading, editing, and running Ghidra Python
 * scripts via the PyGhidra runtime. Models read/write/edit after Claude Code's
 * ergonomics: chunked numbered reads and targeted in-place edits.
 *
 * <p>The five tools:
 * <ul>
 *   <li>{@code run-script} — run a script (inline {@code code} via temp file,
 *       or by {@code scriptPath} / {@code scriptName})</li>
 *   <li>{@code list-scripts} — enumerate scripts in registered directories</li>
 *   <li>{@code read-script} — {@code cat -n}-style view with offset/limit</li>
 *   <li>{@code write-script} — create/overwrite a script in a writeable dir</li>
 *   <li>{@code edit-script} — targeted {@code old_string}/{@code new_string}
 *       replacement (errors on ambiguity unless {@code replace_all})</li>
 * </ul>
 *
 * <p>Python execution requires Ghidra to be launched via PyGhidra. In standard
 * {@code ghidraRun} GUI mode {@code run-script} returns a clear error with
 * launch guidance. The file management tools work in every mode.
 */
public class ScriptToolProvider extends AbstractToolProvider {

    private static final String INLINE_HEADER = "# @runtime PyGhidra\n";

    private final PythonScriptExecutor executor;
    private final ScriptDirectoryManager dirManager;
    private final Supplier<Integer> defaultTimeoutSupplier;
    private final Supplier<Integer> outputCapSupplier;
    private final Supplier<PluginTool> activeToolSupplier;

    /**
     * Test-friendly constructor with injected collaborators.
     */
    public ScriptToolProvider(
            McpSyncServer server,
            PythonScriptExecutor executor,
            ScriptDirectoryManager dirManager,
            Supplier<Integer> defaultTimeoutSupplier,
            Supplier<Integer> outputCapSupplier) {
        this(server, executor, dirManager, defaultTimeoutSupplier,
            outputCapSupplier, ScriptToolProvider::defaultActiveToolLookup);
    }

    ScriptToolProvider(
            McpSyncServer server,
            PythonScriptExecutor executor,
            ScriptDirectoryManager dirManager,
            Supplier<Integer> defaultTimeoutSupplier,
            Supplier<Integer> outputCapSupplier,
            Supplier<PluginTool> activeToolSupplier) {
        super(server);
        this.executor = Objects.requireNonNull(executor, "executor");
        this.dirManager = Objects.requireNonNull(dirManager, "dirManager");
        this.defaultTimeoutSupplier =
            Objects.requireNonNull(defaultTimeoutSupplier, "defaultTimeoutSupplier");
        this.outputCapSupplier =
            Objects.requireNonNull(outputCapSupplier, "outputCapSupplier");
        this.activeToolSupplier =
            Objects.requireNonNull(activeToolSupplier, "activeToolSupplier");
    }

    /**
     * Production factory wiring the {@link GhidraScriptRunner} and a
     * Ghidra-derived {@link ScriptDirectoryManager}. The {@link ConfigManager}
     * is consulted on each call so live edits to the timeout / output cap
     * take effect immediately.
     */
    public static ScriptToolProvider fromGhidra(
            McpSyncServer server, ConfigManager config) {
        PythonScriptExecutor executor =
            new PythonScriptExecutor(new GhidraScriptRunner());
        ScriptDirectoryManager dirs = GhidraDirectoryFactory.build();
        Supplier<Integer> timeoutSupplier = config::getScriptTimeoutSeconds;
        Supplier<Integer> capSupplier = config::getScriptOutputCharLimit;
        return new ScriptToolProvider(
            server, executor, dirs, timeoutSupplier, capSupplier);
    }

    private static PluginTool defaultActiveToolLookup() {
        McpServerManager mgr =
            RevaInternalServiceRegistry.getService(McpServerManager.class);
        return (mgr != null) ? mgr.getActiveTool() : null;
    }

    @Override
    public void registerTools() {
        registerRunScriptTool();
        registerListScriptsTool();
        registerReadScriptTool();
        registerWriteScriptTool();
        registerEditScriptTool();
    }

    /** Public accessor for tests; returns the registered tool list. */
    public List<Tool> getRegisteredTools() {
        return Collections.unmodifiableList(registeredTools);
    }

    // -------- run-script --------

    private void registerRunScriptTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath",
            SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("code", SchemaUtil.stringProperty(
            "Inline Python source. The script runs as a Ghidra script with "
            + "currentProgram, FlatProgramAPI helpers, and monitor available. "
            + "ReVa wraps the run in one transaction: edits need no "
            + "startTransaction call, a clean run commits as a single undo "
            + "entry, and a run that throws or times out rolls back "
            + "completely. A script may still open its own transaction; its "
            + "entries join that unit, and ending one with commit=false rolls "
            + "the whole run back. "
            + "Provide exactly one of: code, scriptPath, scriptName."));
        properties.put("scriptPath", SchemaUtil.stringProperty(
            "Absolute path to an existing .py script to run. A bare file "
            + "name (no directory) is treated as scriptName."));
        properties.put("scriptName", SchemaUtil.stringProperty(
            "Name of a script (e.g., 'MyAnalysis.py') resolved across "
            + "registered Ghidra script directories."));
        properties.put("timeoutSeconds", SchemaUtil.integerPropertyWithDefault(
            "Per-call timeout override in seconds. Defaults to the configured "
            + "script timeout.", defaultTimeoutSupplier.get()));

        Tool tool = Tool.builder()
            .name("run-script")
            .title("Run Python Script")
            .description(
                "Execute a Python script in the Ghidra PyGhidra runtime "
                + "against a specific program. Requires Ghidra to be launched "
                + "via PyGhidra (mcp-reva or pyghidra-gui). Returns captured "
                + "stdout/stderr, duration, and timeout flag. Script failures "
                + "appear in stderr with success=false; tool failures (bad "
                + "args, PyGhidra unavailable) are MCP errors. The whole run is "
                + "one transaction: edits need no startTransaction call, a "
                + "clean run commits as a single undo entry, and a run that "
                + "throws or times out rolls back every change. The result's "
                + "transaction field is committed, rolled back (also when the "
                + "script aborted the run itself), or open (a transaction left "
                + "to running auto-analysis). Entries a "
                + "script left open are ended after the run and reported as "
                + "transactionLeaked=true with a note in stderr; the run's own "
                + "entry is ended first, so a failed run's changes are rolled "
                + "back, not committed. If auto-analysis is still running when "
                + "the script returns, an open transaction is left to it and "
                + "reported as transactionOpen=true. run-script waits up to 30 "
                + "seconds for an in-flight operation (another writer's "
                + "transaction, running auto-analysis) to finish; a result that "
                + "is still busy carries success=false, busy=true and "
                + "transaction=\"refused\" — wait for the in-flight operation to "
                + "finish and retry rather than retrying immediately. "
                + "Cancellation is "
                + "cooperative: every loop needs a bounded exit and a call to "
                + "monitor.checkCancelled() inside it and after long native calls; "
                + "timeoutSeconds takes effect only when control returns to Python. "
                + "A script that never returns to the monitor cannot be forcibly stopped.")
            .inputSchema(createSchema(properties, List.of("programPath")))
            .build();

        registerTool(tool, (exchange, request) -> {
            String code = getOptionalString(request, "code", null);
            // Same rule as the other script tools: a bare file name given as
            // scriptPath is a scriptName, not a path against the JVM cwd.
            String[] merged = mergeBareName(
                getOptionalString(request, "scriptPath", null),
                getOptionalString(request, "scriptName", null));
            String scriptPath = merged[0];
            String scriptName = merged[1];

            validateRunSources(code, scriptPath, scriptName);
            Program program = getProgramFromArgs(request);

            int timeoutSeconds = getOptionalInt(
                request, "timeoutSeconds", defaultTimeoutSupplier.get());
            int outputCap = outputCapSupplier.get();
            PluginTool tool0 = activeToolSupplier.get();

            Path tempFile = null;
            ResourceFile scriptFile;
            String sourceType;
            String sourceValue;
            try {
                if (code != null) {
                    tempFile = Files.createTempFile("reva_", ".py");
                    Files.writeString(tempFile, INLINE_HEADER + code);
                    scriptFile = new ResourceFile(tempFile.toFile());
                    sourceType = "inline";
                    sourceValue = "<inline>";
                } else if (scriptPath != null) {
                    Path p = Paths.get(scriptPath).toAbsolutePath().normalize();
                    if (!Files.isRegularFile(p)) {
                        throw new IllegalArgumentException(
                            "Script not found: " + scriptPath);
                    }
                    if (!dirManager.isInsideReadableDirectory(p)) {
                        throw new IllegalArgumentException(
                            "Refusing to run script outside registered "
                            + "script directories: " + scriptPath);
                    }
                    scriptFile = new ResourceFile(p.toFile());
                    sourceType = "path";
                    sourceValue = p.toString();
                } else {
                    Path resolved = dirManager.findScriptByName(scriptName)
                        .orElseThrow(() -> new IllegalArgumentException(
                            "Script not found: " + scriptName));
                    scriptFile = new ResourceFile(resolved.toFile());
                    sourceType = "name";
                    sourceValue = scriptName;
                }

                try {
                    Result result = executor.execute(
                        scriptFile, program, tool0, timeoutSeconds, outputCap);
                    return createJsonResult(buildRunResult(
                        program, result, sourceType, sourceValue));
                } catch (PyGhidraNotAvailableException e) {
                    return createErrorResult(e.getMessage());
                }
            } catch (IOException e) {
                throw new RuntimeException(
                    "Failed to write temporary script: " + e.getMessage(), e);
            } finally {
                if (tempFile != null) {
                    try {
                        Files.deleteIfExists(tempFile);
                    } catch (IOException ignored) {
                        // best-effort cleanup
                    }
                }
            }
        });
    }

    private static final String LEAK_NOTE_FORMAT =
        "ReVa closed %d transaction(s) the script left open; changes were "
        + "committed. Scripts must end every transaction they start (try/finally).";
    private static final String ROLLED_BACK_NOTE_FORMAT =
        "ReVa closed %d transaction(s) the script left open; the run's "
        + "transaction was aborted (a failed or cancelled run, or an entry "
        + "ended with commit=false), so its changes were rolled back. "
        + "Scripts must end every transaction they start (try/finally).";
    private static final String ABORTED_RUN_NOTE =
        "The run's transaction was aborted (a failed or cancelled run, or the "
        + "script ended an entry with commit=false), so its changes were rolled "
        + "back.";
    private static final String LEFT_OPEN_FOR_ANALYSIS_NOTE =
        "A transaction is still open while auto-analysis runs; ReVa did not close it.";
    private static final String TERMINATED_NOTE =
        "ReVa could not close a transaction the script terminated with "
        + "forceLock; the program may stay locked until the session ends.";

    /**
     * Error text for a busy refusal: the reason the program was still busy,
     * plus what to do about it. A model that only sees "busy" retries at once
     * (trial 3: every busy refusal was answered by an immediate retry), so
     * the guidance rides along with the result.
     */
    static final String BUSY_ERROR_FORMAT =
        "Program is busy: %s. Wait for the in-flight operation to finish, then "
        + "call run-script again. analysis-status shows auto-analysis "
        + "progress. Do not retry in a tight loop.";

    /** Package-private for tests. */
    static Map<String, Object> buildRunResult(
            Program program, Result r, String sourceType, String sourceValue) {
        Map<String, Object> source = new HashMap<>();
        source.put("type", sourceType);
        source.put("value", sourceValue);

        // One shared check with the executor's commit decision: PyGhidra
        // reports Python failures only through the traceback text, so using
        // the same predicate here keeps success:false and transaction
        // "rolled back" from ever disagreeing.
        boolean pythonRaised = PythonScriptExecutor.containsPythonTraceback(r.stderr());

        // A busy refusal is not a run that failed: nothing ran, and the
        // caller may retry once the in-flight writer finishes. Marking it
        // keeps "wait and retry" distinguishable from "the script broke".
        ProgramBusyException busy = r.executionError() instanceof ProgramBusyException b
            ? b : null;

        Map<String, Object> out = new HashMap<>();
        out.put("success",
            r.executionError() == null && !r.timedOut() && !pythonRaised);
        out.put("programPath", program.getDomainFile().getPathname());
        out.put("stdout", r.stdout());
        String stderr = r.stderr();
        if (r.leakedTransactions() > 0) {
            out.put("transactionLeaked", true);
            stderr = appendLine(stderr, String.format(
                r.transactionRolledBack() ? ROLLED_BACK_NOTE_FORMAT : LEAK_NOTE_FORMAT,
                r.leakedTransactions()));
        } else if (r.transactionRolledBack()) {
            // Nothing to close, but the transaction was aborted: say so, or
            // the model sees only success:false without knowing why.
            stderr = appendLine(stderr, ABORTED_RUN_NOTE);
        }
        if (r.transactionLeftOpen()) {
            out.put("transactionOpen", true);
            stderr = appendLine(stderr, LEFT_OPEN_FOR_ANALYSIS_NOTE);
        }
        if (r.transactionTerminated()) {
            out.put("transactionTerminated", true);
            stderr = appendLine(stderr, TERMINATED_NOTE);
        }
        // The parent entry's own commit flag is not the outcome: Ghidra aborts
        // the whole transaction when any entry ends with commit=false, so a
        // script's own rollback wins over a committed parent entry. A refused
        // run started no transaction at all — reporting it as "rolled back"
        // would describe an abort that never happened.
        if (busy != null) {
            out.put("busy", true);
            out.put("transaction", "refused");
        } else {
            out.put("transaction",
                r.transactionLeftOpen() ? "open"
                    : (r.parentCommitted() && !r.transactionRolledBack()
                        ? "committed" : "rolled back"));
        }
        out.put("stderr", stderr);
        out.put("stdoutTruncated", r.stdoutTruncated());
        out.put("stderrTruncated", r.stderrTruncated());
        out.put("durationMs", r.durationMs());
        out.put("timedOut", r.timedOut());
        out.put("scriptSource", source);
        if (busy != null) {
            out.put("error", String.format(BUSY_ERROR_FORMAT, busy.reason()));
        } else if (r.executionError() != null) {
            out.put("error", pythonRaised && !r.timedOut()
                ? "Python exception: " + raisedLine(r.stderr())
                : describe(r.executionError()));
        }
        return out;
    }

    /**
     * The exception line of the traceback in {@code stderr} — type and
     * message, e.g. {@code TypeError: No matching overloads found for ...} —
     * which is what actually says why the script failed. The whole traceback
     * stays in the result's stderr field.
     */
    private static String raisedLine(String stderr) {
        String line = PythonTracebacks.summary(stderr);
        return line == null ? "(unrecognized traceback; see stderr)" : line;
    }

    /**
     * {@code SimpleName: message}. A null message renders as an explicit
     * note instead of {@code SimpleName: null}, which reads like a bug in
     * the tool and says nothing about the failure.
     */
    private static String describe(Throwable error) {
        String message = error.getMessage();
        if (message == null || message.isBlank()) {
            return error.getClass().getSimpleName() + ": (no message; see stderr)";
        }
        return error.getClass().getSimpleName() + ": " + message;
    }

    private static String appendLine(String text, String line) {
        String sep = text.isEmpty() || text.endsWith("\n") ? "" : "\n";
        return text + sep + line;
    }

    // -------- list-scripts --------

    private void registerListScriptsTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("pathFilter", SchemaUtil.stringPropertyWithDefault(
            "Optional substring filter on script absolute path", ""));
        properties.put("nameFilter", SchemaUtil.stringPropertyWithDefault(
            "Optional substring filter on script file name", ""));
        properties.put("startIndex", SchemaUtil.integerPropertyWithDefault(
            "Pagination start (0-indexed)", 0));
        properties.put("maxCount", SchemaUtil.integerPropertyWithDefault(
            "Maximum entries to return", 100));

        Tool tool = Tool.builder()
            .name("list-scripts")
            .title("List Scripts")
            .description(
                "List Python scripts visible to Ghidra across all registered "
                + "script directories (user dir + system dirs + bundle dirs). "
                + "Filterable by path or name; supports pagination.")
            .inputSchema(createSchema(properties, List.of()))
            .build();

        registerTool(tool, (exchange, request) -> {
            String pathFilter = getOptionalString(request, "pathFilter", "");
            String nameFilter = getOptionalString(request, "nameFilter", "");
            int startIndex = getOptionalInt(request, "startIndex", 0);
            int maxCount = getOptionalInt(request, "maxCount", 100);
            validatePaginationArgs(startIndex, maxCount);

            List<Path> all = dirManager.listAllScripts();
            List<Map<String, Object>> matching = new ArrayList<>();
            for (Path p : all) {
                String absolute = p.toString();
                String name = p.getFileName().toString();
                if (!pathFilter.isEmpty() && !absolute.contains(pathFilter)) continue;
                if (!nameFilter.isEmpty() && !name.contains(nameFilter)) continue;
                Map<String, Object> entry = new HashMap<>();
                entry.put("name", name);
                entry.put("absolutePath", absolute);
                entry.put("directory", p.getParent().toString());
                entry.put("writeable", dirManager.isInsideWriteableDirectory(p));
                matching.add(entry);
            }

            int total = matching.size();
            int end = (int) Math.min((long) total, (long) startIndex + (long) maxCount);
            List<Map<String, Object>> page = (startIndex < total)
                ? matching.subList(startIndex, end)
                : List.of();

            Map<String, Object> response = new HashMap<>();
            response.put("scripts", page);
            response.put("total", total);
            response.put("startIndex", startIndex);
            response.put("returned", page.size());
            return createJsonResult(response);
        });
    }

    static void validatePaginationArgs(int startIndex, int maxCount) {
        if (startIndex < 0) {
            throw new IllegalArgumentException("startIndex must be >= 0");
        }
        if (maxCount < 1) {
            throw new IllegalArgumentException("maxCount must be >= 1");
        }
    }

    // -------- read-script --------

    private void registerReadScriptTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("scriptPath", SchemaUtil.stringProperty(
            "Absolute path to the script. Provide either scriptPath or scriptName."));
        properties.put("scriptName", SchemaUtil.stringProperty(
            "Script file name resolved across registered script directories."));
        properties.put("offset", SchemaUtil.integerPropertyWithDefault(
            "1-indexed starting line", 1));
        properties.put("limit", SchemaUtil.integerPropertyWithDefault(
            "Maximum lines to return", 2000));

        Tool tool = Tool.builder()
            .name("read-script")
            .title("Read Script")
            .description(
                "Read a script's source, returned with cat -n style line "
                + "numbers so you can reference exact lines in edit-script. "
                + "Supports chunked reads via offset/limit. Sets truncated=true "
                + "if more lines remain.")
            .inputSchema(createSchema(properties, List.of()))
            .build();

        registerTool(tool, (exchange, request) -> {
            Path target = resolveReadTarget(request);
            int offset = getOptionalInt(request, "offset", 1);
            int limit = getOptionalInt(request, "limit", 2000);
            try {
                String content = Files.readString(target);
                RenderedView view = ScriptFileEditor.renderWithLineNumbers(
                    content, offset, limit);
                Map<String, Object> resp = new HashMap<>();
                resp.put("absolutePath", target.toString());
                resp.put("contents", view.text());
                resp.put("totalLines", view.totalLines());
                resp.put("startLine", view.startLine());
                resp.put("endLine", view.endLine());
                resp.put("truncated", view.truncated());
                return createJsonResult(resp);
            } catch (IOException e) {
                throw new RuntimeException("Failed to read script: " + e.getMessage(), e);
            }
        });
    }

    private Path resolveReadTarget(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String scriptPath = getOptionalString(request, "scriptPath", null);
        String scriptName = getOptionalString(request, "scriptName", null);
        String[] merged = mergeBareName(scriptPath, scriptName);
        scriptPath = merged[0];
        scriptName = merged[1];
        if ((scriptPath == null) == (scriptName == null)) {
            throw new IllegalArgumentException(missingOrBothScriptMessage());
        }
        if (scriptPath != null) {
            Path p = Paths.get(scriptPath).toAbsolutePath().normalize();
            if (!Files.isRegularFile(p)) {
                throw new IllegalArgumentException("Script not found: " + scriptPath);
            }
            if (!dirManager.isInsideReadableDirectory(p)) {
                throw new IllegalArgumentException(
                    "Refusing to read script outside registered script "
                    + "directories: " + scriptPath);
            }
            return p;
        }
        final String nameFinal = scriptName;
        return dirManager.findScriptByName(nameFinal)
            .orElseThrow(() -> new IllegalArgumentException(
                "Script not found: " + nameFinal));
    }

    // -------- write-script --------

    private void registerWriteScriptTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("scriptName", SchemaUtil.stringProperty(
            "File name (e.g., 'MyAnalysis.py') — written to the default "
            + "writeable scripts directory."));
        properties.put("scriptPath", SchemaUtil.stringProperty(
            "Absolute path; must resolve under a writeable script directory."));
        properties.put("code", SchemaUtil.stringProperty("Script source to write."));
        properties.put("programPath", SchemaUtil.stringProperty(
            "Optional. Echoed into the result run hint so the follow-up "
            + "run-script call is ready to send."));
        properties.put("overwrite", SchemaUtil.booleanPropertyWithDefault(
            "Overwrite existing file. Default false: errors if file exists.",
            false));

        Tool tool = Tool.builder()
            .name("write-script")
            .title("Write Script")
            .description(
                "Create a new script or fully replace an existing one in a "
                + "writeable script directory. System directories are read-only. "
                + "Use edit-script for targeted changes instead of full rewrites.")
            .inputSchema(createSchema(properties, List.of("code")))
            .build();

        registerTool(tool, (exchange, request) -> {
            String code = getString(request, "code");
            boolean overwrite = getOptionalBoolean(request, "overwrite", false);
            Path target = resolveWriteTarget(request);

            boolean existed = Files.isRegularFile(target);
            if (existed && !overwrite) {
                throw new IllegalArgumentException(
                    "Script already exists: " + target
                    + " (set overwrite: true to replace)");
            }
            try {
                Files.createDirectories(target.getParent());
                Files.writeString(target, code);
                Map<String, Object> resp = new HashMap<>();
                resp.put("success", true);
                resp.put("absolutePath", target.toString());
                resp.put("bytesWritten", code.getBytes(StandardCharsets.UTF_8).length);
                resp.put("overwrote", existed);
                String runName = target.getFileName().toString();
                resp.put("run", buildRunHint(runName,
                    getOptionalString(request, "programPath", null)));
                resp.put("note", "Run it with run-script, scriptName=\""
                    + runName + "\".");
                return createJsonResult(resp);
            } catch (IOException e) {
                throw new RuntimeException("Failed to write script: " + e.getMessage(), e);
            }
        });
    }

    Path resolveWriteTarget(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String scriptPath = getOptionalString(request, "scriptPath", null);
        String scriptName = getOptionalString(request, "scriptName", null);
        String[] merged = mergeBareName(scriptPath, scriptName);
        scriptPath = merged[0];
        scriptName = merged[1];
        if (scriptPath == null && scriptName == null) {
            throw new IllegalArgumentException(
                "Provide scriptName (a bare file name; it goes in "
                + dirManager.getDefaultWriteDirectory()
                + ") or scriptPath.");
        }
        if (scriptPath != null && scriptName != null) {
            throw new IllegalArgumentException(missingOrBothScriptMessage());
        }
        Path p;
        if (scriptPath != null) {
            p = Paths.get(scriptPath).toAbsolutePath().normalize();
        } else {
            p = dirManager.getDefaultWriteDirectory().resolve(scriptName)
                .toAbsolutePath().normalize();
        }
        if (!dirManager.isInsideWriteableDirectory(p)) {
            String dirs = dirManager.getWriteableDirectories().stream()
                .map(Path::toString)
                .collect(java.util.stream.Collectors.joining(", "));
            Path base = p.getFileName();
            throw new IllegalArgumentException(
                "Refusing to write outside the writeable script directories ("
                + dirs + "): " + p + ". Use scriptName: \""
                + (base == null ? p.toString() : base.toString())
                + "\" to write it there.");
        }
        return p;
    }

    private static boolean hasSeparator(String s) {
        return s.indexOf('/') >= 0 || s.indexOf('\\') >= 0;
    }

    /**
     * A scriptPath without a directory separator is a bare file name: treat
     * it as scriptName. If scriptName is also given and equal, accept; if it
     * differs, leave both set so the caller reports the conflict.
     */
    private static String[] mergeBareName(String scriptPath, String scriptName) {
        if (scriptPath != null && !hasSeparator(scriptPath)) {
            if (scriptName == null || scriptName.equals(scriptPath)) {
                return new String[] {null, scriptPath};
            }
        }
        return new String[] {scriptPath, scriptName};
    }

    private static String missingOrBothScriptMessage() {
        return "Provide exactly one of: scriptPath, scriptName (a bare file "
            + "name is accepted as either).";
    }

    static void validateRunSources(String code, String scriptPath, String scriptName) {
        List<String> given = new java.util.ArrayList<>();
        if (code != null) given.add("code");
        if (scriptPath != null) given.add("scriptPath");
        if (scriptName != null) given.add("scriptName");
        if (given.isEmpty()) {
            throw new IllegalArgumentException(
                "Provide exactly one of: code (inline Python), scriptName "
                + "(a file written with write-script, e.g. scriptName: "
                + "\"annotate.py\"), or scriptPath (an absolute path). "
                + "Got none.");
        }
        if (given.size() > 1) {
            throw new IllegalArgumentException(
                "Provide exactly one of: code, scriptPath, scriptName. Got: "
                + String.join(", ", given) + ". Drop the others.");
        }
    }

    static Map<String, Object> buildRunHint(String name, String programPath) {
        Map<String, Object> run = new java.util.LinkedHashMap<>();
        run.put("tool", "run-script");
        run.put("scriptName", name);
        if (programPath != null) {
            run.put("programPath", programPath);
        }
        return run;
    }

    // -------- edit-script --------

    private void registerEditScriptTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("scriptName", SchemaUtil.stringProperty(
            "Script file name resolved under the default writeable scripts "
            + "directory."));
        properties.put("scriptPath", SchemaUtil.stringProperty(
            "Absolute path to the script to edit (must be writeable)."));
        properties.put("old_string", SchemaUtil.stringProperty(
            "Exact text to find. Must occur exactly once unless replace_all "
            + "is true; surround with enough context to make it unique."));
        properties.put("new_string", SchemaUtil.stringProperty(
            "Replacement text. Must differ from old_string."));
        properties.put("replace_all", SchemaUtil.booleanPropertyWithDefault(
            "Replace every occurrence. Default false: errors if old_string "
            + "matches more than one location.",
            false));

        Tool tool = Tool.builder()
            .name("edit-script")
            .title("Edit Script")
            .description(
                "Replace exact old_string with new_string in a script. "
                + "Errors if old_string isn't found, or if it matches multiple "
                + "locations and replace_all is false. Use this instead of "
                + "write-script when iterating on an existing script.")
            .inputSchema(createSchema(properties,
                List.of("old_string", "new_string")))
            .build();

        registerTool(tool, (exchange, request) -> {
            String oldString = getString(request, "old_string");
            String newString = getString(request, "new_string");
            boolean replaceAll = getOptionalBoolean(request, "replace_all", false);
            Path target = resolveWriteTarget(request);

            if (!Files.isRegularFile(target)) {
                throw new IllegalArgumentException("Script not found: " + target);
            }

            try {
                String original = Files.readString(target);
                EditResult edit = ScriptFileEditor.applyEdit(
                    original, oldString, newString, replaceAll);
                Files.writeString(target, edit.newContent());

                Map<String, Object> resp = new HashMap<>();
                resp.put("success", true);
                resp.put("absolutePath", target.toString());
                resp.put("replacements", edit.replacements());
                resp.put("newSizeBytes", edit.newContent().getBytes(StandardCharsets.UTF_8).length);
                return createJsonResult(resp);
            } catch (IOException e) {
                throw new RuntimeException("Failed to edit script: " + e.getMessage(), e);
            }
        });
    }
}
