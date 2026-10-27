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

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import org.mockito.ArgumentCaptor;
import reva.tools.ProgramBusyException;
import reva.tools.scripts.PythonScriptExecutor.Result;

/**
 * Unit tests for {@link ScriptToolProvider}.
 *
 * Focused on construction and tool registration: the 5 tools must be exposed
 * with the expected names. Handler behavior is covered by the helper classes
 * ({@link ScriptFileEditor}, {@link ScriptDirectoryManager}) and by integration
 * tests for the filesystem and MCP plumbing.
 */
public class ScriptToolProviderTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private McpSyncServer server;
    private ScriptDirectoryManager dirManager;
    private PythonScriptExecutor executor;
    private ScriptToolProvider provider;

    @Before
    public void setUp() throws Exception {
        server = mock(McpSyncServer.class);
        Path userDir = tmp.newFolder("user_scripts").toPath();
        dirManager = new ScriptDirectoryManager(
            List.of(userDir), List.of(userDir), userDir);
        // Fake runner — never invoked in these registration-only tests.
        executor = new PythonScriptExecutor(
            (f, p, t, out, err, monitor) -> {});
        provider = new ScriptToolProvider(server, executor, dirManager,
            () -> 60, () -> 65536);
    }

    @Test
    public void constructorDoesNotThrow() {
        assertNotNull(provider);
    }

    @Test
    public void registerToolsRegistersAllFiveByName() throws Exception {
        provider.registerTools();
        Set<String> names = registeredToolNames(provider);
        assertTrue("run-script not registered", names.contains("run-script"));
        assertTrue("list-scripts not registered", names.contains("list-scripts"));
        assertTrue("read-script not registered", names.contains("read-script"));
        assertTrue("write-script not registered", names.contains("write-script"));
        assertTrue("edit-script not registered", names.contains("edit-script"));
        assertEquals(5, names.size());
    }

    @Test
    public void runScriptSchemaRequiresProgramPath() throws Exception {
        provider.registerTools();
        Tool runScript = findTool(provider, "run-script");
        assertNotNull(runScript);
        @SuppressWarnings("unchecked")
        List<String> required = (List<String>) runScript.inputSchema().get("required");
        assertTrue(
            "run-script must require programPath",
            required.contains("programPath"));
    }

    @Test
    public void readScriptSchemaExposesOffsetAndLimit() throws Exception {
        provider.registerTools();
        Tool readScript = findTool(provider, "read-script");
        assertNotNull(readScript);
        // offset & limit are optional, so they appear in properties but not required
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> properties =
            (java.util.Map<String, Object>) readScript.inputSchema().get("properties");
        assertTrue("read-script schema should include offset",
            properties.containsKey("offset"));
        assertTrue("read-script schema should include limit",
            properties.containsKey("limit"));
    }

    @Test
    public void editScriptSchemaRequiresOldAndNewString() throws Exception {
        provider.registerTools();
        Tool editScript = findTool(provider, "edit-script");
        assertNotNull(editScript);
        @SuppressWarnings("unchecked")
        List<String> required = (List<String>) editScript.inputSchema().get("required");
        assertTrue(required.contains("old_string"));
        assertTrue(required.contains("new_string"));
    }

    @Test
    public void writeScriptSchemaIncludesOverwriteFlag() throws Exception {
        provider.registerTools();
        Tool writeScript = findTool(provider, "write-script");
        assertNotNull(writeScript);
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> properties =
            (java.util.Map<String, Object>) writeScript.inputSchema().get("properties");
        assertTrue("write-script must expose overwrite flag",
            properties.containsKey("overwrite"));
    }

    @Test
    public void validatePaginationArgsRejectsInvalidValues() {
        ScriptToolProvider.validatePaginationArgs(0, 1);
        try {
            ScriptToolProvider.validatePaginationArgs(-1, 1);
            fail("Expected IllegalArgumentException for negative startIndex");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("startIndex"));
        }
        try {
            ScriptToolProvider.validatePaginationArgs(0, 0);
            fail("Expected IllegalArgumentException for maxCount < 1");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("maxCount"));
        }
    }

    @Test
    public void editScriptSchemaDescribesDefaultWriteDirectoryForScriptName() throws Exception {
        provider.registerTools();
        Tool editScript = findTool(provider, "edit-script");
        assertNotNull(editScript);
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> properties =
            (java.util.Map<String, Object>) editScript.inputSchema().get("properties");
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> scriptNameProperty =
            (java.util.Map<String, Object>) properties.get("scriptName");
        assertNotNull(scriptNameProperty);
        String description = (String) scriptNameProperty.get("description");
        assertTrue(description.contains("default writeable scripts directory"));
    }

    /**
     * Pins the exact PyGhidra traceback marker and its shared location on
     * {@link PythonScriptExecutor}. If PyGhidra ever changes the prefix, this
     * test flips loudly instead of {@code success=true} silently regressing
     * for failing scripts (the original e2e bug we fixed).
     */
    @Test
    public void detectsPythonTracebackMarker() {
        assertEquals(
            "Traceback (most recent call last)",
            PythonScriptExecutor.PYTHON_TRACEBACK_MARKER);
        assertTrue(PythonScriptExecutor.containsPythonTraceback(
            "Traceback (most recent call last):\n  File ..."));
        assertTrue("marker may appear mid-stream after other output",
            PythonScriptExecutor.containsPythonTraceback(
                "noise\nTraceback (most recent call last):\n..."));
        assertFalse(PythonScriptExecutor.containsPythonTraceback(""));
        assertFalse(PythonScriptExecutor.containsPythonTraceback(null));
        assertFalse("plain stderr without a Python traceback must not trip",
            PythonScriptExecutor.containsPythonTraceback(
                "warning: deprecated API used"));
    }

    // ---- argument errors, bare names, run hint ----

    private CallToolResult call(String tool, Map<String, Object> args) {
        provider.registerTools();
        ArgumentCaptor<SyncToolSpecification> cap =
            ArgumentCaptor.forClass(SyncToolSpecification.class);
        verify(server, atLeastOnce()).addTool(cap.capture());
        for (SyncToolSpecification spec : cap.getAllValues()) {
            if (spec.tool().name().equals(tool)) {
                return spec.callHandler().apply(null, new CallToolRequest(tool, args));
            }
        }
        throw new AssertionError("no tool " + tool);
    }

    private static String text(CallToolResult r) {
        return ((TextContent) r.content().get(0)).text();
    }

    @Test
    public void runScriptNoSourceNamesTheOptions() {
        CallToolResult r = call("run-script", Map.of("programPath", "/x"));
        assertTrue(r.isError());
        assertTrue(text(r), text(r).contains(
            "Provide exactly one of: code (inline Python), scriptName (a file "
            + "written with write-script, e.g. scriptName: \"annotate.py\"), "
            + "or scriptPath (an absolute path). Got none."));
    }

    @Test
    public void runScriptTwoSourcesListsGiven() {
        CallToolResult r = call("run-script", Map.of(
            "programPath", "/x", "code", "pass", "scriptName", "a.py"));
        assertTrue(r.isError());
        assertTrue(text(r), text(r).contains(
            "Provide exactly one of: code, scriptPath, scriptName. Got: "
            + "code, scriptName. Drop the others."));
    }

    @Test
    public void writeScriptBareScriptPathGoesToDefaultDirectory() throws Exception {
        CallToolResult r = call("write-script", Map.of(
            "scriptPath", "x.py", "code", "print(1)"));
        assertFalse(text(r), r.isError());
        Path expected = dirManager.getDefaultWriteDirectory().resolve("x.py");
        assertTrue(java.nio.file.Files.isRegularFile(expected));
    }

    @Test
    public void writeScriptEqualBareNameAndPathAccepted() {
        CallToolResult r = call("write-script", Map.of(
            "scriptPath", "y.py", "scriptName", "y.py", "code", "pass"));
        assertFalse(text(r), r.isError());
    }

    @Test
    public void writeScriptDifferentNameAndBarePathRejected() {
        CallToolResult r = call("write-script", Map.of(
            "scriptPath", "y.py", "scriptName", "z.py", "code", "pass"));
        assertTrue(r.isError());
        assertTrue(text(r), text(r).contains("Provide exactly one of"));
    }

    @Test
    public void writeScriptMissingNameSaysWhereItGoes() {
        CallToolResult r = call("write-script", Map.of("code", "pass"));
        assertTrue(r.isError());
        assertTrue(text(r), text(r).contains(
            "Provide scriptName (a bare file name; it goes in "
            + dirManager.getDefaultWriteDirectory() + ") or scriptPath."));
    }

    @Test
    public void editScriptMissingNameSaysWhereItGoes() {
        CallToolResult r = call("edit-script", Map.of(
            "old_string", "a", "new_string", "b"));
        assertTrue(r.isError());
        assertTrue(text(r), text(r).contains("Provide scriptName (a bare file name"));
    }

    @Test
    public void writeScriptOutsidePathListsDirectoriesAndHint() {
        CallToolResult r = call("write-script", Map.of(
            "scriptPath", "/tmp/x.py", "code", "pass"));
        assertTrue(r.isError());
        String dir = dirManager.getWriteableDirectories().get(0).toString();
        assertTrue(text(r), text(r).contains(
            "Refusing to write outside the writeable script directories ("
            + dir + "): /tmp/x.py. Use scriptName: \"x.py\" to write it there."));
    }

    @Test
    public void writeScriptResultCarriesRunHint() throws Exception {
        CallToolResult r = call("write-script", Map.of(
            "scriptName", "h.py", "code", "pass", "programPath", "/prog"));
        assertFalse(text(r), r.isError());
        com.fasterxml.jackson.databind.JsonNode n =
            new com.fasterxml.jackson.databind.ObjectMapper().readTree(text(r));
        assertEquals("run-script", n.get("run").get("tool").asText());
        assertEquals("h.py", n.get("run").get("scriptName").asText());
        assertEquals("/prog", n.get("run").get("programPath").asText());
        assertEquals("Run it with run-script, scriptName=\"h.py\".",
            n.get("note").asText());
    }

    @Test
    public void writeScriptRunHintOmitsProgramPathWhenAbsent() throws Exception {
        CallToolResult r = call("write-script", Map.of(
            "scriptName", "h2.py", "code", "pass"));
        com.fasterxml.jackson.databind.JsonNode n =
            new com.fasterxml.jackson.databind.ObjectMapper().readTree(text(r));
        assertFalse(n.get("run").has("programPath"));
    }

    /** Runs run-script against a registered mock program with a recording runner. */
    private CallToolResult runScriptCapturing(Map<String, Object> args,
            java.util.concurrent.atomic.AtomicReference<String> ran) {
        ghidra.program.model.listing.Program program =
            mock(ghidra.program.model.listing.Program.class);
        ghidra.framework.model.DomainFile df = mock(ghidra.framework.model.DomainFile.class);
        when(df.getPathname()).thenReturn("/run-target");
        when(program.getDomainFile()).thenReturn(df);
        provider = new ScriptToolProvider(server,
            new PythonScriptExecutor((f, p, t, out, err, monitor) -> ran.set(f.getName())),
            dirManager, () -> 60, () -> 65536);
        reva.plugin.RevaProgramManager.registerProgram(program);
        try {
            return call("run-script", args);
        } finally {
            reva.plugin.RevaProgramManager.unregisterProgram(program);
        }
    }

    @Test
    public void runScriptBareScriptPathRunsByName() throws Exception {
        java.nio.file.Files.writeString(
            dirManager.getDefaultWriteDirectory().resolve("bare.py"), "pass\n");
        java.util.concurrent.atomic.AtomicReference<String> ran =
            new java.util.concurrent.atomic.AtomicReference<>();
        CallToolResult r = runScriptCapturing(
            Map.of("programPath", "/run-target", "scriptPath", "bare.py"), ran);

        assertFalse(text(r), r.isError());
        assertEquals("bare.py", ran.get());
        com.fasterxml.jackson.databind.JsonNode n =
            new com.fasterxml.jackson.databind.ObjectMapper().readTree(text(r));
        assertEquals("name", n.get("scriptSource").get("type").asText());
        assertEquals("bare.py", n.get("scriptSource").get("value").asText());
    }

    @Test
    public void runScriptEqualBareNameAndPathAccepted() throws Exception {
        java.nio.file.Files.writeString(
            dirManager.getDefaultWriteDirectory().resolve("same.py"), "pass\n");
        java.util.concurrent.atomic.AtomicReference<String> ran =
            new java.util.concurrent.atomic.AtomicReference<>();
        CallToolResult r = runScriptCapturing(Map.of("programPath", "/run-target",
            "scriptPath", "same.py", "scriptName", "same.py"), ran);

        assertFalse(text(r), r.isError());
        assertEquals("same.py", ran.get());
    }

    @Test
    public void runScriptDifferentNameAndBarePathRejected() {
        CallToolResult r = call("run-script", Map.of("programPath", "/x",
            "scriptPath", "a.py", "scriptName", "b.py"));
        assertTrue(r.isError());
        assertTrue(text(r), text(r).contains(
            "Provide exactly one of: code, scriptPath, scriptName. Got: "
            + "scriptPath, scriptName. Drop the others."));
    }

    @Test
    public void runScriptPythonTracebackReportsRolledBack() throws Exception {
        // The executor and buildRunResult share one traceback check, so a run
        // whose only failure signal is the stderr traceback reports both
        // success:false and transaction:"rolled back".
        ghidra.program.model.listing.Program program =
            mock(ghidra.program.model.listing.Program.class);
        ghidra.framework.model.DomainFile df = mock(ghidra.framework.model.DomainFile.class);
        when(df.getPathname()).thenReturn("/run-target");
        when(program.getDomainFile()).thenReturn(df);
        when(program.startTransaction(anyString())).thenReturn(21);
        provider = new ScriptToolProvider(server,
            new PythonScriptExecutor((f, p, t, out, err, monitor) ->
                err.print("Traceback (most recent call last):\n"
                    + "  File \"<string>\", line 1, in <module>\n"
                    + "ValueError: boom\n")),
            dirManager, () -> 60, () -> 65536);
        reva.plugin.RevaProgramManager.registerProgram(program);
        try {
            CallToolResult r = call("run-script", Map.of(
                "programPath", "/run-target", "code", "raise ValueError('boom')"));

            assertFalse(text(r), r.isError());
            com.fasterxml.jackson.databind.JsonNode n =
                new com.fasterxml.jackson.databind.ObjectMapper().readTree(text(r));
            assertFalse("a Python traceback is a failed run",
                n.get("success").asBoolean());
            assertEquals("rolled back", n.get("transaction").asText());
            assertTrue(n.get("stderr").asText().contains("ValueError"));
            verify(program).endTransaction(21, false);
        } finally {
            reva.plugin.RevaProgramManager.unregisterProgram(program);
        }
    }

    /** A program mock whose domain file reports {@code path}. */
    private static ghidra.program.model.listing.Program programWithPath(String path) {
        ghidra.program.model.listing.Program program =
            mock(ghidra.program.model.listing.Program.class);
        ghidra.framework.model.DomainFile df =
            mock(ghidra.framework.model.DomainFile.class);
        when(df.getPathname()).thenReturn(path);
        when(program.getDomainFile()).thenReturn(df);
        return program;
    }

    /** A run result with everything defaulted except stderr and the error. */
    private static Result runResult(String stderr, Throwable error) {
        return new Result("", stderr, false, false, 5, false, error,
            0, false, false, false, false);
    }

    @Test
    public void runScriptErrorCarriesTheParsedPythonException() {
        // PyGhidra's failure signal is the traceback text; the error field
        // must name the exception, not point at a generic message.
        String stderr = "Traceback (most recent call last):\n"
            + "  File \"<string>\", line 1, in <module>\n"
            + "ValueError: boom\n";

        Map<String, Object> out = ScriptToolProvider.buildRunResult(
            programWithPath("/run-target"),
            runResult(stderr, new IllegalStateException(
                PythonScriptExecutor.PYTHON_RAISED_MESSAGE)),
            "inline", "<inline>");

        assertEquals(Boolean.FALSE, out.get("success"));
        assertEquals("Python exception: ValueError: boom", out.get("error"));
        assertEquals("rolled back", out.get("transaction"));
    }

    @Test
    public void runScriptTimeoutErrorTakesPrecedenceOverPythonTraceback() {
        String stderr = "Traceback (most recent call last):\nCancelledException: cancelled\n";
        Result result = new Result("", stderr, false, false, 5, true,
            new IllegalStateException("script timed out after 3 seconds"),
            0, false, false, false, false);
        Map<String, Object> out = ScriptToolProvider.buildRunResult(
            programWithPath("/run-target"), result, "inline", "<inline>");
        assertEquals("IllegalStateException: script timed out after 3 seconds", out.get("error"));
    }

    @Test
    public void runScriptNullMessageNeverRendersAsNull() {
        // A message-less exception used to render as "SimpleName: null",
        // which says nothing about the failure.
        Map<String, Object> out = ScriptToolProvider.buildRunResult(
            programWithPath("/run-target"),
            runResult("some stderr\n", new RuntimeException()),
            "inline", "<inline>");

        assertEquals(Boolean.FALSE, out.get("success"));
        assertEquals("RuntimeException: (no message; see stderr)",
            out.get("error"));
    }

    @Test
    public void runScriptBusyResultIsMachineDetectable() {
        Map<String, Object> out = ScriptToolProvider.buildRunResult(
            programWithPath("/run-target"),
            runResult("", new ProgramBusyException(
                "a transaction is open (ReVa: Auto Analysis)")),
            "inline", "<inline>");

        assertEquals(Boolean.FALSE, out.get("success"));
        assertEquals(Boolean.TRUE, out.get("busy"));
        assertEquals("a refused run started no transaction", "refused",
            out.get("transaction"));
        String error = (String) out.get("error");
        assertTrue(error, error.startsWith(
            "Program is busy: a transaction is open (ReVa: Auto Analysis)."));
        assertTrue("the error must say what to do instead of retrying: " + error,
            error.contains("Do not retry in a tight loop."));
    }

    @Test
    public void runScriptBusyProgramReturnsBusyTrue() throws Exception {
        // End to end through the tool handler: the program stays busy for the
        // whole (here zero-length) wait, so nothing runs and the caller gets a
        // result it can branch on instead of a failed script.
        ghidra.program.model.listing.Program program = programWithPath("/run-target");
        ghidra.framework.model.TransactionInfo info =
            mock(ghidra.framework.model.TransactionInfo.class);
        when(info.getDescription()).thenReturn("ReVa: Auto Analysis");
        when(program.getCurrentTransactionInfo()).thenReturn(info);
        provider = new ScriptToolProvider(server,
            new PythonScriptExecutor(
                (f, p, t, out, err, monitor) -> { }, p -> false, 0, 1),
            dirManager, () -> 60, () -> 65536);
        reva.plugin.RevaProgramManager.registerProgram(program);
        try {
            CallToolResult r = call("run-script", Map.of(
                "programPath", "/run-target", "code", "pass"));

            assertFalse(text(r), r.isError());
            com.fasterxml.jackson.databind.JsonNode n =
                new com.fasterxml.jackson.databind.ObjectMapper().readTree(text(r));
            assertFalse(n.get("success").asBoolean());
            assertTrue(n.get("busy").asBoolean());
            assertEquals("refused", n.get("transaction").asText());
            assertTrue(n.get("error").asText(),
                n.get("error").asText().startsWith(
                    "Program is busy: a transaction is open (ReVa: Auto Analysis)."));
        } finally {
            reva.plugin.RevaProgramManager.unregisterProgram(program);
        }
    }

    @Test
    public void readScriptBareScriptPathResolvesByName() throws Exception {
        java.nio.file.Files.writeString(
            dirManager.getDefaultWriteDirectory().resolve("r.py"), "pass\n");
        CallToolResult r = call("read-script", Map.of("scriptPath", "r.py"));
        assertFalse(text(r), r.isError());
    }

    private static Set<String> registeredToolNames(ScriptToolProvider provider) {
        return provider.getRegisteredTools().stream()
            .map(Tool::name)
            .collect(Collectors.toSet());
    }

    private static Tool findTool(ScriptToolProvider provider, String name) {
        return provider.getRegisteredTools().stream()
            .filter(t -> t.name().equals(name))
            .findFirst()
            .orElse(null);
    }
}
