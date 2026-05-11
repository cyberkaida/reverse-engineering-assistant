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
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema.Tool;

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
        List<String> required = runScript.inputSchema().required();
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
        Object props = readScript.inputSchema().properties();
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> properties =
            (java.util.Map<String, Object>) props;
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
        List<String> required = editScript.inputSchema().required();
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
            (java.util.Map<String, Object>) writeScript.inputSchema().properties();
        assertTrue("write-script must expose overwrite flag",
            properties.containsKey("overwrite"));
    }

    /**
     * Pins the exact PyGhidra traceback marker. If PyGhidra ever changes the
     * prefix, this test flips loudly instead of {@code success=true} silently
     * regressing for failing scripts (the original e2e bug we fixed).
     */
    @Test
    public void detectsPythonTracebackMarker() {
        assertEquals(
            "Traceback (most recent call last)",
            ScriptToolProvider.PYTHON_TRACEBACK_MARKER);
        assertTrue(ScriptToolProvider.detectsPythonRaise(
            "Traceback (most recent call last):\n  File ..."));
        assertTrue("marker may appear mid-stream after other output",
            ScriptToolProvider.detectsPythonRaise(
                "noise\nTraceback (most recent call last):\n..."));
        assertFalse(ScriptToolProvider.detectsPythonRaise(""));
        assertFalse(ScriptToolProvider.detectsPythonRaise(null));
        assertFalse("plain stderr without a Python traceback must not trip",
            ScriptToolProvider.detectsPythonRaise(
                "warning: deprecated API used"));
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
