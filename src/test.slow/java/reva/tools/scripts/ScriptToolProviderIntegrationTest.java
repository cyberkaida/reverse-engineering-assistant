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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptUtil;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for {@link ScriptToolProvider}.
 *
 * The gradle integrationTest JVM is not launched via PyGhidra, so {@code
 * run-script} cannot actually execute Python here. We verify:
 * <ul>
 *   <li>{@code list-scripts} discovers files in the live user scripts dir</li>
 *   <li>{@code read-script} returns {@code cat -n} numbered output, with
 *       offset/limit slicing and truncation flag</li>
 *   <li>{@code write-script} creates files; refuses paths outside writeable
 *       dirs; refuses overwriting without the flag; succeeds with the flag</li>
 *   <li>{@code edit-script} replaces unique substrings; rejects ambiguity;
 *       handles replace_all</li>
 *   <li>{@code run-script} returns a clear error mentioning PyGhidra when
 *       the runtime is unavailable</li>
 * </ul>
 *
 * Real Python execution is covered by Python e2e tests via {@code mcp-reva}.
 */
public class ScriptToolProviderIntegrationTest extends RevaIntegrationTestBase {

    /** Unique prefix so we can find & delete just our test artifacts. */
    private static final String FIXTURE_PREFIX = "reva_it_";

    private String programPath;
    private final List<Path> createdScripts = new ArrayList<>();
    private Path userScriptsDir;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();
        env.open(program);
        ghidra.app.services.ProgramManager pm =
            tool.getService(ghidra.app.services.ProgramManager.class);
        if (pm != null) {
            pm.openProgram(program);
        }
        if (serverManager != null) {
            serverManager.programOpened(program, tool);
        }

        ResourceFile userDir = GhidraScriptUtil.getUserScriptDirectory();
        userScriptsDir = userDir.getFile(false).toPath();
        Files.createDirectories(userScriptsDir);
    }

    @After
    public void cleanUpScripts() {
        for (Path p : createdScripts) {
            try {
                Files.deleteIfExists(p);
            } catch (IOException ignored) {
                // best-effort
            }
        }
        createdScripts.clear();
    }

    private String uniqueName(String suffix) {
        return FIXTURE_PREFIX + UUID.randomUUID().toString().substring(0, 8)
            + "_" + suffix + ".py";
    }

    // -------- write-script --------

    @Test
    public void writeScriptCreatesFileInUserDir() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                String name = uniqueName("write_create");
                Map<String, Object> args = new HashMap<>();
                args.put("scriptName", name);
                args.put("code", "print('hello')\n");

                CallToolResult result =
                    client.callTool(new CallToolRequest("write-script", args));
                assertMcpResultNotError(result, "write-script should succeed");
                JsonNode resp = parseJsonContent(
                    ((TextContent) result.content().get(0)).text());

                String absolutePath = resp.get("absolutePath").asText();
                Path written = Path.of(absolutePath);
                createdScripts.add(written);

                assertTrue("file should exist on disk", Files.isRegularFile(written));
                assertEquals("print('hello')\n", Files.readString(written));
                assertFalse(resp.get("overwrote").asBoolean());
                assertTrue(resp.get("bytesWritten").asInt() > 0);
                assertTrue(absolutePath.startsWith(userScriptsDir.toString()));
            } catch (Exception e) {
                fail("test failed: " + e);
            }
        });
    }

    @Test
    public void writeScriptRefusesOverwriteByDefault() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                String name = uniqueName("write_no_overwrite");
                Path target = userScriptsDir.resolve(name);
                Files.writeString(target, "original\n");
                createdScripts.add(target);

                Map<String, Object> args = new HashMap<>();
                args.put("scriptName", name);
                args.put("code", "replaced\n");

                CallToolResult result =
                    client.callTool(new CallToolRequest("write-script", args));
                assertTrue("should error without overwrite", result.isError());
                assertEquals("original\n", Files.readString(target));
            } catch (Exception e) {
                fail("test failed: " + e);
            }
        });
    }

    @Test
    public void writeScriptAllowsOverwriteWithFlag() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                String name = uniqueName("write_overwrite");
                Path target = userScriptsDir.resolve(name);
                Files.writeString(target, "original\n");
                createdScripts.add(target);

                Map<String, Object> args = new HashMap<>();
                args.put("scriptName", name);
                args.put("code", "replaced\n");
                args.put("overwrite", true);

                CallToolResult result =
                    client.callTool(new CallToolRequest("write-script", args));
                assertMcpResultNotError(result, "should succeed with overwrite");
                assertEquals("replaced\n", Files.readString(target));

                JsonNode resp = parseJsonContent(
                    ((TextContent) result.content().get(0)).text());
                assertTrue("overwrote flag should be set", resp.get("overwrote").asBoolean());
            } catch (Exception e) {
                fail("test failed: " + e);
            }
        });
    }

    @Test
    public void writeScriptRefusesPathOutsideWriteableDirectories() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                Path outside = Files.createTempFile(FIXTURE_PREFIX + "outside_", ".py");
                createdScripts.add(outside);

                Map<String, Object> args = new HashMap<>();
                args.put("scriptPath", outside.toString());
                args.put("code", "evil\n");
                args.put("overwrite", true);

                CallToolResult result =
                    client.callTool(new CallToolRequest("write-script", args));
                assertTrue("should refuse path outside writeable dir", result.isError());
                // ensure no content written
                assertEquals("", Files.readString(outside));
            } catch (Exception e) {
                fail("test failed: " + e);
            }
        });
    }

    // -------- read-script --------

    @Test
    public void readScriptReturnsCatNStyleNumberedOutput() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                String name = uniqueName("read_basic");
                Path target = userScriptsDir.resolve(name);
                Files.writeString(target, "alpha\nbeta\ngamma\n");
                createdScripts.add(target);

                Map<String, Object> args = new HashMap<>();
                args.put("scriptName", name);

                CallToolResult result =
                    client.callTool(new CallToolRequest("read-script", args));
                assertMcpResultNotError(result, "read-script should succeed");
                JsonNode resp = parseJsonContent(
                    ((TextContent) result.content().get(0)).text());
                assertEquals("1\talpha\n2\tbeta\n3\tgamma\n",
                    resp.get("contents").asText());
                assertEquals(3, resp.get("totalLines").asInt());
                assertFalse(resp.get("truncated").asBoolean());
            } catch (Exception e) {
                fail("test failed: " + e);
            }
        });
    }

    @Test
    public void readScriptHonoursOffsetAndLimitAndReportsTruncation() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                String name = uniqueName("read_slice");
                Path target = userScriptsDir.resolve(name);
                Files.writeString(target, "a\nb\nc\nd\ne\n");
                createdScripts.add(target);

                Map<String, Object> args = new HashMap<>();
                args.put("scriptName", name);
                args.put("offset", 2);
                args.put("limit", 2);

                CallToolResult result =
                    client.callTool(new CallToolRequest("read-script", args));
                assertMcpResultNotError(result, "read-script should succeed");
                JsonNode resp = parseJsonContent(
                    ((TextContent) result.content().get(0)).text());
                assertEquals("2\tb\n3\tc\n", resp.get("contents").asText());
                assertEquals(5, resp.get("totalLines").asInt());
                assertEquals(2, resp.get("startLine").asInt());
                assertEquals(3, resp.get("endLine").asInt());
                assertTrue("more lines remain", resp.get("truncated").asBoolean());
            } catch (Exception e) {
                fail("test failed: " + e);
            }
        });
    }

    // -------- edit-script --------

    @Test
    public void editScriptReplacesUniqueOccurrence() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                String name = uniqueName("edit_unique");
                Path target = userScriptsDir.resolve(name);
                Files.writeString(target, "print('hello')\nprint('world')\n");
                createdScripts.add(target);

                Map<String, Object> args = new HashMap<>();
                args.put("scriptName", name);
                args.put("old_string", "hello");
                args.put("new_string", "greetings");

                CallToolResult result =
                    client.callTool(new CallToolRequest("edit-script", args));
                assertMcpResultNotError(result, "edit-script should succeed");
                assertEquals("print('greetings')\nprint('world')\n",
                    Files.readString(target));
            } catch (Exception e) {
                fail("test failed: " + e);
            }
        });
    }

    @Test
    public void editScriptRefusesAmbiguousMatch() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                String name = uniqueName("edit_ambiguous");
                Path target = userScriptsDir.resolve(name);
                Files.writeString(target, "x = 1\ny = x + x\n");
                createdScripts.add(target);

                Map<String, Object> args = new HashMap<>();
                args.put("scriptName", name);
                args.put("old_string", "x");
                args.put("new_string", "z");

                CallToolResult result =
                    client.callTool(new CallToolRequest("edit-script", args));
                assertTrue("ambiguous match must error", result.isError());
                // File unchanged
                assertEquals("x = 1\ny = x + x\n", Files.readString(target));
            } catch (Exception e) {
                fail("test failed: " + e);
            }
        });
    }

    @Test
    public void editScriptReplaceAllReplacesEvery() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                String name = uniqueName("edit_replace_all");
                Path target = userScriptsDir.resolve(name);
                Files.writeString(target, "x = 1\ny = x + x\n");
                createdScripts.add(target);

                Map<String, Object> args = new HashMap<>();
                args.put("scriptName", name);
                args.put("old_string", "x");
                args.put("new_string", "z");
                args.put("replace_all", true);

                CallToolResult result =
                    client.callTool(new CallToolRequest("edit-script", args));
                assertMcpResultNotError(result, "replace_all should succeed");
                assertEquals("z = 1\ny = z + z\n", Files.readString(target));

                JsonNode resp = parseJsonContent(
                    ((TextContent) result.content().get(0)).text());
                assertEquals(3, resp.get("replacements").asInt());
            } catch (Exception e) {
                fail("test failed: " + e);
            }
        });
    }

    // -------- list-scripts --------

    @Test
    public void listScriptsFindsWrittenFile() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                String name = uniqueName("list_visible");
                Path target = userScriptsDir.resolve(name);
                Files.writeString(target, "# pass\n");
                createdScripts.add(target);

                Map<String, Object> args = new HashMap<>();
                args.put("nameFilter", FIXTURE_PREFIX);
                args.put("maxCount", 1000);

                CallToolResult result =
                    client.callTool(new CallToolRequest("list-scripts", args));
                assertMcpResultNotError(result, "list-scripts should succeed");
                JsonNode resp = parseJsonContent(
                    ((TextContent) result.content().get(0)).text());
                JsonNode scripts = resp.get("scripts");
                boolean found = false;
                for (JsonNode entry : scripts) {
                    if (entry.get("name").asText().equals(name)) {
                        found = true;
                        assertTrue(entry.get("writeable").asBoolean());
                        break;
                    }
                }
                assertTrue("listing must include written file", found);
            } catch (Exception e) {
                fail("test failed: " + e);
            }
        });
    }

    // -------- run-script: PyGhidra unavailable --------

    @Test
    public void runScriptReportsPyGhidraUnavailableInGradleJvm() throws Exception {
        // The gradle integrationTest JVM is launched via vanilla Java, so
        // PyGhidraScriptProvider.scriptRunner is null and run-script must
        // return a clear, actionable error.
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();
                Map<String, Object> args = new HashMap<>();
                args.put("programPath", programPath);
                args.put("code", "print('would not run')\n");

                CallToolResult result =
                    client.callTool(new CallToolRequest("run-script", args));
                assertTrue("must surface a tool error in non-PyGhidra JVM",
                    result.isError());
                String message =
                    ((TextContent) result.content().get(0)).text();
                assertTrue("error must mention PyGhidra: " + message,
                    message.contains("PyGhidra"));
            } catch (Exception e) {
                fail("test failed: " + e);
            }
        });
    }
}
