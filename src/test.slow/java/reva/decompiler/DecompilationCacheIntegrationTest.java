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
package reva.decompiler;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Pins that the tools read decompilations through the shared {@link DecompilationCache}.
 * Counter assertions use deltas so earlier calls do not matter.
 */
public class DecompilationCacheIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;

    @Before
    public void setUp() throws Exception {
        programPath = program.getDomainFile().getPathname();
        LineMapFixture.createLineMapFunctions(program);
        LineMapFixture.createTenCallCaller(program);

        LineMapFixture.openInTools(env, tool, serverManager, program);
    }

    private DecompilationCache cache() {
        return LineMapFixture.cache();
    }

    private JsonNode read(McpSyncClient client, Map<String, Object> extra) {
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", programPath);
        args.put("functionNameOrAddress", "lineMapFn");
        args.put("includeIncomingReferences", false);
        args.putAll(extra);
        return LineMapFixture.callJson(client, "get-decompilation", args);
    }

    private long decompilesDuring(Runnable call) {
        return LineMapFixture.decompilesDuring(call);
    }

    @Test
    public void testSecondPageCostsNoDecompile() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            cache().dropProgram(program);

            long first = decompilesDuring(() -> read(client, Map.of("offset", 1, "limit", 3)));
            long second = decompilesDuring(() -> read(client, Map.of("offset", 4, "limit", 3)));
            assertEquals("First page decompiles once", 1, first);
            assertEquals("Second page is served from the cache", 0, second);
        });
    }

    @Test
    public void testDisassemblyAndCommentsServedFromCache() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            Map<String, Object> full = Map.of("includeDisassembly", true, "includeComments", true, "limit", 200);

            cache().dropProgram(program);
            read(client, Map.of("offset", 1, "limit", 3));
            JsonNode[] warm = new JsonNode[1];
            long delta = decompilesDuring(() -> warm[0] = read(client, full));
            assertEquals("Disassembly and comments need no further decompile", 0, delta);

            cache().dropProgram(program);
            JsonNode fresh = read(client, full);
            assertEquals("Cached output equals fresh output", fresh, warm[0]);
        });
    }

    @Test
    public void testProgramCloseDropsEntries() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            cache().dropProgram(program);
            read(client, Map.of("offset", 1, "limit", 3));
            assertTrue("Entry should be cached", cache().stats().entries() > 0);

            serverManager.programClosed(program, tool);
            assertEquals("Closing the program drops its entries", 0, cache().stats().entries());
        });
    }

    /**
     * Headless release: a program that is never opened in the tool (so the plugin's programClosed never runs)
     * is closed by releasing its last consumer. The cache's close listener must drop its entries.
     */
    @Test
    public void testClosingAProgramOutsideThePluginDropsItsEntries() throws Exception {
        ghidra.program.model.listing.Program other =
            createDefaultProgram(getName() + "Closing", "x86:LE:32:default", this);
        boolean released = false;
        try {
            int txId = other.startTransaction("Add test memory");
            try {
                other.getMemory().createInitializedBlock("test",
                    other.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000),
                    0x1000, (byte) 0, ghidra.util.task.TaskMonitor.DUMMY, false);
            } finally {
                other.endTransaction(txId, true);
            }
            LineMapFixture.createLineMapFunctions(other);
            ghidra.program.model.listing.Function otherFn = other.getFunctionManager()
                .getFunctionAt(other.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000500));
            ghidra.program.model.listing.Function mainFn = program.getFunctionManager()
                .getFunctionAt(program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000500));

            cache().dropProgram(program);
            int base = cache().stats().entries();
            assertTrue(cache().get(program, mainFn).success());
            assertTrue(cache().get(other, otherFn).success());
            assertEquals("One entry per program", base + 2, cache().stats().entries());

            other.release(this);
            released = true;
            assertTrue("Releasing the last consumer closes the program", other.isClosed());

            assertEquals("The closed program's entry is gone", base + 1, cache().stats().entries());
            assertEquals("The open program's entry is still served", 0,
                decompilesDuring(() -> cache().get(program, mainFn)));
        } finally {
            if (!released) {
                other.release(this);
            }
        }
    }

    /** Runs body with a cache backed by the stub registered in place of the real one. */
    private void withStubCache(DecompilationCache.Backend backend, Runnable body) {
        LineMapFixture.withRegisteredCache(
            new DecompilationCache(backend, DecompilationCache.DEFAULT_MAX_CHARS), body);
    }

    private Map<String, Object> lineMapFnArgs() {
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", programPath);
        args.put("functionNameOrAddress", "lineMapFn");
        args.put("includeIncomingReferences", false);
        return args;
    }

    @Test
    public void testInitFailureKeepsDecompilationErrorShape() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            withStubCache((p, f, b) -> DecompilationResult.failure(
                DecompilationResult.FailureKind.INIT_FAILED, "Failed to initialize decompiler"), () -> {
                JsonNode json = LineMapFixture.callJson(client, "get-decompilation", lineMapFnArgs());
                assertEquals("Failed to initialize decompiler", json.get("decompilationError").asText());
                assertEquals("", json.get("decompilation").asText());
            });
        });
    }

    @Test
    public void testDecompileFailureIsAnErrorResult() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            withStubCache((p, f, b) -> DecompilationResult.failure("Decompilation failed: boom"), () -> {
                CallToolResult result = client.callTool(new CallToolRequest("get-decompilation", lineMapFnArgs()));
                assertTrue("Expected an MCP error result", result.isError());
                String text = ((TextContent) result.content().get(0)).text();
                assertTrue("Got " + text, text.contains("Decompilation failed: boom"));
            });
        });
    }

    @Test
    public void testDecompileExceptionKeepsDecompilationErrorShape() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            withStubCache((p, f, b) -> {
                throw new IllegalStateException("boom");
            }, () -> {
                JsonNode json = LineMapFixture.callJson(client, "get-decompilation", lineMapFnArgs());
                assertEquals("Exception during decompilation: boom", json.get("decompilationError").asText());
                assertEquals("", json.get("decompilation").asText());
            });
        });
    }

    private JsonNode readTenTarget(McpSyncClient client) {
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", programPath);
        args.put("functionNameOrAddress", "tenTarget");
        return LineMapFixture.callJson(client, "get-decompilation", args);
    }

    @Test
    public void testTenReferencesFromOneCallerCostTwoDecompiles() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            cache().dropProgram(program);
            JsonNode[] json = new JsonNode[1];
            long delta = decompilesDuring(() -> json[0] = readTenTarget(client));
            assertEquals("Ten references in ten entries", 10, json[0].get("incomingReferences").size());
            assertEquals("Target plus the one caller", 2, delta);
        });
    }

    @Test
    public void testCallerFromLineIsTheDisplayedCallLine() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            JsonNode refs = readTenTarget(client).get("incomingReferences");
            assertEquals("Ten call references", 10, refs.size());
            java.util.Set<Integer> lines = new java.util.HashSet<>();
            for (JsonNode ref : refs) {
                lines.add(ref.get("fromLine").asInt());
            }
            assertEquals("Ten separate call lines", 10, lines.size());
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("functionNameOrAddress", "tenCaller");
            args.put("includeIncomingReferences", false);
            args.put("limit", 200);
            String[] shown = LineMapFixture.callJson(client, "get-decompilation", args)
                .get("decompilation").asText().split("\n");
            for (JsonNode ref : refs) {
                int fromLine = ref.get("fromLine").asInt();
                String numbered = shown[fromLine - 1];
                assertTrue("Displayed line " + fromLine + " is numbered: " + numbered,
                    numbered.startsWith(String.format("%4d\t", fromLine)));
                String line = numbered.substring(numbered.indexOf('\t') + 1);
                assertTrue("Line " + fromLine + " should call tenTarget: " + line, line.contains("tenTarget"));
                assertTrue("Context should contain the line: " + ref.get("context").asText(),
                    ref.get("context").asText().contains(line));
            }
        });
    }

    @Test
    public void testFindCrossReferencesContextUsesCache() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            cache().dropProgram(program);
            Map<String, Object> xr = new HashMap<>();
            xr.put("programPath", programPath);
            xr.put("location", "tenTarget");
            xr.put("direction", "to");
            xr.put("includeContext", true);

            JsonNode[] first = new JsonNode[1];
            long firstDelta = decompilesDuring(() -> first[0] = LineMapFixture.callJson(client, "find-cross-references", xr));
            assertEquals("The one caller is decompiled once, through the cache", 1, firstDelta);

            long hitsBefore = cache().stats().hits();
            long secondDelta = decompilesDuring(() -> LineMapFixture.callJson(client, "find-cross-references", xr));
            assertEquals("Second call decompiles nothing", 0, secondDelta);
            assertTrue("Second call is served by cache hits", cache().stats().hits() - hitsBefore >= 1);

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("functionNameOrAddress", "tenCaller");
            args.put("includeIncomingReferences", false);
            args.put("limit", 200);
            String[] shown = LineMapFixture.callJson(client, "get-decompilation", args)
                .get("decompilation").asText().split("\\n");
            JsonNode refs = first[0].get("referencesTo");
            assertEquals(10, refs.size());
            for (JsonNode ref : refs) {
                JsonNode fn = ref.get("fromFunction");
                int line = fn.get("line").asInt();
                String text = shown[line - 1].substring(shown[line - 1].indexOf('\t') + 1);
                assertTrue("Line " + line + " should call tenTarget: " + text, text.contains("tenTarget"));
                String context = fn.get("context").asText();
                assertFalse("Context is non-empty", context.isEmpty());
                assertTrue("Context " + context + " should contain " + text, context.contains(text));
            }
        });
    }

    private long hits() {
        return cache().stats().hits();
    }

    private int nonExternalFunctions() {
        int count = 0;
        for (ghidra.program.model.listing.Function f : program.getFunctionManager().getFunctions(true)) {
            if (!f.isExternal()) {
                count++;
            }
        }
        return count;
    }

    @Test
    public void testSearchDecompilationFillsAndUsesCache() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            cache().dropProgram(program);
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("pattern", "lineMapCallee|tenTarget");
            args.put("maxResults", 500);

            JsonNode[] first = new JsonNode[1];
            long firstDelta = decompilesDuring(() -> first[0] = LineMapFixture.callJson(client, "search-decompilation", args));
            assertEquals("Each function is decompiled once, through the cache", nonExternalFunctions(), firstDelta);
            assertTrue("The search found matches", first[0].get("resultsCount").asInt() > 0);

            long hitsBefore = hits();
            JsonNode[] second = new JsonNode[1];
            long secondDelta = decompilesDuring(() -> second[0] = LineMapFixture.callJson(client, "search-decompilation", args));
            // The hits assertion below is what detects a bypass: a bypass also shows delta 0.
            assertEquals("Second search decompiles nothing", 0, secondDelta);
            assertTrue("Second search is served by cache hits", hits() - hitsBefore >= nonExternalFunctions());
            assertEquals("Identical results", first[0], second[0]);
        });
    }

    private JsonNode readFunction(McpSyncClient client, String name) {
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", programPath);
        args.put("functionNameOrAddress", name);
        args.put("includeIncomingReferences", false);
        args.put("limit", 200);
        return LineMapFixture.callJson(client, "get-decompilation", args);
    }

    private java.util.List<Integer> fromLines(McpSyncClient client) {
        java.util.List<Integer> lines = new java.util.ArrayList<>();
        for (JsonNode ref : readTenTarget(client).get("incomingReferences")) {
            lines.add(ref.get("fromLine").asInt());
        }
        java.util.Collections.sort(lines);
        return lines;
    }

    private java.util.List<Integer> asList(JsonNode array) {
        java.util.List<Integer> lines = new java.util.ArrayList<>();
        for (JsonNode n : array) {
            lines.add(n.asInt());
        }
        return lines;
    }

    @Test
    public void testGetCallersDecompiledUsesCache() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            cache().dropProgram(program);
            readFunction(client, "tenCaller");
            java.util.List<Integer> expected = fromLines(client);

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("functionNameOrAddress", "tenTarget");
            long hitsBefore = hits();
            JsonNode[] json = new JsonNode[1];
            long delta = decompilesDuring(() -> json[0] = LineMapFixture.callJson(client, "get-callers-decompiled", args));
            // The hits assertion below is what detects a bypass: a bypass also shows delta 0.
            assertEquals("The caller was already read", 0, delta);
            assertTrue("Served by a cache hit", hits() - hitsBefore >= 1);
            JsonNode caller = json[0].get("callers").get(0);
            assertEquals("tenCaller", caller.get("functionName").asText());
            assertTrue(caller.get("success").asBoolean());
            assertEquals(expected, asList(caller.get("callLineNumbers")));
            assertEquals(10, expected.size());
        });
    }

    @Test
    public void testGetReferencersDecompiledUsesCache() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            cache().dropProgram(program);
            readFunction(client, "tenCaller");
            java.util.List<Integer> expected = fromLines(client);

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("addressOrSymbol", "tenTarget");
            long hitsBefore = hits();
            JsonNode[] json = new JsonNode[1];
            long delta = decompilesDuring(() -> json[0] = LineMapFixture.callJson(client, "get-referencers-decompiled", args));
            // The hits assertion below is what detects a bypass: a bypass also shows delta 0.
            assertEquals("The referencing function was already read", 0, delta);
            assertTrue("Served by a cache hit", hits() - hitsBefore >= 1);
            JsonNode ref = json[0].get("referencers").get(0);
            assertEquals("tenCaller", ref.get("functionName").asText());
            assertTrue(ref.get("success").asBoolean());
            assertEquals(expected, asList(ref.get("referenceLineNumbers")));
        });
    }

    @Test
    public void testBulkToolsFillTheCache() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            cache().dropProgram(program);
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("functionNameOrAddress", "tenTarget");
            long cold = decompilesDuring(() -> LineMapFixture.callJson(client, "get-callers-decompiled", args));
            assertEquals("One caller decompiled once", 1, cold);
            long hitsBefore = hits();
            long warm = decompilesDuring(() -> readFunction(client, "tenCaller"));
            assertEquals("get-decompilation now hits", 0, warm);
            assertTrue(hits() - hitsBefore >= 1);
        });
    }

    @Test
    public void testRereadAfterRenameVariablesIsAHit() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            cache().dropProgram(program);
            String text = readFunction(client, "lineMapFn").get("decompilation").asText();
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("(DAT_\\w+)").matcher(text);
            assertTrue("A renameable variable should be present in: " + text, m.find());
            String oldName = m.group(1);

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("functionNameOrAddress", "lineMapFn");
            args.put("variableMappings", Map.of(oldName, "renamedByTest"));
            JsonNode renamed = LineMapFixture.callJson(client, "rename-variables", args);
            assertTrue(renamed.get("variablesRenamed").asBoolean());

            long hitsBefore = hits();
            JsonNode[] json = new JsonNode[1];
            long delta = decompilesDuring(() -> json[0] = readFunction(client, "lineMapFn"));
            assertEquals("The diff's after-decompile filled the cache", 0, delta);
            assertTrue("Served by a cache hit", hits() - hitsBefore >= 1);
            assertTrue("Text has the new name: " + json[0].get("decompilation").asText(),
                json[0].get("decompilation").asText().contains("renamedByTest"));
        });
    }

    @Test
    public void testEditSucceedsWhenTheCacheIsUnregistered() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            String text = readFunction(client, "lineMapFn").get("decompilation").asText();
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("(DAT_\\w+)").matcher(text);
            assertTrue("A renameable variable should be present in: " + text, m.find());

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("functionNameOrAddress", "lineMapFn");
            args.put("variableMappings", Map.of(m.group(1), "renamedWithoutCache"));
            DecompilationCache original = cache();
            reva.util.RevaInternalServiceRegistry.unregisterService(DecompilationCache.class);
            try {
                JsonNode renamed = LineMapFixture.callJson(client, "rename-variables", args);
                assertTrue(renamed.get("variablesRenamed").asBoolean());
                assertFalse("The edit must not report an error: " + renamed, renamed.has("decompilationError"));
                assertTrue("The diff is still reported: " + renamed, renamed.has("changes"));
            } finally {
                reva.util.RevaInternalServiceRegistry.registerService(DecompilationCache.class, original);
            }
        });
    }

    /** Same construction as DecompilerToolProvider.COMMENT_TYPE_NAMES, so it iterates in the same order. */
    private static final Map<ghidra.program.model.listing.CommentType, String> COMMENT_TYPE_NAMES = Map.of(
        ghidra.program.model.listing.CommentType.PRE, "pre",
        ghidra.program.model.listing.CommentType.EOL, "eol",
        ghidra.program.model.listing.CommentType.POST, "post",
        ghidra.program.model.listing.CommentType.PLATE, "plate",
        ghidra.program.model.listing.CommentType.REPEATABLE, "repeatable"
    );

    /** The ClangLines of a fresh decompile, as the pre-cache code walked them. */
    private java.util.List<ghidra.app.decompiler.ClangLine> freshLines(ghidra.program.model.listing.Function fn) {
        ghidra.app.decompiler.DecompInterface decompiler = ConfiguredDecompiler.open(program);
        assertNotNull(decompiler);
        try {
            ghidra.app.decompiler.DecompileResults results =
                decompiler.decompileFunction(fn, 60, ghidra.util.task.TaskMonitor.DUMMY);
            assertTrue(results.decompileCompleted());
            return ghidra.app.decompiler.component.DecompilerUtils.toLines(results.getCCodeMarkup());
        } finally {
            decompiler.dispose();
        }
    }

    /** Distinct token addresses of the line that have a code unit, in the pre-cache HashSet's order. */
    private java.util.List<ghidra.program.model.address.Address> commentableAddresses(
            ghidra.app.decompiler.ClangLine line) {
        java.util.Set<ghidra.program.model.address.Address> addresses = new java.util.HashSet<>();
        for (ghidra.app.decompiler.ClangToken token : line.getAllTokens()) {
            if (token.getMinAddress() != null) {
                addresses.add(token.getMinAddress());
            }
        }
        java.util.List<ghidra.program.model.address.Address> result = new java.util.ArrayList<>();
        for (ghidra.program.model.address.Address a : addresses) {
            if (program.getListing().getCodeUnitAt(a) != null) {
                result.add(a);
            }
        }
        return result;
    }

    /**
     * Pins the per-line comment list of includeComments against the pre-cache logic: the line's token addresses
     * go into a HashSet in token order, the set is iterated, and per address the comment types follow
     * COMMENT_TYPE_NAMES iteration order. That map is a Map.of, whose iteration order is fixed within one JVM
     * but randomized between JVMs, so the expected list is built in this JVM from an identically constructed map.
     */
    @Test
    public void testLineCommentsKeepThePreCacheOrder() throws Exception {
        ghidra.program.model.listing.Function fn = program.getFunctionManager()
            .getFunctionAt(program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000500));
        ghidra.app.decompiler.ClangLine target = null;
        int most = 0;
        for (ghidra.app.decompiler.ClangLine line : freshLines(fn)) {
            int n = commentableAddresses(line).size();
            if (n > most) {
                most = n;
                target = line;
            }
        }
        assertNotNull("Some line has a commentable token address", target);
        int lineNumber = target.getLineNumber();

        // EOL, POST and REPEATABLE are not printed by the decompiler, so line numbers do not move.
        java.util.Set<java.util.List<String>> placed = new java.util.HashSet<>();
        int txId = program.startTransaction("Comments on one decompiled line");
        try {
            for (ghidra.program.model.address.Address a : commentableAddresses(target)) {
                ghidra.program.model.listing.CodeUnit cu = program.getListing().getCodeUnitAt(a);
                for (ghidra.program.model.listing.CommentType type : java.util.List.of(
                        ghidra.program.model.listing.CommentType.EOL,
                        ghidra.program.model.listing.CommentType.POST,
                        ghidra.program.model.listing.CommentType.REPEATABLE)) {
                    String comment = type + " at " + a;
                    cu.setComment(type, comment);
                    placed.add(java.util.List.of(reva.util.AddressUtil.formatAddress(a),
                        COMMENT_TYPE_NAMES.get(type), comment));
                }
            }
        } finally {
            program.endTransaction(txId, true);
        }

        ghidra.app.decompiler.ClangLine after = freshLines(fn).stream()
            .filter(l -> l.getLineNumber() == lineNumber).findFirst().orElseThrow();
        java.util.List<java.util.List<String>> expected = new java.util.ArrayList<>();
        for (ghidra.program.model.address.Address a : commentableAddresses(after)) {
            ghidra.program.model.listing.CodeUnit cu = program.getListing().getCodeUnitAt(a);
            for (Map.Entry<ghidra.program.model.listing.CommentType, String> e : COMMENT_TYPE_NAMES.entrySet()) {
                String c = cu.getComment(e.getKey());
                if (c != null && !c.isEmpty()) {
                    expected.add(java.util.List.of(reva.util.AddressUtil.formatAddress(a), e.getValue(), c));
                }
            }
        }
        System.out.println("testLineCommentsKeepThePreCacheOrder: line " + lineNumber + ", "
            + commentableAddresses(after).size() + " address(es), expected " + expected);

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            JsonNode json = read(client, Map.of("includeDisassembly", true, "includeComments", true, "limit", 200));
            java.util.List<java.util.List<String>> actual = new java.util.ArrayList<>();
            for (JsonNode lineInfo : json.get("synchronizedContent")) {
                if (lineInfo.get("lineNumber").asInt() == lineNumber && lineInfo.has("comments")) {
                    for (JsonNode c : lineInfo.get("comments")) {
                        actual.add(java.util.List.of(c.get("address").asText(), c.get("type").asText(),
                            c.get("comment").asText()));
                    }
                }
            }
            assertTrue("At least two comments on the line: " + actual, actual.size() >= 2);
            assertEquals("Exactly the comments placed on the line", placed, new java.util.HashSet<>(actual));
            assertEquals("Pre-cache order", expected, actual);
        });
    }

    @Test
    public void testSetDecompilationCommentAfterReadCostsNoDecompile() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            cache().dropProgram(program);
            readFunction(client, "lineMapFn");

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("functionNameOrAddress", "lineMapFn");
            args.put("lineNumber", 5);
            args.put("commentType", "eol");
            args.put("comment", "cached line comment");
            long hitsBefore = hits();
            JsonNode[] json = new JsonNode[1];
            long delta = decompilesDuring(() -> json[0] = LineMapFixture.callJson(client, "set-decompilation-comment", args));
            // The hits assertion below is what detects a bypass: a bypass also shows delta 0.
            assertEquals("The line is resolved from the cached read", 0, delta);
            assertTrue("Served by a cache hit", hits() - hitsBefore >= 1);
            assertTrue(json[0].get("success").asBoolean());
        });
    }

    private String errorText(McpSyncClient client, String tool, Map<String, Object> args) {
        CallToolResult result = client.callTool(new CallToolRequest(tool, args));
        assertTrue(tool + " should return an error result", result.isError());
        return ((TextContent) result.content().get(0)).text();
    }

    private void checkThrownBulkAndComment(RuntimeException thrown, String bulkText) throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            readFunction(client, "lineMapFn"); // satisfies the read gate of set-decompilation-comment
            Map<String, Object> callers = new HashMap<>();
            callers.put("programPath", programPath);
            callers.put("functionNameOrAddress", "tenTarget");
            Map<String, Object> referencers = new HashMap<>();
            referencers.put("programPath", programPath);
            referencers.put("addressOrSymbol", "tenTarget");
            Map<String, Object> comment = new HashMap<>();
            comment.put("programPath", programPath);
            comment.put("functionNameOrAddress", "lineMapFn");
            comment.put("lineNumber", 5);
            comment.put("commentType", "eol");
            comment.put("comment", "never set");
            withStubCache((p, f, b) -> {
                throw thrown;
            }, () -> {
                assertEquals(bulkText, errorText(client, "get-callers-decompiled", callers));
                assertEquals(bulkText, errorText(client, "get-referencers-decompiled", referencers));
                assertEquals("Failed to set comment: boom", errorText(client, "set-decompilation-comment", comment));
            });
        });
    }

    /** Old code: IllegalArgumentException escaped the handler; registerTool answered with the bare message. */
    @Test
    public void testThrownIllegalArgumentKeepsItsBareText() throws Exception {
        checkThrownBulkAndComment(new IllegalArgumentException("boom"), "boom");
    }

    /** Old code: any other exception escaped the handler; registerTool answered "Tool execution failed: ". */
    @Test
    public void testThrownRuntimeExceptionKeepsToolExecutionFailedText() throws Exception {
        checkThrownBulkAndComment(new RuntimeException("boom"), "Tool execution failed: boom");
    }

    @Test
    public void testDebugInfoReportsCacheCounters() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            cache().dropProgram(program);
            readFunction(client, "lineMapFn");
            readFunction(client, "lineMapFn");
            assertTrue("The cache must have counted something", cache().stats().decompiles() >= 1);

            JsonNode result = LineMapFixture.callJson(client, "capture-reva-debug-info", Map.of());
            java.io.File zip = new java.io.File(result.get("debugZipPath").asText());
            assertTrue("Debug zip should exist: " + zip, zip.isFile());
            // Nothing decompiles between the tool call and this read, so the counters must agree exactly.
            DecompilationCache.Stats stats = cache().stats();
            JsonNode info = readDebugInfo(zip);
            JsonNode counters = info.path("reva").path("decompilationCache");
            assertFalse("reva.decompilationCache missing: " + info.path("reva"), counters.isMissingNode());
            assertEquals(stats.decompiles(), counters.get("decompiles").asLong());
            assertEquals(stats.hits(), counters.get("hits").asLong());
            assertEquals(stats.misses(), counters.get("misses").asLong());
            assertEquals(stats.failures(), counters.get("failures").asLong());
            assertEquals(stats.evictions(), counters.get("evictions").asLong());
            assertEquals(stats.entries(), counters.get("entries").asInt());
            assertEquals(stats.chars(), counters.get("chars").asLong());
            assertTrue(counters.get("hits").asLong() >= 1);
        });
    }

    private static JsonNode readDebugInfo(java.io.File zip) {
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(zip)) {
            java.util.zip.ZipEntry entry = zf.stream().filter(e -> e.getName().endsWith("/debug-info.json"))
                .findFirst().orElseThrow(() -> new AssertionError("debug-info.json missing in " + zip));
            try (java.io.InputStream in = zf.getInputStream(entry)) {
                return new com.fasterxml.jackson.databind.ObjectMapper().readTree(in);
            }
        } catch (java.io.IOException e) {
            throw new AssertionError("Cannot read " + zip, e);
        } finally {
            zip.delete();
        }
    }
}
