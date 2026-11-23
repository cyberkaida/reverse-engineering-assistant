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

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import reva.AnalyzedFixtureSupport;
import reva.RevaIntegrationTestBase;
import reva.plugin.RevaProgramManager;
import reva.util.RevaInternalServiceRegistry;

/**
 * Cache output equals direct decompiler output on a real analysed binary, and the cache stays within its
 * bound while a search decompiles every function.
 */
public class DecompilationCacheEquivalenceIntegrationTest extends RevaIntegrationTestBase {

    private static final String FIXTURE = "test_cpp_x86_64";

    /** Functions allowed to fail on both sides; none fail on this fixture. */
    private static final int ALLOWED_BOTH_FAIL = 0;

    private static void assertSameSnapshot(String label, DecompilationSnapshot expected, DecompilationSnapshot actual) {
        assertEquals(label + ": code", expected.code(), actual.code());
        assertEquals(label + ": signature", expected.signature(), actual.signature());
        assertEquals(label + ": lines", expected.lines(), actual.lines());
    }

    @Test
    public void testCachedOutputEqualsUncachedOutput() throws Exception {
        String path = AnalyzedFixtureSupport.importAndAnalyze(this, FIXTURE);
        Program analysed = RevaProgramManager.getProgramByPath(path);
        assertNotNull("Analysed program should be resolvable", analysed);

        DecompilationCache cache = LineMapFixture.cache();
        cache.dropProgram(analysed);
        Map<Function, DecompilationSnapshot> direct = new java.util.LinkedHashMap<>();
        int nonExternal = 0;
        int bothFailed = 0;
        DecompInterface decompiler = ConfiguredDecompiler.open(analysed);
        assertNotNull("Direct decompiler should open", decompiler);
        try {
            for (Function function : analysed.getFunctionManager().getFunctions(true)) {
                if (function.isExternal()) {
                    continue;
                }
                nonExternal++;
                // First pass: every get is a miss, so this compares the backend with a second, direct run.
                DecompilationResult cached = cache.get(analysed, function);
                DecompilationResult uncached = ConfiguredDecompiler.decompile(decompiler, analysed, function);
                if (!cached.success() && !uncached.success()) {
                    bothFailed++;
                    continue;
                }
                assertEquals(function.getName() + ": both sides must succeed or fail together",
                    uncached.success(), cached.success());
                assertSameSnapshot(function.getName() + " (first pass)", uncached.snapshot(), cached.snapshot());
                direct.put(function, uncached.snapshot());
            }
        } finally {
            decompiler.dispose();
        }
        int compared = direct.size();
        assertTrue("Compared " + compared + " of " + nonExternal + " (" + bothFailed + " failed on both sides)",
            bothFailed <= ALLOWED_BOTH_FAIL && compared >= nonExternal - ALLOWED_BOTH_FAIL);

        // Second pass: everything must now be served from the store, and equal the uncached output.
        DecompilationCache.Stats before = cache.stats();
        for (Map.Entry<Function, DecompilationSnapshot> e : direct.entrySet()) {
            DecompilationResult hit = cache.get(analysed, e.getKey());
            assertTrue(e.getKey().getName() + ": hit must succeed", hit.success());
            assertSameSnapshot(e.getKey().getName() + " (cache hit)", e.getValue(), hit.snapshot());
        }
        DecompilationCache.Stats after = cache.stats();
        assertEquals("Second pass decompiles nothing", before.decompiles(), after.decompiles());
        assertEquals("Second pass is all hits", before.hits() + compared, after.hits());
        assertEquals("Nothing was evicted", before.evictions(), after.evictions());

        // The tool's text for a few functions corresponds to the uncached code, and is served from the store.
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            int checked = 0;
            for (Map.Entry<Function, DecompilationSnapshot> e : direct.entrySet()) {
                if (checked == 5) {
                    break;
                }
                String[] lines = e.getValue().code().split("\n");
                StringBuilder expected = new StringBuilder();
                for (int i = 0; i < lines.length; i++) {
                    expected.append(String.format("%4d\t%s\n", i + 1, lines[i]));
                }
                Map<String, Object> args = new HashMap<>();
                args.put("programPath", path);
                args.put("functionNameOrAddress", "0x" + e.getKey().getEntryPoint());
                args.put("includeIncomingReferences", false);
                args.put("limit", lines.length + 10);
                long hitsBefore = LineMapFixture.cache().stats().hits();
                JsonNode[] json = new JsonNode[1];
                long delta = LineMapFixture.decompilesDuring(
                    () -> json[0] = LineMapFixture.callJson(client, "get-decompilation", args));
                String label = e.getKey().getName();
                assertEquals(label + ": tool text equals numbered uncached code", expected.toString(),
                    json[0].get("decompilation").asText());
                assertEquals(label + ": tool read costs no decompile", 0, delta);
                assertTrue(label + ": tool read is a cache hit", LineMapFixture.cache().stats().hits() > hitsBefore);
                checked++;
            }
            assertEquals("Five functions checked through the tool", 5, checked);
        });
    }

    private JsonNode searchNothing(io.modelcontextprotocol.client.McpSyncClient client, String path) {
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", path);
        args.put("pattern", "zzz_pattern_that_matches_nothing_zzz");
        args.put("maxResults", 500);
        return LineMapFixture.callJson(client, "search-decompilation", args);
    }

    @Test
    public void testBoundHoldsUnderSearchDecompilation() throws Exception {
        String path = AnalyzedFixtureSupport.importAndAnalyze(this, FIXTURE);
        Program analysed = RevaProgramManager.getProgramByPath(path);
        assertNotNull(analysed);
        int limit = RevaInternalServiceRegistry.getService(reva.plugin.ConfigManager.class)
            .getMaxDecompilerSearchFunctions();
        int functions = analysed.getFunctionManager().getFunctionCount();
        assertTrue("Search limit " + limit + " must cover the fixture's " + functions + " functions",
            functions <= limit);

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Learn how much text the fixture produces with a bound it cannot reach.
            long[] total = new long[1];
            LineMapFixture.withRegisteredCache(new DecompilationCache(), () -> {
                assertEquals(0, searchNothing(client, path).get("resultsCount").asInt());
                total[0] = LineMapFixture.cache().stats().chars();
            });
            assertTrue("Fixture must produce some text", total[0] > 0);

            long maxChars = Math.max(1, total[0] / 3);
            LineMapFixture.withRegisteredCache(new DecompilationCache(maxChars), () -> {
                assertEquals(0, searchNothing(client, path).get("resultsCount").asInt());
                DecompilationCache.Stats stats = LineMapFixture.cache().stats();
                assertTrue("chars " + stats.chars() + " must not exceed " + maxChars, stats.chars() <= maxChars);
                assertTrue("The search must have overflowed the bound", stats.evictions() > 0);
            });
        });
    }
}
