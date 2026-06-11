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
package reva.tools.constants;

import static org.junit.Assert.*;
import java.util.Map;
import org.junit.Test;
import com.fasterxml.jackson.databind.JsonNode;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.AnalyzedFixtureSupport;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for the constants (ConstantSearch) tool package against a REAL
 * analyzed Mach-O fixture (test_x86_64, built from test_program.c: add(2,3),
 * multiply(4,5), and a printf with a format string).
 *
 * <p>Behavior is pinned to the tool's observed output on this fixture. Note the
 * tool's I/O quirks, verified against {@link reva.tools.constants.ConstantSearchToolProvider}:
 * <ul>
 *   <li>{@code value}/{@code minValue}/{@code maxValue} are STRING inputs (decimal,
 *       0x-hex, or negative), not integers. We pass strings.</li>
 *   <li>Output {@code value}/{@code searchedValue} are formatted by {@code formatValue()}
 *       as {@code "0x%x (%d)"} for non-zero values and the bare {@code "0"} for zero.</li>
 *   <li>{@code uniqueValues[]}/{@code constants[]} carry a raw {@code decimal} long field.</li>
 *   <li>At -O0 small immediates may or may not survive as instruction operands. Rather than
 *       assume 2/3/4/5 are present, we DISCOVER a real constant via list-common-constants and
 *       feed it back into the search tools so the present-value assertions are stable.</li>
 * </ul>
 */
public class ConstantSearchToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String importFixture() throws Exception {
        return withMcpClient(createMcpTransport(),
            (McpClientFunction<String>) client -> {
                client.initialize();
                return AnalyzedFixtureSupport.importAndAnalyze(client, "test_x86_64");
            });
    }

    /**
     * Pick a stable, non-noise constant the fixture actually contains by reading
     * list-common-constants. Returns the raw decimal value of the most frequent
     * constant, or null if the fixture has none (which would itself be notable).
     */
    private static Long discoverPresentConstant(JsonNode listJson) {
        JsonNode constants = listJson.get("constants");
        if (constants == null || !constants.isArray() || constants.size() == 0) {
            return null;
        }
        return constants.get(0).get("decimal").asLong();
    }

    @Test
    public void testListCommonConstants() throws Exception {
        String path = importFixture();
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult r = client.callTool(new CallToolRequest("list-common-constants",
                Map.of("programPath", path, "topN", 20, "includeSmallValues", true)));
            assertMcpResultNotError(r, "list-common-constants");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            assertEquals("programPath echoed back", path, json.get("programPath").asText());
            assertTrue("fixture has at least one constant",
                json.get("totalUniqueConstants").asInt() > 0);
            assertTrue("constants is an array", json.get("constants").isArray());

            // returned is the size of the returned slice and is bounded by topN.
            int returned = json.get("returned").asInt();
            assertEquals("returned matches constants array size",
                json.get("constants").size(), returned);
            assertTrue("returned never exceeds topN", returned <= 20);

            for (JsonNode c : json.get("constants")) {
                assertTrue("constant has value", c.has("value"));
                assertTrue("constant has decimal", c.has("decimal"));
                assertTrue("constant has occurrences", c.has("occurrences"));
                assertTrue("constant has uniqueFunctions", c.has("uniqueFunctions"));
                assertTrue("constant has sampleLocations", c.has("sampleLocations"));
                assertTrue("occurrences is positive", c.get("occurrences").asInt() > 0);
                assertTrue("sampleLocations is an array", c.get("sampleLocations").isArray());
            }
        });
    }

    @Test
    public void testListCommonConstantsDefaultFiltersNoise() throws Exception {
        String path = importFixture();
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            // includeSmallValues omitted -> default false -> noise (0-255, -1) excluded.
            CallToolResult r = client.callTool(new CallToolRequest("list-common-constants",
                Map.of("programPath", path, "topN", 20)));
            assertMcpResultNotError(r, "list-common-constants default filter");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            assertEquals("default filter description is pinned",
                "excluded noise values (0-255, -1)", json.get("filterApplied").asText());
            // Every returned constant must be outside the noise band (unsigned > 255, not -1).
            for (JsonNode c : json.get("constants")) {
                long dec = c.get("decimal").asLong();
                assertTrue("noise-filtered constant is not a small value 0-255: " + dec,
                    Long.compareUnsigned(dec, 255) > 0);
                assertNotEquals("noise-filtered constant is not -1 (0xffffffffffffffff)",
                    -1L, dec);
            }
        });
    }

    @Test
    public void testFindConstantUsesPresentValue() throws Exception {
        String path = importFixture();
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Discover a constant that is actually present, then search for it.
            CallToolResult listResult = client.callTool(new CallToolRequest("list-common-constants",
                Map.of("programPath", path, "topN", 20, "includeSmallValues", true)));
            assertMcpResultNotError(listResult, "list-common-constants");
            JsonNode listJson = parseJsonContent(((TextContent) listResult.content().get(0)).text());
            Long present = discoverPresentConstant(listJson);
            assertNotNull("fixture must contain at least one immediate constant", present);

            CallToolResult r = client.callTool(new CallToolRequest("find-constant-uses",
                Map.of("programPath", path, "value", Long.toString(present), "maxResults", 100)));
            assertMcpResultNotError(r, "find-constant-uses present");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            // Structural invariant: resultCount always equals results.size().
            assertEquals("resultCount equals results size",
                json.get("results").size(), json.get("resultCount").asInt());

            // searchedValue echoes formatValue(present): "0x%x (%d)" for non-zero, "0" for zero.
            String expectedSearched = present == 0
                ? "0"
                : String.format("0x%x (%d)", present, present);
            assertEquals("searchedValue is formatValue of the requested value",
                expectedSearched, json.get("searchedValue").asText());

            // The value came FROM list-common-constants, so it must be found at least once.
            assertTrue("a present constant yields at least one use",
                json.get("resultCount").asInt() > 0);

            JsonNode first = json.get("results").get(0);
            assertTrue("result has address", first.has("address"));
            assertTrue("address is 0x-prefixed", first.get("address").asText().startsWith("0x"));
            assertTrue("result has mnemonic", first.has("mnemonic"));
            assertTrue("result has operandIndex", first.has("operandIndex"));
            assertTrue("result has instruction", first.has("instruction"));
            assertEquals("result value echoes formatValue of the matched constant",
                expectedSearched, first.get("value").asText());
        });
    }

    @Test
    public void testFindConstantUsesAbsentValue() throws Exception {
        String path = importFixture();
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            // 0xdeadbeefcafef00d is extremely unlikely to appear as an immediate in this
            // tiny fixture. Pin the absent-value behavior: resultCount==0, empty results.
            CallToolResult r = client.callTool(new CallToolRequest("find-constant-uses",
                Map.of("programPath", path, "value", "0xdeadbeefcafef00d", "maxResults", 100)));
            assertMcpResultNotError(r, "find-constant-uses absent");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            assertEquals("absent value yields zero results", 0, json.get("resultCount").asInt());
            assertEquals("results array is empty for an absent value",
                0, json.get("results").size());
            assertFalse("not truncated when nothing matched", json.get("truncated").asBoolean());
        });
    }

    @Test
    public void testFindConstantsInRange() throws Exception {
        String path = importFixture();
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Discover a present constant and build a range that brackets it so the
            // range query reliably finds something on this fixture.
            CallToolResult listResult = client.callTool(new CallToolRequest("list-common-constants",
                Map.of("programPath", path, "topN", 20, "includeSmallValues", true)));
            assertMcpResultNotError(listResult, "list-common-constants");
            JsonNode listJson = parseJsonContent(((TextContent) listResult.content().get(0)).text());
            Long present = discoverPresentConstant(listJson);
            assertNotNull("fixture must contain at least one immediate constant", present);

            // small window bracketing the discovered constant while staying in unsigned space
            long min = present > 16 ? present - 16 : 0;
            long max = present + 16;

            CallToolResult r = client.callTool(new CallToolRequest("find-constants-in-range",
                Map.of("programPath", path,
                    "minValue", Long.toString(min),
                    "maxValue", Long.toString(max),
                    "maxResults", 200)));
            assertMcpResultNotError(r, "find-constants-in-range");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            assertEquals("programPath echoed back", path, json.get("programPath").asText());
            assertTrue("range query around a present value finds occurrences",
                json.get("totalOccurrences").asInt() > 0);
            assertTrue("response carries uniqueValues", json.has("uniqueValues"));
            assertTrue("uniqueValues is an array", json.get("uniqueValues").isArray());

            // uniqueValuesFound matches uniqueValues array size.
            assertEquals("uniqueValuesFound matches uniqueValues size",
                json.get("uniqueValues").size(), json.get("uniqueValuesFound").asInt());
            // totalOccurrences matches results array size (each result is one occurrence).
            assertEquals("totalOccurrences matches results size",
                json.get("results").size(), json.get("totalOccurrences").asInt());

            // range echo is formatted via formatValue.
            JsonNode range = json.get("range");
            assertEquals("range.min is formatValue of min",
                min == 0 ? "0" : String.format("0x%x (%d)", min, min),
                range.get("min").asText());
            assertEquals("range.max is formatValue of max",
                String.format("0x%x (%d)", max, max),
                range.get("max").asText());

            // Every unique value carries value/decimal/occurrences and lies within the range.
            for (JsonNode uv : json.get("uniqueValues")) {
                assertTrue("uniqueValue has value", uv.has("value"));
                assertTrue("uniqueValue has decimal", uv.has("decimal"));
                assertTrue("uniqueValue has occurrences", uv.has("occurrences"));
                long dec = uv.get("decimal").asLong();
                assertTrue("uniqueValue decimal within [min,max]: " + dec,
                    Long.compareUnsigned(dec, min) >= 0 && Long.compareUnsigned(dec, max) <= 0);
            }
        });
    }

    @Test
    public void testFindConstantsInRangeMinGreaterThanMaxIsError() throws Exception {
        String path = importFixture();
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult r = client.callTool(new CallToolRequest("find-constants-in-range",
                Map.of("programPath", path, "minValue", "100", "maxValue", "10")));
            assertTrue("min > max should be an error", r.isError());
        });
    }

    @Test
    public void testFindConstantUsesMissingProgramIsError() throws Exception {
        // No fixture needed: missing-program resolution errors before any program is touched.
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult r = client.callTool(new CallToolRequest("find-constant-uses",
                Map.of("programPath", "/does-not-exist", "value", "1")));
            assertTrue("find-constant-uses on a missing program should error", r.isError());
        });
    }
}
