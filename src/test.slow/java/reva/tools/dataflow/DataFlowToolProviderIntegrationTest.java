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
package reva.tools.dataflow;

import static org.junit.Assert.*;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.AnalyzedFixtureSupport;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for the dataflow tool package against a REAL analyzed Mach-O
 * fixture ({@code test_dataflow_x86_64}, built from test_dataflow.c:
 * {@code int transform(int seed){int a=seed+7;int b=a*3;int c=b-a;return c;}} plus a
 * {@code main} that prints {@code transform(11)}).
 *
 * <p>Behavior is pinned to the tool's observed output on this fixture. Notes on the
 * dataflow tool I/O (verified against {@link reva.tools.dataflow.DataFlowToolProvider}):
 * <ul>
 *   <li>The Mach-O symbol carries a leading underscore: {@code transform} appears as
 *       {@code _transform}. We resolve the entry by scanning {@code get-symbols} for a
 *       function named {@code transform} or {@code _transform}, then assert the trace
 *       tools echo {@code function=="_transform"} and the same {@code functionAddress}.</li>
 *   <li>Operations carry an {@code opcode} field (the pcode mnemonic). Varnodes carry an
 *       optional {@code variableName}. Constant varnodes carry {@code value} formatted as
 *       {@code "0x" + Long.toHexString(offset)} (e.g. {@code "0x7"}).</li>
 *   <li>Backward terminators of type {@code CONSTANT} carry {@code value} in the same
 *       {@code "0x..."} hex form. Forward terminators of type {@code RETURN} carry an
 *       {@code address}.</li>
 *   <li>Seeding a trace at the function entry yields "No data flow information at address".
 *       We seed at OPERATION addresses instead, discovered robustly from a forward trace
 *       and from a {@code param_1} variable access.</li>
 *   <li>At -O0 the source locals a/b/c are folded into temporaries/registers and do NOT
 *       resolve by source name; we assert on the {@code param_1} parameter instead.</li>
 * </ul>
 */
public class DataFlowToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private static final String FIXTURE = "test_dataflow_x86_64";

    /**
     * Resolve the entry address of {@code transform} by scanning get-symbols for a
     * function named "transform" or "_transform" (Mach-O underscore). Returns the
     * 0x-prefixed entry address string. Fails the test if not found.
     */
    private String transformEntry(String path) throws Exception {
        return withMcpClient(createMcpTransport(), (McpClientFunction<String>) client -> {
            client.initialize();
            CallToolResult r = client.callTool(new CallToolRequest("get-symbols",
                Map.of("programPath", path, "maxCount", 500, "filterDefaultNames", true)));
            assertMcpResultNotError(r, "get-symbols");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());
            for (JsonNode sym : json.get("symbols")) {
                if (!sym.path("isFunction").asBoolean(false)) {
                    continue;
                }
                String name = sym.path("name").asText();
                if ("transform".equals(name) || "_transform".equals(name)) {
                    return sym.get("address").asText();
                }
            }
            fail("Could not find function transform/_transform in get-symbols output");
            return null; // unreachable
        });
    }

    /**
     * Find the address of the first operation in a forward trace from the given seed
     * whose opcode matches the requested opcode. Returns the 0x-prefixed address.
     */
    private static String findOpAddress(JsonNode traceJson, String opcode) {
        for (JsonNode op : traceJson.get("operations")) {
            if (opcode.equals(op.path("opcode").asText()) && op.has("address")) {
                return op.get("address").asText();
            }
        }
        return null;
    }

    @Test
    public void testTraceDataFlowForward() throws Exception {
        String path = AnalyzedFixtureSupport.importAndAnalyze(this, FIXTURE);
        String entry = transformEntry(path);

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Robustly seed at the INT_ADD operation address: find param_1's READ access
            // (the seed+7 add) and trace forward from there.
            CallToolResult accessResult = client.callTool(new CallToolRequest("find-variable-accesses",
                Map.of("programPath", path, "functionAddress", entry, "variableName", "param_1")));
            assertMcpResultNotError(accessResult, "find-variable-accesses for seed");
            JsonNode accessJson = parseJsonContent(((TextContent) accessResult.content().get(0)).text());
            String seed = null;
            for (JsonNode a : accessJson.get("accesses")) {
                if ("INT_ADD".equals(a.path("operation").asText())) {
                    seed = a.get("address").asText();
                    break;
                }
            }
            assertNotNull("param_1 has an INT_ADD access to seed the forward trace from", seed);

            CallToolResult r = client.callTool(new CallToolRequest("trace-data-flow-forward",
                Map.of("programPath", path, "address", seed)));
            assertMcpResultNotError(r, "trace-data-flow-forward");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            assertEquals("programPath echoed back", path, json.get("programPath").asText());
            assertEquals("direction is forward", "forward", json.get("direction").asText());
            assertEquals("function resolves to _transform (Mach-O underscore)",
                "_transform", json.get("function").asText());
            assertEquals("functionAddress matches resolved entry",
                entry, json.get("functionAddress").asText());
            assertEquals("startAddress echoes the seed", seed, json.get("startAddress").asText());

            // operationCount mirrors operations array size and is the spike-observed 4.
            assertEquals("operationCount mirrors operations size",
                json.get("operations").size(), json.get("operationCount").asInt());
            assertEquals("forward trace from INT_ADD has 4 operations", 4, json.get("operationCount").asInt());

            // Opcodes are exactly {INT_ADD, INT_MULT, COPY, RETURN} - an exact-set
            // assertion catches a regression that adds an extra opcode.
            Set<String> opcodes = new HashSet<>();
            for (JsonNode op : json.get("operations")) {
                opcodes.add(op.path("opcode").asText());
            }
            assertEquals("forward slice opcodes are exactly {INT_ADD, INT_MULT, COPY, RETURN}",
                Set.of("INT_ADD", "INT_MULT", "COPY", "RETURN"), opcodes);

            // The INT_ADD operation's inputs include a varnode named param_1.
            boolean intAddHasParam1 = false;
            for (JsonNode op : json.get("operations")) {
                if (!"INT_ADD".equals(op.path("opcode").asText())) {
                    continue;
                }
                if (!op.has("inputs")) {
                    continue;
                }
                for (JsonNode in : op.get("inputs")) {
                    if ("param_1".equals(in.path("variableName").asText())) {
                        intAddHasParam1 = true;
                    }
                }
            }
            assertTrue("INT_ADD inputs include the param_1 varnode", intAddHasParam1);

            // terminators contains a RETURN entry.
            boolean hasReturnTerminator = false;
            for (JsonNode t : json.get("terminators")) {
                if ("RETURN".equals(t.path("type").asText())) {
                    hasReturnTerminator = true;
                }
            }
            assertTrue("forward terminators include a RETURN", hasReturnTerminator);
        });
    }

    @Test
    public void testTraceDataFlowBackward() throws Exception {
        String path = AnalyzedFixtureSupport.importAndAnalyze(this, FIXTURE);
        String entry = transformEntry(path);

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Robustly seed at the COPY operation address: run a forward trace from the
            // param_1 INT_ADD access, then pick the COPY op address as the backward seed.
            CallToolResult accessResult = client.callTool(new CallToolRequest("find-variable-accesses",
                Map.of("programPath", path, "functionAddress", entry, "variableName", "param_1")));
            assertMcpResultNotError(accessResult, "find-variable-accesses for seed");
            JsonNode accessJson = parseJsonContent(((TextContent) accessResult.content().get(0)).text());
            // Guard the seed: a single access means the INT_ADD address is unambiguous.
            // A future multi-access change must fail here loudly, not silently mis-seed.
            assertEquals("param_1 has exactly one access (INT_ADD) on this fixture",
                1, accessJson.get("accessCount").asInt());
            String addAddr = null;
            for (JsonNode a : accessJson.get("accesses")) {
                if ("INT_ADD".equals(a.path("operation").asText())) {
                    addAddr = a.get("address").asText();
                    break;
                }
            }
            assertNotNull("param_1 INT_ADD access address", addAddr);

            CallToolResult fwd = client.callTool(new CallToolRequest("trace-data-flow-forward",
                Map.of("programPath", path, "address", addAddr)));
            assertMcpResultNotError(fwd, "trace-data-flow-forward (to find COPY seed)");
            JsonNode fwdJson = parseJsonContent(((TextContent) fwd.content().get(0)).text());
            String seed = findOpAddress(fwdJson, "COPY");
            Set<String> seenOpcodes = new HashSet<>();
            for (JsonNode op : fwdJson.get("operations")) {
                seenOpcodes.add(op.path("opcode").asText());
            }
            assertNotNull("forward trace exposes a COPY operation address to seed backward from "
                + "(seen opcodes: " + seenOpcodes + ")", seed);

            CallToolResult r = client.callTool(new CallToolRequest("trace-data-flow-backward",
                Map.of("programPath", path, "address", seed)));
            assertMcpResultNotError(r, "trace-data-flow-backward");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            assertEquals("programPath echoed back", path, json.get("programPath").asText());
            assertEquals("direction is backward", "backward", json.get("direction").asText());
            assertEquals("function resolves to _transform", "_transform", json.get("function").asText());
            assertEquals("functionAddress matches resolved entry",
                entry, json.get("functionAddress").asText());
            assertEquals("operationCount mirrors operations size",
                json.get("operations").size(), json.get("operationCount").asInt());

            // Backward terminators include two CONSTANT entries with values 0x7 and 0x2.
            // (transform: a = seed + 7; b = a * 3 -> the multiply lowers to <<1 + add, i.e.
            // constants 0x7 and 0x2 appear in the backward slice's constant terminators.)
            java.util.Set<String> constValues = new java.util.HashSet<>();
            for (JsonNode t : json.get("terminators")) {
                if ("CONSTANT".equals(t.path("type").asText())) {
                    constValues.add(t.get("value").asText());
                }
            }
            assertTrue("backward CONSTANT terminators include 0x7 (the +7)",
                constValues.contains("0x7"));
            assertTrue("backward CONSTANT terminators include 0x2 (the *3 lowered shift)",
                constValues.contains("0x2"));
        });
    }

    @Test
    public void testFindVariableAccesses() throws Exception {
        String path = AnalyzedFixtureSupport.importAndAnalyze(this, FIXTURE);
        String entry = transformEntry(path);

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult r = client.callTool(new CallToolRequest("find-variable-accesses",
                Map.of("programPath", path, "functionAddress", entry, "variableName", "param_1")));
            assertMcpResultNotError(r, "find-variable-accesses");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            assertEquals("programPath echoed back", path, json.get("programPath").asText());
            assertEquals("function resolves to _transform", "_transform", json.get("function").asText());
            assertEquals("functionAddress matches resolved entry",
                entry, json.get("functionAddress").asText());
            assertEquals("variableName echoed back", "param_1", json.get("variableName").asText());
            assertEquals("param_1 is classified as a parameter",
                "parameter", json.get("variableType").asText());
            assertEquals("dataType is int (DataType.getDisplayName())",
                "int", json.get("dataType").asText());

            // accessCount mirrors accesses array size; spike observed exactly 1.
            assertEquals("accessCount mirrors accesses size",
                json.get("accesses").size(), json.get("accessCount").asInt());
            assertEquals("param_1 has exactly one access on this fixture",
                1, json.get("accessCount").asInt());

            // The single access is a READ via INT_ADD (the seed+7).
            JsonNode access = json.get("accesses").get(0);
            assertTrue("access has a 0x-prefixed address",
                access.get("address").asText().startsWith("0x"));
            assertEquals("param_1 access type is READ", "READ", access.get("accessType").asText());
            assertEquals("param_1 access operation is INT_ADD", "INT_ADD", access.get("operation").asText());
        });
    }

    @Test
    public void testTraceMissingProgramIsError() throws Exception {
        // No fixture needed: missing-program resolution errors before any program is touched.
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult r = client.callTool(new CallToolRequest("trace-data-flow-forward",
                Map.of("programPath", "/does-not-exist", "address", "0x100000470")));
            assertTrue("trace-data-flow-forward on a missing program should error", r.isError());
        });
    }
}
