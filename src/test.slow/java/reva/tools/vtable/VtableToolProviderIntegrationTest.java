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
package reva.tools.vtable;

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
 * Integration tests for the vtable tool package against a REAL analyzed C++
 * Mach-O fixture (test_cpp_x86_64, built from test_cpp_program.cpp: an abstract
 * base {@code Animal} with concrete {@code Dog}/{@code Cat} overriding
 * {@code legs()}/{@code speak()}, plus an indirect virtual dispatch through a
 * base pointer in {@code dispatch(const Animal*)}).
 *
 * <p><b>RTTI reliably produces vtables for this fixture.</b> Ghidra's RTTI
 * analyzer emits Itanium-ABI vtable symbols ({@code __ZTV3Dog} = "vtable for
 * Dog", etc.). All assertions below are HARD — no {@code Assume} is used. The
 * vtable discovery is fully deterministic across runs in this environment.
 *
 * <p><b>Vtable-address subtlety (pinned from observed behavior):</b> the
 * {@code __ZTV3Dog} symbol points at the <i>start</i> of the Itanium vtable
 * object (offset-to-top word at +0x0, RTTI pointer at +0x8); the
 * function-pointer array begins at symbol+0x10 (e.g. {@code 0x100001028} for
 * Dog). {@code analyze-vtable} on the {@code __ZTV*} symbol therefore sees only
 * the offset-to-top word and reports a single non-function entry, whereas the
 * function-pointer-array address yields the real method slots. Rather than
 * hardcode this ABI offset, these tests discover the canonical vtable address
 * the way the tooling itself does: by calling
 * {@code find-vtables-containing-function} on a known virtual method
 * (Dog::legs) and reading back the {@code vtableAddress} it reports
 * ({@code 0x100001028}), which is exactly the address {@code analyze-vtable}
 * wants.
 */
public class VtableToolProviderIntegrationTest extends RevaIntegrationTestBase {

    /** Itanium-ABI mangled name for {@code Dog::legs() const}. */
    private static final String DOG_LEGS_MANGLED = "__ZNK3Dog4legsEv";

    /**
     * Resolve the entry-point address of a function by its (possibly mangled)
     * symbol name via get-symbols. Returns the first FUNCTION-typed symbol's
     * address, or the first matching label address as a fallback.
     */
    private String addressOfSymbol(io.modelcontextprotocol.client.McpSyncClient client,
            String programPath, String symbolName) {
        // test_cpp_x86_64 is a toy binary with well under 2000 symbols; a single page suffices.
        CallToolResult syms = client.callTool(new CallToolRequest("get-symbols",
            Map.of("programPath", programPath, "maxCount", 2000,
                   "filterDefaultNames", false, "includeExternal", false)));
        assertMcpResultNotError(syms, "get-symbols");
        JsonNode json = parseJsonContent(((TextContent) syms.content().get(0)).text());
        String fallback = null;
        for (JsonNode s : json.get("symbols")) {
            if (symbolName.equals(s.path("name").asText())) {
                if (s.path("isFunction").asBoolean()) {
                    return s.path("address").asText();
                }
                if (fallback == null) {
                    fallback = s.path("address").asText();
                }
            }
        }
        return fallback;
    }

    /**
     * Discover the canonical (function-pointer-array) vtable address for the
     * Dog vtable by asking find-vtables-containing-function about Dog::legs.
     * This is the address analyze-vtable expects (symbol+0x10 in the Itanium
     * ABI). Returns the vtableAddress string, asserting discovery succeeded.
     */
    private String discoverDogVtableAddress(io.modelcontextprotocol.client.McpSyncClient client,
            String programPath, String legsAddr) {
        CallToolResult r = client.callTool(new CallToolRequest("find-vtables-containing-function",
            Map.of("programPath", programPath, "functionAddress", legsAddr)));
        assertMcpResultNotError(r, "find-vtables-containing-function");
        JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());
        assertTrue("RTTI must place Dog::legs in at least one vtable",
            json.get("vtableCount").asInt() > 0);
        return json.get("vtables").get(0).get("vtableAddress").asText();
    }

    /**
     * analyze-vtable on the Dog function-pointer array reports the four virtual
     * slots (~Dog, ~Dog, legs, speak) plus a trailing non-function entry. Pins
     * exact slot indices, offsets, function names, and the structure-less shape.
     */
    @Test
    public void testAnalyzeVtable() throws Exception {
        String path = AnalyzedFixtureSupport.importAndAnalyze(this, "test_cpp_x86_64");
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            String legsAddr = addressOfSymbol(client, path, DOG_LEGS_MANGLED);
            assertNotNull("fixture must expose Dog::legs (" + DOG_LEGS_MANGLED + ")", legsAddr);
            String vtableAddr = discoverDogVtableAddress(client, path, legsAddr);

            CallToolResult r = client.callTool(new CallToolRequest("analyze-vtable",
                Map.of("programPath", path, "vtableAddress", vtableAddr)));
            assertMcpResultNotError(r, "analyze-vtable");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            assertEquals("programPath echoed back", path, json.get("programPath").asText());
            assertEquals("vtableAddress echoed back", vtableAddr, json.get("vtableAddress").asText());
            assertEquals("x86_64 pointer size", 8, json.get("pointerSize").asInt());
            // No Structure datatype is applied at the vtable by default analysis.
            assertFalse("no structure defined at the raw vtable address",
                json.get("hasStructure").asBoolean());
            assertTrue("structure-less analysis carries an explanatory note", json.has("note"));

            JsonNode entries = json.get("entries");
            assertNotNull("entries array present", entries);
            // 4 function-pointer slots (~Dog, ~Dog, legs, speak) + 1 trailing
            // non-function (RTTI/end-of-vtable) entry that the reader records
            // before stopping.
            assertEquals("Dog vtable reports 5 entries (4 funcs + 1 terminator)",
                5, json.get("entryCount").asInt());
            assertEquals("entryCount matches entries array size",
                json.get("entryCount").asInt(), entries.size());

            // Slot offsets are sequential pointer-sized steps; the four method
            // slots resolve to functions, the terminator does not.
            for (int i = 0; i < entries.size(); i++) {
                JsonNode e = entries.get(i);
                assertEquals("slot index is sequential", i, e.get("slot").asInt());
                assertEquals("offset is slot * pointerSize",
                    String.format("0x%x", i * 8), e.get("offset").asText());
                assertTrue("every entry carries a resolved target address", e.has("address"));
            }

            // The two destructor slots (Itanium emits ~Dog twice: complete +
            // deleting), then legs, then speak.
            assertEquals("slot 0 is the complete destructor", "~Dog",
                entries.get(0).get("functionName").asText());
            assertEquals("slot 1 is the deleting destructor", "~Dog",
                entries.get(1).get("functionName").asText());
            assertEquals("slot 2 is legs()", "legs",
                entries.get(2).get("functionName").asText());
            assertEquals("slot 3 is speak()", "speak",
                entries.get(3).get("functionName").asText());
            // Each resolved method slot carries a signature.
            assertTrue("resolved slot carries a signature", entries.get(2).has("signature"));

            // The trailing entry is a non-function terminator.
            JsonNode terminator = entries.get(4);
            assertTrue("terminator functionName is null",
                terminator.get("functionName").isNull());
            assertTrue("terminator carries an end-of-vtable note", terminator.has("note"));

            // Cross-check the resolved legs slot target equals the discovered
            // legs function entry address.
            assertEquals("slot 2 target is the Dog::legs entry point",
                legsAddr, entries.get(2).get("address").asText());
        });
    }

    /**
     * find-vtables-containing-function on Dog::legs reports exactly the Dog
     * vtable with the correct slot index/offset. Pins the real output shape.
     */
    @Test
    public void testFindVtablesContainingFunction() throws Exception {
        String path = AnalyzedFixtureSupport.importAndAnalyze(this, "test_cpp_x86_64");
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            String legsAddr = addressOfSymbol(client, path, DOG_LEGS_MANGLED);
            assertNotNull("fixture must expose Dog::legs", legsAddr);

            CallToolResult r = client.callTool(new CallToolRequest("find-vtables-containing-function",
                Map.of("programPath", path, "functionAddress", legsAddr)));
            assertMcpResultNotError(r, "find-vtables-containing-function");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            assertEquals("programPath echoed back", path, json.get("programPath").asText());
            assertEquals("functionAddress echoed back", legsAddr,
                json.get("functionAddress").asText());
            assertEquals("functionName resolved to legs", "legs",
                json.get("functionName").asText());
            assertEquals("Dog::legs appears in exactly one vtable", 1,
                json.get("vtableCount").asInt());
            assertEquals("vtableCount matches vtables array size",
                json.get("vtableCount").asInt(), json.get("vtables").size());

            JsonNode vt = json.get("vtables").get(0);
            assertTrue("vtable entry has vtableAddress", vt.has("vtableAddress"));
            // legs is the 3rd method slot (index 2) at offset 0x10 (2 * 8).
            assertEquals("legs sits at slot index 2", 2, vt.get("slotIndex").asInt());
            assertEquals("legs slot offset is 0x10", "0x10", vt.get("slotOffset").asText());
        });
    }

    /**
     * find-vtable-callers on Dog::legs resolves the indirect virtual dispatch
     * site in dispatch(const Animal*). The vtable slot offset (0x10) matches the
     * x86_64 indirect call {@code CALL qword ptr [RAX + 0x10]}. Pins the real
     * caller output shape and confirms the indirect dispatch IS resolved.
     */
    @Test
    public void testFindVtableCallers() throws Exception {
        String path = AnalyzedFixtureSupport.importAndAnalyze(this, "test_cpp_x86_64");
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            String legsAddr = addressOfSymbol(client, path, DOG_LEGS_MANGLED);
            assertNotNull("fixture must expose Dog::legs", legsAddr);

            CallToolResult r = client.callTool(new CallToolRequest("find-vtable-callers",
                Map.of("programPath", path, "functionAddress", legsAddr)));
            assertMcpResultNotError(r, "find-vtable-callers");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            assertEquals("programPath echoed back", path, json.get("programPath").asText());
            assertEquals("functionAddress echoed back", legsAddr,
                json.get("functionAddress").asText());
            assertEquals("functionName resolved to legs", "legs",
                json.get("functionName").asText());

            // The vtables[] section reports the slot whose offset is searched for.
            assertTrue("response carries the vtable slot info", json.get("vtables").size() > 0);
            assertEquals("searched slot offset is legs' 0x10", "0x10",
                json.get("vtables").get(0).get("slotOffset").asText());

            // The indirect dispatch through the base pointer IS surfaced.
            assertEquals("potentialCallerCount matches array size",
                json.get("potentialCallers").size(), json.get("potentialCallerCount").asInt());
            assertEquals("exactly the one dispatch() indirect call is found", 1,
                json.get("potentialCallerCount").asInt());

            JsonNode caller = json.get("potentialCallers").get(0);
            assertTrue("caller has a call-site address", caller.has("address"));
            assertEquals("matched offset is the legs slot offset", "0x10",
                caller.get("offset").asText());
            assertEquals("indirect call resolved inside dispatch()", "dispatch",
                caller.get("function").asText());
            assertTrue("caller carries the disassembled instruction text",
                caller.get("instruction").asText().toUpperCase().contains("CALL"));
            assertTrue("caller carries the operand representation", caller.has("operand"));
        });
    }

    /**
     * Error/edge-path pinning. Two real behaviors observed on this fixture:
     * (1) a genuinely missing program errors; (2) analyze-vtable on a
     * non-vtable code address does NOT error — it returns hasStructure=false
     * with a single non-function "end of vtable" entry.
     */
    @Test
    public void testErrorAndEdgePaths() throws Exception {
        // (1) Missing program -> hard MCP error (no fixture needed).
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult missing = client.callTool(new CallToolRequest("analyze-vtable",
                Map.of("programPath", "/does-not-exist", "vtableAddress", "0x1000")));
            assertTrue("analyze-vtable on a missing program should error", missing.isError());
        });

        // (2) analyze-vtable on a non-vtable code address is NOT an error; it
        //     reports a structure-less, single non-function terminator entry.
        String path = AnalyzedFixtureSupport.importAndAnalyze(this, "test_cpp_x86_64");
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            String legsAddr = addressOfSymbol(client, path, DOG_LEGS_MANGLED);
            assertNotNull("fixture must expose Dog::legs", legsAddr);

            CallToolResult r = client.callTool(new CallToolRequest("analyze-vtable",
                Map.of("programPath", path, "vtableAddress", legsAddr)));
            assertMcpResultNotError(r, "analyze-vtable on a non-vtable address (graceful, not an error)");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());

            assertEquals("vtableAddress echoed back", legsAddr, json.get("vtableAddress").asText());
            assertFalse("code address has no vtable structure",
                json.get("hasStructure").asBoolean());
            // The reader reads one word (function prologue bytes), finds it is
            // not a function pointer, records it as a terminator, and stops.
            assertEquals("a non-vtable address yields a single terminator entry",
                1, json.get("entryCount").asInt());
            JsonNode only = json.get("entries").get(0);
            assertTrue("the single entry resolves to no function",
                only.get("functionName").isNull());
            assertTrue("the single entry is flagged as a non-function/end-of-vtable",
                only.has("note"));
        });
    }
}
