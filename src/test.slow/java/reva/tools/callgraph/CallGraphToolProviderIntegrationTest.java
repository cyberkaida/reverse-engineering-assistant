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
package reva.tools.callgraph;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import reva.RevaIntegrationTestBase;

public class CallGraphToolProviderIntegrationTest extends RevaIntegrationTestBase {
    private String programPath;
    private Address mainAddr, helperAddr, leafAddr;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();
        var space = program.getAddressFactory().getDefaultAddressSpace();
        mainAddr = space.getAddress(0x01001000);
        helperAddr = space.getAddress(0x01002000);
        leafAddr = space.getAddress(0x01003000);
        int tx = program.startTransaction("callgraph setup");
        try {
            FunctionManager fm = program.getFunctionManager();
            fm.createFunction("main", mainAddr, new AddressSet(mainAddr, mainAddr.add(0x80)), SourceType.USER_DEFINED);
            fm.createFunction("helper", helperAddr, new AddressSet(helperAddr, helperAddr.add(0x40)), SourceType.USER_DEFINED);
            fm.createFunction("leaf", leafAddr, new AddressSet(leafAddr, leafAddr.add(0x20)), SourceType.USER_DEFINED);
            ReferenceManager rm = program.getReferenceManager();
            rm.addMemoryReference(mainAddr.add(0x10), helperAddr, RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
            rm.addMemoryReference(mainAddr.add(0x20), leafAddr, RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
            rm.addMemoryReference(helperAddr.add(0x10), leafAddr, RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
        } finally {
            program.endTransaction(tx, true);
        }
        env.open(program);
    }

    @Test
    public void testGetCallGraphFromMain() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult r = client.callTool(new CallToolRequest("get-call-graph",
                Map.of("programPath", programPath, "functionAddress", "0x01001000", "depth", 2)));
            assertMcpResultNotError(r, "get-call-graph");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());
            assertEquals(2, json.get("depth").asInt());
            // Fixture has exactly 2 direct callees of main (helper, leaf); pin the count.
            assertEquals(2, json.get("calleeCount").asInt());
            assertTrue(collectNames(json.get("callees")).contains("helper"));
            assertTrue(collectNames(json.get("callees")).contains("leaf"));
        });
    }

    @Test
    public void testGetCallTreeCallees() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult r = client.callTool(new CallToolRequest("get-call-tree",
                Map.of("programPath", programPath, "functionAddress", "0x01001000",
                       "direction", "callees", "maxDepth", 3)));
            assertMcpResultNotError(r, "get-call-tree");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());
            assertEquals("callees", json.get("direction").asText());
            // Tree view re-visits leaf on two branches (main->leaf and main->helper->leaf),
            // so the node count is main + helper + leaf + leaf = 4. Pin it exactly.
            assertEquals(4, json.get("totalNodes").asInt());
            // Tree root is main with a non-empty "callees" child array.
            JsonNode tree = json.get("tree");
            assertNotNull("tree present", tree);
            assertEquals("main", tree.get("name").asText());
            JsonNode children = tree.get("callees");
            assertNotNull("tree root has a callees child array", children);
            assertTrue("tree root has callee children", children.isArray() && children.size() > 0);
            assertTrue("main's direct callees include helper and leaf",
                collectNames(children).contains("helper") && collectNames(children).contains("leaf"));
        });
    }

    @Test
    public void testFindCommonCallersOfLeaf() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult r = client.callTool(new CallToolRequest("find-common-callers",
                Map.of("programPath", programPath,
                       "functionAddresses", List.of("0x01003000"))));
            assertMcpResultNotError(r, "find-common-callers");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());
            List<String> callers = collectNames(json.get("commonCallers"));
            assertTrue("main calls leaf", callers.contains("main"));
            assertTrue("helper calls leaf", callers.contains("helper"));
        });
    }

    @Test
    public void testCallGraphInvalidAddressErrors() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult r = client.callTool(new CallToolRequest("get-call-graph",
                Map.of("programPath", programPath, "functionAddress", "0x01000ff0")));
            // Address is inside mapped memory but has no function: tool returns an error
            // result with message "No function at address: 0x01000ff0".
            assertTrue("get-call-graph on an address with no function should error", r.isError());
            assertTrue("error message names the missing function address",
                ((TextContent) r.content().get(0)).text().contains("No function at address"));
        });
    }

    private List<String> collectNames(JsonNode arr) {
        List<String> out = new ArrayList<>();
        if (arr != null) for (JsonNode n : arr) if (n.has("name")) out.add(n.get("name").asText());
        return out;
    }
}
