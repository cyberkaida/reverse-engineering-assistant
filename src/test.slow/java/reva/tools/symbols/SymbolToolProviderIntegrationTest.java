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
package reva.tools.symbols;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

public class SymbolToolProviderIntegrationTest extends RevaIntegrationTestBase {
    private String programPath;
    private Address fnAddr;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();
        fnAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01001000);
        int tx = program.startTransaction("symbols setup");
        try {
            FunctionManager fm = program.getFunctionManager();
            fm.createFunction("myFunction", fnAddr,
                new AddressSet(fnAddr, fnAddr.add(0x40)), SourceType.USER_DEFINED);
            SymbolTable st = program.getSymbolTable();
            st.createLabel(fnAddr.add(0x100), "myLabel", SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(tx, true);
        }
        env.open(program);
    }

    @Test
    public void testGetSymbolsCount() throws Exception {
        long actual = countNonDefaultSymbols();
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult r = client.callTool(new CallToolRequest("get-symbols-count",
                Map.of("programPath", programPath, "filterDefaultNames", true)));
            assertMcpResultNotError(r, "get-symbols-count");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());
            assertEquals("count must match program symbol table",
                actual, json.get("count").asLong());
            assertTrue(json.get("filterDefaultNames").asBoolean());
        });
    }

    @Test
    public void testGetSymbolsReturnsCreatedSymbols() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult r = client.callTool(new CallToolRequest("get-symbols",
                Map.of("programPath", programPath, "maxCount", 1000)));
            assertMcpResultNotError(r, "get-symbols");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());
            assertTrue(json.has("symbols"));
            boolean foundFn = false, foundLabel = false;
            for (JsonNode s : json.get("symbols")) {
                if ("myFunction".equals(s.get("name").asText())) {
                    foundFn = true;
                    assertEquals("0x01001000", s.get("address").asText());
                    assertTrue(s.get("isFunction").asBoolean());
                }
                if ("myLabel".equals(s.get("name").asText())) foundLabel = true;
            }
            assertTrue("get-symbols must include the created function", foundFn);
            assertTrue("get-symbols must include the created label", foundLabel);
        });
    }

    @Test
    public void testGetSymbolsPagination() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult r = client.callTool(new CallToolRequest("get-symbols",
                Map.of("programPath", programPath, "startIndex", 0, "maxCount", 1)));
            assertMcpResultNotError(r, "get-symbols paginated");
            JsonNode json = parseJsonContent(((TextContent) r.content().get(0)).text());
            assertEquals(0, json.get("startIndex").asInt());
            assertEquals(1, json.get("requestedCount").asInt());
            assertEquals("with maxCount=1 and >=2 symbols, exactly one is returned",
                1, json.get("actualCount").asInt());
            assertEquals(json.get("startIndex").asInt() + json.get("actualCount").asInt(),
                json.get("nextStartIndex").asInt());
        });
    }

    @Test
    public void testGetSymbolsCountMissingProgramErrors() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult r = client.callTool(new CallToolRequest("get-symbols-count",
                Map.of("programPath", "/does-not-exist")));
            assertTrue("missing program must error", r.isError());
        });
    }

    /**
     * Mirror the get-symbols-count handler's default counting semantics:
     * iterate all symbols, skip externals (includeExternal defaults to false),
     * and filter Ghidra default names (filterDefaultNames defaults to true).
     */
    private long countNonDefaultSymbols() {
        long n = 0;
        for (ghidra.program.model.symbol.Symbol s : program.getSymbolTable().getAllSymbols(true)) {
            if (s.isExternal()) {
                continue;
            }
            if (!reva.util.SymbolUtil.isDefaultSymbolName(s.getName())) {
                n++;
            }
        }
        return n;
    }
}
