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
package reva.tools.memory;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.Map;

import org.junit.Test;
import org.mockito.ArgumentCaptor;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

/**
 * Unit tests for read-memory argument validation and tool documentation.
 */
public class MemoryToolProviderFormatTest {

    private static SyncToolSpecification readMemorySpec() {
        McpSyncServer server = mock(McpSyncServer.class);
        new MemoryToolProvider(server).registerTools();

        ArgumentCaptor<SyncToolSpecification> specCaptor =
            ArgumentCaptor.forClass(SyncToolSpecification.class);
        verify(server, atLeastOnce()).addTool(specCaptor.capture());
        for (SyncToolSpecification spec : specCaptor.getAllValues()) {
            if (spec.tool().name().equals("read-memory")) {
                return spec;
            }
        }
        throw new AssertionError("read-memory tool was not registered");
    }

    private static CallToolResult call(Map<String, Object> args) {
        return readMemorySpec().callHandler().apply(null,
            new CallToolRequest("read-memory", args));
    }

    private static String errorText(CallToolResult result) {
        assertTrue("expected an error result", result.isError());
        assertEquals(1, result.content().size());
        return ((TextContent) result.content().get(0)).text();
    }

    @Test
    public void unknownFormatNamesTheValidValues() {
        String text = errorText(call(Map.of(
            "addressOrSymbol", "0x1000", "format", "utf-32")));
        assertTrue(text, text.contains("utf-32"));
        assertTrue(text, text.contains("'hex'"));
        assertTrue(text, text.contains("'bytes'"));
        assertTrue(text, text.contains("'both'"));
        assertTrue(text, text.contains("'ascii'"));
        assertTrue(text, text.contains("'utf16'"));
    }

    @Test
    public void nonPositiveLengthStatesTheRange() {
        String text = errorText(call(Map.of(
            "addressOrSymbol", "0x1000", "length", 0)));
        assertEquals("Invalid length: 0 (must be 1-8192; omit for the default 16)", text);
    }

    @Test
    public void oversizedLengthStatesTheRange() {
        String text = errorText(call(Map.of(
            "addressOrSymbol", "0x1000", "length", 9000)));
        assertEquals("Invalid length: 9000 (must be 1-8192; omit for the default 16)", text);
    }

    @Test
    public void toolDescriptionNamesTheFormats() {
        String description = readMemorySpec().tool().description().toLowerCase();
        assertTrue(description, description.contains("hex"));
        assertTrue(description, description.contains("bytes"));
        assertTrue(description, description.contains("both"));
        assertTrue(description, description.contains("ascii"));
        assertTrue(description, description.contains("utf16"));
    }

    @Test
    public void formatSchemaListsAllFormatsAndDefaultsToHex() {
        Object converted = new ObjectMapper().convertValue(
            readMemorySpec().tool().inputSchema(), Map.class);
        Map<?, ?> properties = (Map<?, ?>) ((Map<?, ?>) converted).get("properties");
        Map<?, ?> format = (Map<?, ?>) properties.get("format");

        assertEquals("hex", format.get("default"));
        String description = String.valueOf(format.get("description")).toLowerCase();
        assertTrue(description, description.contains("'hex'"));
        assertTrue(description, description.contains("'bytes'"));
        assertTrue(description, description.contains("'both'"));
        assertTrue(description, description.contains("'ascii'"));
        assertTrue(description, description.contains("'utf16'"));
    }
}
