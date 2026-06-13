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
package reva.tools;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema.Tool;

/**
 * Unit tests for {@link AbstractToolProvider#unregisterTools()}.
 */
public class AbstractToolProviderUnregisterTest {

    @Mock
    private McpSyncServer mockServer;

    /** Minimal provider that registers two no-op tools. */
    private static class TwoToolProvider extends AbstractToolProvider {
        TwoToolProvider(McpSyncServer server) {
            super(server);
        }

        @Override
        public void registerTools() {
            registerTool(Tool.builder()
                .name("tool-one")
                .description("first")
                .inputSchema(createSchema(Map.of(), List.of()))
                .build(), (exchange, request) -> null);
            registerTool(Tool.builder()
                .name("tool-two")
                .description("second")
                .inputSchema(createSchema(Map.of(), List.of()))
                .build(), (exchange, request) -> null);
        }
    }

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void unregisterRemovesEachToolAndClearsList() {
        TwoToolProvider provider = new TwoToolProvider(mockServer);
        provider.registerTools();
        assertEquals(2, provider.registeredTools.size());

        provider.unregisterTools();

        verify(mockServer).removeTool("tool-one");
        verify(mockServer).removeTool("tool-two");
        assertTrue("registeredTools must be empty after unregister",
            provider.registeredTools.isEmpty());
    }

    @Test
    public void unregisterIsSafeWhenNothingRegistered() {
        TwoToolProvider provider = new TwoToolProvider(mockServer);
        provider.unregisterTools();
        verify(mockServer, never()).removeTool(anyString());
        assertTrue(provider.registeredTools.isEmpty());
    }
}
