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
package reva.server;

import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import org.junit.After;
import org.junit.Test;

import reva.plugin.ConfigManager;

/**
 * Regression test for issue #366: after a server restart (triggered by any
 * config change — port, host, API key toggle/change, enabled flag), the MCP
 * streamable endpoint answered {@code initialize} with HTTP 500:
 * "Cannot invoke McpStreamableServerSession$Factory.startSession(...) because
 * this.sessionFactory is null".
 *
 * <p>Root cause: restartServer() recreated the transport provider, but the
 * McpServer — built once in the constructor — wires its session factory into
 * the provider instance that existed at build time. The recreated provider
 * served by Jetty therefore never received a session factory.
 */
public class ServerRestartInitializeIntegrationTest {

    private McpServerManager manager;

    @After
    public void tearDown() {
        if (manager != null) {
            manager.shutdown();
            manager = null;
        }
    }

    @Test
    public void initializeSucceedsAfterRestart() throws Exception {
        ConfigManager config = new ConfigManager();
        config.setRandomAvailablePort();
        config.setServerHost("127.0.0.1");
        manager = new McpServerManager(config);
        manager.startServer();
        assertTrue("Server should start on localhost", manager.isServerRunning());

        // Sanity: the endpoint works on first start (proves the HTTP plumbing
        // in this test is correct, so the post-restart assertion is meaningful).
        assertInitializeSucceeds(config.getServerPort(), "before restart");

        // Any config-triggered restart (port/host/API-key change) funnels through here.
        manager.restartServer();
        assertTrue("Server should be running after restart", manager.isServerRunning());

        // Issue #366: this POST returned 500 (NPE on null sessionFactory) because
        // the restart swapped in a transport provider the McpServer never wired.
        assertInitializeSucceeds(config.getServerPort(), "after restart");
    }

    /** POSTs a real MCP initialize request and asserts a 200 with a session id. */
    private static void assertInitializeSucceeds(int port, String when) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) URI
            .create("http://127.0.0.1:" + port + "/mcp/message")
            .toURL()
            .openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(10000);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Accept", "text/event-stream, application/json");

        String body = """
            {"jsonrpc":"2.0","id":1,"method":"initialize","params":{\
            "protocolVersion":"2025-06-18","capabilities":{},\
            "clientInfo":{"name":"reva-regression-test","version":"1.0"}}}""";
        try (OutputStream out = conn.getOutputStream()) {
            out.write(body.getBytes(StandardCharsets.UTF_8));
        }

        int status = conn.getResponseCode();
        String detail = readBody(status >= 400 ? conn.getErrorStream() : conn.getInputStream());
        assertEquals("initialize " + when + " must return 200, body: " + detail, 200, status);

        String sessionId = conn.getHeaderField("mcp-session-id");
        assertNotNull("initialize " + when + " must return an mcp-session-id header", sessionId);
        assertFalse("session id must not be blank", sessionId.isBlank());
        conn.disconnect();
    }

    private static String readBody(InputStream in) throws Exception {
        if (in == null) {
            return "<no body>";
        }
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        }
        return sb.toString();
    }
}
