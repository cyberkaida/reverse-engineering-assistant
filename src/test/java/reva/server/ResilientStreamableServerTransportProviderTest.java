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

import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.lang.reflect.Field;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import io.modelcontextprotocol.spec.HttpHeaders;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpStreamableServerSession;
import jakarta.servlet.AsyncContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Regression tests for the resilience fork's session lifecycle.
 *
 * <p>Reproduces the failure observed in the field: toggling tool groups broadcasts a
 * burst of {@code tools/list_changed} notifications, and if one of those writes lands
 * on a listening SSE stream whose connection the client has already recycled, the
 * write fails. The transport must close only that stream and keep the session in the
 * map, so the client's GET reconnect (with Last-Event-ID) resolves instead of hitting
 * a 404 and dropping every registered tool.
 */
public class ResilientStreamableServerTransportProviderTest {

	private static final String ENDPOINT = "/mcp/message";
	private static final String SESSION_ID = "test-session";

	private ResilientStreamableServerTransportProvider provider;

	@Before
	public void setUp() throws Exception {
		// No keep-alive interval: avoids spinning up the scheduler thread in tests.
		provider = ResilientStreamableServerTransportProvider.builder()
			.mcpEndpoint(ENDPOINT)
			.build();

		// Insert a real session directly. Going through doPost(initialize) would require
		// a wired McpServer/session factory; the session map is the only private detail
		// we need, and a real session exercises the genuine notify -> listeningStream ->
		// transport.sendMessage path that the broadcast travels.
		McpStreamableServerSession session = new McpStreamableServerSession(SESSION_ID, null, null,
				Duration.ofSeconds(1), new HashMap<>(), new HashMap<>());
		sessions(provider).put(SESSION_ID, session);
	}

	@Test
	public void brokenListeningStreamWriteKeepsSessionAlive() throws Exception {
		// Establish the listening SSE stream over a writer whose connection is dead.
		AsyncContext asyncContext = establishListeningStream(failingWriter());

		// Broadcast as a tool toggle would: write fails on the dead connection.
		provider.notifyClients(McpSchema.METHOD_NOTIFICATION_TOOLS_LIST_CHANGED, null).block();

		// The session must survive — only the stream is gone.
		assertTrue("Session must remain after a listening-stream write failure",
				sessions(provider).containsKey(SESSION_ID));
		// The dead stream's async context is completed (stream closed, not leaked).
		verify(asyncContext, atLeastOnce()).complete();
	}

	@Test
	public void sessionSurvivesBrokenStreamSoGetReconnectResolves() throws Exception {
		// First GET establishes a stream that then fails on broadcast.
		establishListeningStream(failingWriter());
		provider.notifyClients(McpSchema.METHOD_NOTIFICATION_TOOLS_LIST_CHANGED, null).block();

		// Client reconnects the GET stream with Last-Event-ID to resume.
		HttpServletResponse reconnect = mock(HttpServletResponse.class);
		when(reconnect.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
		AsyncContext reconnectAsync = mock(AsyncContext.class);
		HttpServletRequest reconnectRequest = getRequest(reconnectAsync);
		when(reconnectRequest.getHeader(HttpHeaders.LAST_EVENT_ID)).thenReturn("5");

		provider.doGet(reconnectRequest, reconnect);

		// Reconnect resolved: the session was found, so no error response of any kind
		// (neither sendError overload) and the stream re-opened.
		verify(reconnect, never()).sendError(eq(HttpServletResponse.SC_NOT_FOUND));
		verify(reconnect, never()).sendError(anyInt());
		verify(reconnect, never()).sendError(anyInt(), anyString());
		verify(reconnectRequest).startAsync();
	}

	// --- helpers ---------------------------------------------------------------

	/** Drives doGet to attach a listening stream backed by the given writer. */
	private AsyncContext establishListeningStream(PrintWriter writer) throws Exception {
		HttpServletResponse response = mock(HttpServletResponse.class);
		when(response.getWriter()).thenReturn(writer);
		AsyncContext asyncContext = mock(AsyncContext.class);
		HttpServletRequest request = getRequest(asyncContext);
		// Fresh listening stream (no replay).
		when(request.getHeader(HttpHeaders.LAST_EVENT_ID)).thenReturn(null);

		provider.doGet(request, response);
		return asyncContext;
	}

	/** A mock GET request for our session, returning the given async context. */
	private HttpServletRequest getRequest(AsyncContext asyncContext) {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getRequestURI()).thenReturn(ENDPOINT);
		when(request.getHeader("Accept")).thenReturn("text/event-stream, application/json");
		when(request.getHeader(HttpHeaders.MCP_SESSION_ID)).thenReturn(SESSION_ID);
		when(request.getHeaderNames()).thenReturn(Collections.enumeration(Collections.emptyList()));
		when(request.startAsync()).thenReturn(asyncContext);
		return request;
	}

	/** A PrintWriter whose underlying connection is dead: every write trips checkError(). */
	private static PrintWriter failingWriter() {
		Writer dead = new Writer() {
			@Override
			public void write(char[] cbuf, int off, int len) throws IOException {
				throw new IOException("client disconnected");
			}

			@Override
			public void flush() throws IOException {
				throw new IOException("client disconnected");
			}

			@Override
			public void close() {
			}
		};
		return new PrintWriter(dead);
	}

	@SuppressWarnings("unchecked")
	private static Map<String, McpStreamableServerSession> sessions(
			ResilientStreamableServerTransportProvider provider) throws Exception {
		Field field = ResilientStreamableServerTransportProvider.class.getDeclaredField("sessions");
		field.setAccessible(true);
		return (Map<String, McpStreamableServerSession>) field.get(provider);
	}
}
