/*
 * Copyright 2024-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Forked from MCP Java SDK's HttpServletStreamableServerTransportProvider (v0.17.0).
 *
 * FIX: The upstream sendMessage() catches bare Exception and unconditionally removes
 * the session from the sessions map. A serialization error on a single message
 * permanently kills the entire session. This fork splits the catch block to separate
 * serialization failures (non-fatal) from connection failures (fatal).
 *
 * No upstream issue filed yet — the bug is in HttpServletStreamableServerTransportProvider.sendMessage()
 * which catches bare Exception and unconditionally calls sessions.remove(), so any serialization
 * error permanently kills the session.
 */
package reva.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.modelcontextprotocol.json.TypeRef;

import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpTransportContextExtractor;
import io.modelcontextprotocol.server.transport.ServerTransportSecurityException;
import io.modelcontextprotocol.server.transport.ServerTransportSecurityValidator;
import io.modelcontextprotocol.spec.HttpHeaders;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpStreamableServerSession;
import io.modelcontextprotocol.spec.McpStreamableServerTransport;
import io.modelcontextprotocol.spec.McpStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.ProtocolVersions;
import io.modelcontextprotocol.util.Assert;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.util.KeepAliveScheduler;
import jakarta.servlet.AsyncContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Resilient fork of the MCP SDK's HttpServletStreamableServerTransportProvider.
 *
 * <p>
 * The upstream implementation catches bare {@code Exception} in {@code sendMessage()}
 * and unconditionally removes the session, which means a single serialization error
 * permanently kills the session for ALL clients. This fork splits the catch block to
 * separate serialization failures (session stays alive) from connection failures
 * (session is properly removed).
 *
 * @see io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider
 */
@WebServlet(asyncSupported = true)
public class ResilientStreamableServerTransportProvider extends HttpServlet
		implements McpStreamableServerTransportProvider {

	private static final Logger logger = LoggerFactory.getLogger(ResilientStreamableServerTransportProvider.class);

	public static final String MESSAGE_EVENT_TYPE = "message";

	public static final String ENDPOINT_EVENT_TYPE = "endpoint";

	private static final String ACCEPT = "Accept";

	public static final String UTF_8 = "UTF-8";

	public static final String APPLICATION_JSON = "application/json";

	public static final String TEXT_EVENT_STREAM = "text/event-stream";

	public static final String FAILED_TO_SEND_ERROR_RESPONSE = "Failed to send error response: {}";

	private final String mcpEndpoint;

	private final boolean disallowDelete;

	private final McpJsonMapper jsonMapper;

	private McpStreamableServerSession.Factory sessionFactory;

	private final ConcurrentHashMap<String, McpStreamableServerSession> sessions = new ConcurrentHashMap<>();

	private McpTransportContextExtractor<HttpServletRequest> contextExtractor;

	private volatile boolean isClosing = false;

	private KeepAliveScheduler keepAliveScheduler;

	private final ServerTransportSecurityValidator securityValidator;

	private ResilientStreamableServerTransportProvider(McpJsonMapper jsonMapper, String mcpEndpoint,
			boolean disallowDelete, McpTransportContextExtractor<HttpServletRequest> contextExtractor,
			Duration keepAliveInterval, ServerTransportSecurityValidator securityValidator) {
		Assert.notNull(jsonMapper, "JsonMapper must not be null");
		Assert.notNull(mcpEndpoint, "MCP endpoint must not be null");
		Assert.notNull(contextExtractor, "Context extractor must not be null");
		Assert.notNull(securityValidator, "Security validator must not be null");

		this.jsonMapper = jsonMapper;
		this.mcpEndpoint = mcpEndpoint;
		this.disallowDelete = disallowDelete;
		this.contextExtractor = contextExtractor;
		this.securityValidator = securityValidator;

		if (keepAliveInterval != null) {
			this.keepAliveScheduler = KeepAliveScheduler
				.builder(() -> (isClosing) ? Flux.empty() : Flux.fromIterable(sessions.values()))
				.initialDelay(keepAliveInterval)
				.interval(keepAliveInterval)
				.build();

			this.keepAliveScheduler.start();
		}
	}

	// Inlined from package-private HttpServletRequestUtils
	private static Map<String, List<String>> extractHeaders(HttpServletRequest request) {
		Map<String, List<String>> headers = new HashMap<>();
		Enumeration<String> names = request.getHeaderNames();
		while (names.hasMoreElements()) {
			String name = names.nextElement();
			headers.put(name, Collections.list(request.getHeaders(name)));
		}
		return headers;
	}

	@Override
	public List<String> protocolVersions() {
		return List.of(ProtocolVersions.MCP_2024_11_05, ProtocolVersions.MCP_2025_03_26,
				ProtocolVersions.MCP_2025_06_18, ProtocolVersions.MCP_2025_11_25);
	}

	@Override
	public void setSessionFactory(McpStreamableServerSession.Factory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	public Mono<Void> notifyClients(String method, Object params) {
		if (this.sessions.isEmpty()) {
			logger.debug("No active sessions to broadcast message to");
			return Mono.empty();
		}

		logger.debug("Attempting to broadcast message to {} active sessions", this.sessions.size());

		return Mono.fromRunnable(() -> {
			this.sessions.values().parallelStream().forEach(session -> {
				try {
					session.sendNotification(method, params).block();
				}
				catch (Exception e) {
					logger.error("Failed to send message to session {}: {}", session.getId(), e.getMessage());
				}
			});
		});
	}

	@Override
	public Mono<Void> notifyClient(String sessionId, String method, Object params) {
		return Mono.defer(() -> {
			McpStreamableServerSession session = this.sessions.get(sessionId);
			if (session == null) {
				logger.debug("Session {} not found", sessionId);
				return Mono.empty();
			}
			return session.sendNotification(method, params);
		});
	}

	@Override
	public Mono<Void> closeGracefully() {
		return Mono.fromRunnable(() -> {
			this.isClosing = true;
			logger.debug("Initiating graceful shutdown with {} active sessions", this.sessions.size());

			this.sessions.values().parallelStream().forEach(session -> {
				try {
					session.closeGracefully().block();
				}
				catch (Exception e) {
					logger.error("Failed to close session {}: {}", session.getId(), e.getMessage());
				}
			});

			this.sessions.clear();
			logger.debug("Graceful shutdown completed");
		}).then().doOnSuccess(v -> {
			sessions.clear();
			logger.debug("Graceful shutdown completed");
			if (this.keepAliveScheduler != null) {
				this.keepAliveScheduler.shutdown();
			}
		});
	}

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		String requestURI = request.getRequestURI();
		if (!requestURI.endsWith(mcpEndpoint)) {
			response.sendError(HttpServletResponse.SC_NOT_FOUND);
			return;
		}

		if (this.isClosing) {
			response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Server is shutting down");
			return;
		}

		try {
			Map<String, List<String>> headers = extractHeaders(request);
			this.securityValidator.validateHeaders(headers);
		}
		catch (ServerTransportSecurityException e) {
			response.sendError(e.getStatusCode(), e.getMessage());
			return;
		}

		List<String> badRequestErrors = new ArrayList<>();

		String accept = request.getHeader(ACCEPT);
		if (accept == null || !accept.contains(TEXT_EVENT_STREAM)) {
			badRequestErrors.add("text/event-stream required in Accept header");
		}

		String sessionId = request.getHeader(HttpHeaders.MCP_SESSION_ID);

		if (sessionId == null || sessionId.isBlank()) {
			badRequestErrors.add("Session ID required in mcp-session-id header");
		}

		if (!badRequestErrors.isEmpty()) {
			String combinedMessage = String.join("; ", badRequestErrors);
			this.responseError(response, HttpServletResponse.SC_BAD_REQUEST,
					McpError.builder(McpSchema.ErrorCodes.METHOD_NOT_FOUND).message(combinedMessage).build());
			return;
		}

		McpStreamableServerSession session = this.sessions.get(sessionId);

		if (session == null) {
			response.sendError(HttpServletResponse.SC_NOT_FOUND);
			return;
		}

		logger.debug("Handling GET request for session: {}", sessionId);

		McpTransportContext transportContext = this.contextExtractor.extract(request);

		try {
			response.setContentType(TEXT_EVENT_STREAM);
			response.setCharacterEncoding(UTF_8);
			response.setHeader("Cache-Control", "no-cache");
			response.setHeader("Connection", "keep-alive");
			response.setHeader("Access-Control-Allow-Origin", "*");

			AsyncContext asyncContext = request.startAsync();
			asyncContext.setTimeout(0);

			ResilientMcpSessionTransport sessionTransport = new ResilientMcpSessionTransport(
					sessionId, asyncContext, response.getWriter());

			// Check if this is a replay request
			if (request.getHeader(HttpHeaders.LAST_EVENT_ID) != null) {
				String lastId = request.getHeader(HttpHeaders.LAST_EVENT_ID);

				try {
					session.replay(lastId)
						.contextWrite(ctx -> ctx.put(McpTransportContext.KEY, transportContext))
						.toIterable()
						.forEach(message -> {
							try {
								sessionTransport.sendMessage(message)
									.contextWrite(ctx -> ctx.put(McpTransportContext.KEY, transportContext))
									.block();
							}
							catch (Exception e) {
								logger.error("Failed to replay message: {}", e.getMessage());
								asyncContext.complete();
							}
						});
				}
				catch (Exception e) {
					logger.error("Failed to replay messages: {}", e.getMessage());
					asyncContext.complete();
				}
			}
			else {
				// Establish new listening stream
				McpStreamableServerSession.McpStreamableServerSessionStream listeningStream = session
					.listeningStream(sessionTransport);

				asyncContext.addListener(new jakarta.servlet.AsyncListener() {
					@Override
					public void onComplete(jakarta.servlet.AsyncEvent event) throws IOException {
						logger.debug("SSE connection completed for session: {}", sessionId);
						listeningStream.close();
					}

					@Override
					public void onTimeout(jakarta.servlet.AsyncEvent event) throws IOException {
						logger.debug("SSE connection timed out for session: {}", sessionId);
						listeningStream.close();
					}

					@Override
					public void onError(jakarta.servlet.AsyncEvent event) throws IOException {
						logger.debug("SSE connection error for session: {}", sessionId);
						listeningStream.close();
					}

					@Override
					public void onStartAsync(jakarta.servlet.AsyncEvent event) throws IOException {
						// No action needed
					}
				});
			}
		}
		catch (Exception e) {
			logger.error("Failed to handle GET request for session {}: {}", sessionId, e.getMessage());
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		}
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		String requestURI = request.getRequestURI();
		if (!requestURI.endsWith(mcpEndpoint)) {
			response.sendError(HttpServletResponse.SC_NOT_FOUND);
			return;
		}

		if (this.isClosing) {
			response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Server is shutting down");
			return;
		}

		try {
			Map<String, List<String>> headers = extractHeaders(request);
			this.securityValidator.validateHeaders(headers);
		}
		catch (ServerTransportSecurityException e) {
			response.sendError(e.getStatusCode(), e.getMessage());
			return;
		}

		List<String> badRequestErrors = new ArrayList<>();

		String accept = request.getHeader(ACCEPT);
		if (accept == null || !accept.contains(TEXT_EVENT_STREAM)) {
			badRequestErrors.add("text/event-stream required in Accept header");
		}
		if (accept == null || !accept.contains(APPLICATION_JSON)) {
			badRequestErrors.add("application/json required in Accept header");
		}

		McpTransportContext transportContext = this.contextExtractor.extract(request);

		try {
			BufferedReader reader = request.getReader();
			StringBuilder body = new StringBuilder();
			String line;
			while ((line = reader.readLine()) != null) {
				body.append(line);
			}

			McpSchema.JSONRPCMessage message = McpSchema.deserializeJsonRpcMessage(jsonMapper, body.toString());

			// Handle initialization request
			if (message instanceof McpSchema.JSONRPCRequest jsonrpcRequest
					&& jsonrpcRequest.method().equals(McpSchema.METHOD_INITIALIZE)) {
				if (!badRequestErrors.isEmpty()) {
					String combinedMessage = String.join("; ", badRequestErrors);
					this.responseError(response, HttpServletResponse.SC_BAD_REQUEST,
							McpError.builder(McpSchema.ErrorCodes.METHOD_NOT_FOUND).message(combinedMessage).build());
					return;
				}

				McpSchema.InitializeRequest initializeRequest = jsonMapper.convertValue(jsonrpcRequest.params(),
						new TypeRef<McpSchema.InitializeRequest>() {
						});
				McpStreamableServerSession.McpStreamableServerSessionInit init = this.sessionFactory
					.startSession(initializeRequest);
				this.sessions.put(init.session().getId(), init.session());

				try {
					McpSchema.InitializeResult initResult = init.initResult().block();

					response.setContentType(APPLICATION_JSON);
					response.setCharacterEncoding(UTF_8);
					response.setHeader(HttpHeaders.MCP_SESSION_ID, init.session().getId());
					response.setStatus(HttpServletResponse.SC_OK);

					String jsonResponse = jsonMapper.writeValueAsString(new McpSchema.JSONRPCResponse(
							McpSchema.JSONRPC_VERSION, jsonrpcRequest.id(), initResult, null));

					PrintWriter writer = response.getWriter();
					writer.write(jsonResponse);
					writer.flush();
					return;
				}
				catch (Exception e) {
					logger.error("Failed to initialize session: {}", e.getMessage());
					this.responseError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
							McpError.builder(McpSchema.ErrorCodes.INTERNAL_ERROR)
								.message("Failed to initialize session: " + e.getMessage())
								.build());
					return;
				}
			}

			String sessionId = request.getHeader(HttpHeaders.MCP_SESSION_ID);

			if (sessionId == null || sessionId.isBlank()) {
				badRequestErrors.add("Session ID required in mcp-session-id header");
			}

			if (!badRequestErrors.isEmpty()) {
				String combinedMessage = String.join("; ", badRequestErrors);
				this.responseError(response, HttpServletResponse.SC_BAD_REQUEST,
						McpError.builder(McpSchema.ErrorCodes.METHOD_NOT_FOUND).message(combinedMessage).build());
				return;
			}

			McpStreamableServerSession session = this.sessions.get(sessionId);

			if (session == null) {
				this.responseError(response, HttpServletResponse.SC_NOT_FOUND,
						McpError.builder(McpSchema.ErrorCodes.INTERNAL_ERROR)
							.message("Session not found: " + sessionId)
							.build());
				return;
			}

			if (message instanceof McpSchema.JSONRPCResponse jsonrpcResponse) {
				session.accept(jsonrpcResponse)
					.contextWrite(ctx -> ctx.put(McpTransportContext.KEY, transportContext))
					.block();
				response.setStatus(HttpServletResponse.SC_ACCEPTED);
			}
			else if (message instanceof McpSchema.JSONRPCNotification jsonrpcNotification) {
				session.accept(jsonrpcNotification)
					.contextWrite(ctx -> ctx.put(McpTransportContext.KEY, transportContext))
					.block();
				response.setStatus(HttpServletResponse.SC_ACCEPTED);
			}
			else if (message instanceof McpSchema.JSONRPCRequest jsonrpcRequest) {
				// For streaming responses, we need to return SSE
				response.setContentType(TEXT_EVENT_STREAM);
				response.setCharacterEncoding(UTF_8);
				response.setHeader("Cache-Control", "no-cache");
				response.setHeader("Connection", "keep-alive");
				response.setHeader("Access-Control-Allow-Origin", "*");

				AsyncContext asyncContext = request.startAsync();
				asyncContext.setTimeout(0);

				ResilientMcpSessionTransport sessionTransport = new ResilientMcpSessionTransport(
						sessionId, asyncContext, response.getWriter());

				try {
					session.responseStream(jsonrpcRequest, sessionTransport)
						.contextWrite(ctx -> ctx.put(McpTransportContext.KEY, transportContext))
						.block();
				}
				catch (Exception e) {
					logger.error("Failed to handle request stream: {}", e.getMessage());
					asyncContext.complete();
				}
			}
			else {
				this.responseError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
						McpError.builder(McpSchema.ErrorCodes.INVALID_REQUEST).message("Unknown message type").build());
			}
		}
		catch (IllegalArgumentException | IOException e) {
			logger.error("Failed to deserialize message: {}", e.getMessage());
			this.responseError(response, HttpServletResponse.SC_BAD_REQUEST,
					McpError.builder(McpSchema.ErrorCodes.INVALID_REQUEST)
						.message("Invalid message format: " + e.getMessage())
						.build());
		}
		catch (Exception e) {
			logger.error("Error handling message: {}", e.getMessage());
			try {
				this.responseError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
						McpError.builder(McpSchema.ErrorCodes.INTERNAL_ERROR)
							.message("Error processing message: " + e.getMessage())
							.build());
			}
			catch (IOException ex) {
				logger.error(FAILED_TO_SEND_ERROR_RESPONSE, ex.getMessage());
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error processing message");
			}
		}
	}

	@Override
	protected void doDelete(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		String requestURI = request.getRequestURI();
		if (!requestURI.endsWith(mcpEndpoint)) {
			response.sendError(HttpServletResponse.SC_NOT_FOUND);
			return;
		}

		if (this.isClosing) {
			response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Server is shutting down");
			return;
		}

		try {
			Map<String, List<String>> headers = extractHeaders(request);
			this.securityValidator.validateHeaders(headers);
		}
		catch (ServerTransportSecurityException e) {
			response.sendError(e.getStatusCode(), e.getMessage());
			return;
		}

		if (this.disallowDelete) {
			response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
			return;
		}

		McpTransportContext transportContext = this.contextExtractor.extract(request);

		if (request.getHeader(HttpHeaders.MCP_SESSION_ID) == null) {
			this.responseError(response, HttpServletResponse.SC_BAD_REQUEST,
					McpError.builder(McpSchema.ErrorCodes.METHOD_NOT_FOUND)
						.message("Session ID required in mcp-session-id header")
						.build());
			return;
		}

		String sessionId = request.getHeader(HttpHeaders.MCP_SESSION_ID);
		McpStreamableServerSession session = this.sessions.get(sessionId);

		if (session == null) {
			response.sendError(HttpServletResponse.SC_NOT_FOUND);
			return;
		}

		try {
			session.delete().contextWrite(ctx -> ctx.put(McpTransportContext.KEY, transportContext)).block();
			this.sessions.remove(sessionId);
			response.setStatus(HttpServletResponse.SC_OK);
		}
		catch (Exception e) {
			logger.error("Failed to delete session {}: {}", sessionId, e.getMessage());
			try {
				this.responseError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
						McpError.builder(McpSchema.ErrorCodes.INTERNAL_ERROR).message(e.getMessage()).build());
			}
			catch (IOException ex) {
				logger.error(FAILED_TO_SEND_ERROR_RESPONSE, ex.getMessage());
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error deleting session");
			}
		}
	}

	public void responseError(HttpServletResponse response, int httpCode, McpError mcpError) throws IOException {
		response.setContentType(APPLICATION_JSON);
		response.setCharacterEncoding(UTF_8);
		response.setStatus(httpCode);
		String jsonError = jsonMapper.writeValueAsString(mcpError);
		PrintWriter writer = response.getWriter();
		writer.write(jsonError);
		writer.flush();
		return;
	}

	private void sendEvent(PrintWriter writer, String eventType, String data, String id) throws IOException {
		if (id != null) {
			writer.write("id: " + id + "\n");
		}
		writer.write("event: " + eventType + "\n");
		writer.write("data: " + data + "\n\n");
		writer.flush();

		if (writer.checkError()) {
			throw new IOException("Client disconnected");
		}
	}

	@Override
	public void destroy() {
		closeGracefully().block();
		super.destroy();
	}

	/**
	 * Resilient session transport that separates serialization errors from connection
	 * errors in sendMessage(). Serialization failures don't kill the session.
	 */
	private class ResilientMcpSessionTransport implements McpStreamableServerTransport {

		private final String sessionId;

		private final AsyncContext asyncContext;

		private final PrintWriter writer;

		private volatile boolean closed = false;

		private final ReentrantLock lock = new ReentrantLock();

		ResilientMcpSessionTransport(String sessionId, AsyncContext asyncContext, PrintWriter writer) {
			this.sessionId = sessionId;
			this.asyncContext = asyncContext;
			this.writer = writer;
			logger.debug("Resilient session transport {} initialized with SSE writer", sessionId);
		}

		@Override
		public Mono<Void> sendMessage(McpSchema.JSONRPCMessage message) {
			return sendMessage(message, null);
		}

		/**
		 * Sends a JSON-RPC message with resilient error handling.
		 *
		 * <p>FIX: The upstream MCP SDK catches bare Exception and removes the session
		 * on ANY error, including serialization failures. This implementation splits
		 * the operation: serialization errors are logged but don't kill the session,
		 * while actual connection failures properly remove the session.
		 */
		@Override
		public Mono<Void> sendMessage(McpSchema.JSONRPCMessage message, String messageId) {
			return Mono.fromRunnable(() -> {
				if (this.closed) {
					logger.debug("Attempted to send message to closed session: {}", this.sessionId);
					return;
				}

				lock.lock();
				try {
					if (this.closed) {
						logger.debug("Session {} was closed during message send attempt", this.sessionId);
						return;
					}

					// Step 1: Serialize the message. If this fails, the session is still
					// alive -- only this particular message couldn't be serialized.
					String jsonText;
					try {
						jsonText = jsonMapper.writeValueAsString(message);
					}
					catch (Exception e) {
						logger.error("Failed to serialize message for session {}: {}",
								this.sessionId, e.getMessage());
						return; // Session stays alive
					}

					// Step 2: Send the serialized message over the wire. If this fails,
					// the client has actually disconnected and the session should be removed.
					try {
						ResilientStreamableServerTransportProvider.this.sendEvent(writer, MESSAGE_EVENT_TYPE, jsonText,
								messageId != null ? messageId : this.sessionId);
						logger.debug("Message sent to session {} with ID {}", this.sessionId, messageId);
					}
					catch (Exception e) {
						logger.error("Failed to send message to session {}: {}",
								this.sessionId, e.getMessage());
						ResilientStreamableServerTransportProvider.this.sessions.remove(this.sessionId);
						this.asyncContext.complete();
					}
				}
				finally {
					lock.unlock();
				}
			});
		}

		@Override
		public <T> T unmarshalFrom(Object data, TypeRef<T> typeRef) {
			return jsonMapper.convertValue(data, typeRef);
		}

		@Override
		public Mono<Void> closeGracefully() {
			return Mono.fromRunnable(() -> {
				ResilientMcpSessionTransport.this.close();
			});
		}

		@Override
		public void close() {
			lock.lock();
			try {
				if (this.closed) {
					logger.debug("Session transport {} already closed", this.sessionId);
					return;
				}

				this.closed = true;

				this.asyncContext.complete();
				logger.debug("Successfully completed async context for session {}", sessionId);
			}
			catch (Exception e) {
				logger.warn("Failed to complete async context for session {}: {}", sessionId, e.getMessage());
			}
			finally {
				lock.unlock();
			}
		}

	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {

		private McpJsonMapper jsonMapper;

		private String mcpEndpoint = "/mcp";

		private boolean disallowDelete = false;

		private McpTransportContextExtractor<HttpServletRequest> contextExtractor = (
				serverRequest) -> McpTransportContext.EMPTY;

		private Duration keepAliveInterval;

		private ServerTransportSecurityValidator securityValidator = ServerTransportSecurityValidator.NOOP;

		public Builder jsonMapper(McpJsonMapper jsonMapper) {
			Assert.notNull(jsonMapper, "JsonMapper must not be null");
			this.jsonMapper = jsonMapper;
			return this;
		}

		public Builder mcpEndpoint(String mcpEndpoint) {
			Assert.notNull(mcpEndpoint, "MCP endpoint must not be null");
			this.mcpEndpoint = mcpEndpoint;
			return this;
		}

		public Builder disallowDelete(boolean disallowDelete) {
			this.disallowDelete = disallowDelete;
			return this;
		}

		public Builder contextExtractor(McpTransportContextExtractor<HttpServletRequest> contextExtractor) {
			Assert.notNull(contextExtractor, "Context extractor must not be null");
			this.contextExtractor = contextExtractor;
			return this;
		}

		public Builder keepAliveInterval(Duration keepAliveInterval) {
			this.keepAliveInterval = keepAliveInterval;
			return this;
		}

		public Builder securityValidator(ServerTransportSecurityValidator securityValidator) {
			Assert.notNull(securityValidator, "Security validator must not be null");
			this.securityValidator = securityValidator;
			return this;
		}

		public ResilientStreamableServerTransportProvider build() {
			Assert.notNull(this.mcpEndpoint, "MCP endpoint must be set");
			return new ResilientStreamableServerTransportProvider(
					jsonMapper == null ? McpJsonDefaults.getMapper() : jsonMapper, mcpEndpoint, disallowDelete,
					contextExtractor, keepAliveInterval, securityValidator);
		}

	}

}
