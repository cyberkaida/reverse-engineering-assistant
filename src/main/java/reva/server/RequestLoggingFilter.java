/*
 * Copyright (c) 2024-2025 The ReVa authors
 * SPDX-License-Identifier: Apache-2.0
 */

package reva.server;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import ghidra.util.Msg;
import reva.plugin.ConfigManager;
import reva.util.RevaToolLogger;

import java.io.IOException;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Filter that logs incoming MCP requests and responses.
 *
 * <p>This filter provides two logging modes:
 * <ul>
 *   <li><b>Debug mode</b> ({@link ConfigManager#isDebugMode()}): Logs request headers to Ghidra's log</li>
 *   <li><b>Request logging</b> ({@link ConfigManager#isRequestLoggingEnabled()}): Logs full HTTP
 *       request/response bodies to reva-tools.log for debugging MCP protocol issues</li>
 * </ul>
 */
public class RequestLoggingFilter implements Filter {
    private final ConfigManager configManager;

    /**
     * Creates a new request logging filter.
     *
     * @param configManager The config manager to check logging settings
     */
    public RequestLoggingFilter(ConfigManager configManager) {
        this.configManager = configManager;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // No initialization needed
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Debug mode: Log headers to Ghidra log
        if (configManager.isDebugMode()) {
            logHeadersToGhidra(httpRequest);
        }

        // Request logging mode: Log full HTTP request/response to reva-tools.log
        if (configManager.isRequestLoggingEnabled()) {
            doFilterWithBodyLogging(httpRequest, httpResponse, chain);
        } else {
            chain.doFilter(request, response);
        }
    }

    /**
     * Log request headers to Ghidra's debug log.
     */
    private void logHeadersToGhidra(HttpServletRequest req) {
        StringBuilder headers = new StringBuilder();
        Enumeration<String> headerNames = req.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement();
            headers.append(name).append("=").append(req.getHeader(name)).append("; ");
        }

        Msg.debug(this, String.format("MCP Request: %s %s Headers: %s",
            req.getMethod(),
            req.getRequestURI(),
            headers.toString()));
    }

    /**
     * Filter with full request/response body logging to reva-tools.log.
     */
    private void doFilterWithBodyLogging(HttpServletRequest request, HttpServletResponse response,
                                         FilterChain chain) throws IOException, ServletException {

        String requestId = RevaToolLogger.generateRequestId();
        long startTime = System.currentTimeMillis();

        // Wrap request to capture body
        CachingRequestWrapper wrappedRequest = new CachingRequestWrapper(request);

        // Wrap response to capture body
        CachingResponseWrapper wrappedResponse = new CachingResponseWrapper(response);

        // Log HTTP request
        Map<String, String> requestHeaders = extractHeaders(request);
        RevaToolLogger.logHttpRequest(
            requestId,
            request.getMethod(),
            request.getRequestURI(),
            requestHeaders,
            wrappedRequest.getCachedBody()
        );

        // Log to Ghidra's application log for correlation
        Msg.debug(this, String.format("[ReVa:%s] HTTP %s %s",
            requestId, request.getMethod(), request.getRequestURI()));

        try {
            // Execute the filter chain with wrapped request/response
            chain.doFilter(wrappedRequest, wrappedResponse);

            // Flush to ensure all content is captured
            wrappedResponse.flushBuffer();

        } finally {
            // Log HTTP response
            long durationMs = System.currentTimeMillis() - startTime;
            Map<String, String> responseHeaders = extractResponseHeaders(wrappedResponse);
            RevaToolLogger.logHttpResponse(
                requestId,
                wrappedResponse.getStatus(),
                durationMs,
                responseHeaders,
                wrappedResponse.getCapturedBody()
            );
        }
    }

    /**
     * Extract request headers into a map.
     */
    private Map<String, String> extractHeaders(HttpServletRequest request) {
        Map<String, String> headers = new LinkedHashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement();
            // Skip authorization headers from logs for security
            if (name.equalsIgnoreCase("Authorization") || name.equalsIgnoreCase("X-API-Key")) {
                headers.put(name, "[REDACTED]");
            } else {
                headers.put(name, request.getHeader(name));
            }
        }
        return headers;
    }

    /**
     * Extract response headers into a map.
     */
    private Map<String, String> extractResponseHeaders(HttpServletResponse response) {
        Map<String, String> headers = new LinkedHashMap<>();
        for (String name : response.getHeaderNames()) {
            headers.put(name, response.getHeader(name));
        }
        return headers;
    }

    @Override
    public void destroy() {
        // No cleanup needed
    }
}
