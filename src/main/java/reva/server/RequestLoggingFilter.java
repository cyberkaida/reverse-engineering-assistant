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
import ghidra.util.Msg;
import reva.plugin.ConfigManager;
import java.io.IOException;
import java.util.Enumeration;

/**
 * Filter that logs incoming MCP request headers when debug mode is enabled.
 * Useful for diagnosing client connection issues.
 *
 * <p>This filter only logs when {@link ConfigManager#isDebugMode()} returns true,
 * avoiding performance overhead in production.
 */
public class RequestLoggingFilter implements Filter {
    private final ConfigManager configManager;

    /**
     * Creates a new request logging filter.
     *
     * @param configManager The config manager to check debug mode status
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

        // Only log when debug mode is enabled
        if (configManager.isDebugMode()) {
            HttpServletRequest req = (HttpServletRequest) request;

            // Log all headers for debugging
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

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // No cleanup needed
    }
}
