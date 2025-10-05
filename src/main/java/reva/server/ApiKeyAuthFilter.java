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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.util.Msg;

import reva.plugin.ConfigManager;

/**
 * Authentication filter for API key-based access control to the MCP server.
 * Checks for the X-API-Key header when authentication is enabled in configuration.
 */
public class ApiKeyAuthFilter implements Filter {
    private static final String API_KEY_HEADER = "X-API-Key";
    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();

    private final ConfigManager configManager;

    /**
     * Constructor
     * @param configManager The configuration manager to get API key settings from
     */
    public ApiKeyAuthFilter(ConfigManager configManager) {
        this.configManager = configManager;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // No initialization needed
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        // Only process HTTP requests
        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Check if API key authentication is enabled
        if (!configManager.isApiKeyEnabled()) {
            // Authentication disabled - allow all requests
            chain.doFilter(request, response);
            return;
        }

        // Get the API key from the request header
        String providedApiKey = httpRequest.getHeader(API_KEY_HEADER);
        String configuredApiKey = configManager.getApiKey();

        // Validate API key
        if (providedApiKey == null || providedApiKey.trim().isEmpty()) {
            Msg.warn(this, "API key authentication failed: missing X-API-Key header from " +
                     getClientInfo(httpRequest));
            sendUnauthorizedResponse(httpResponse, "Missing X-API-Key header");
            return;
        }

        if (configuredApiKey == null || configuredApiKey.trim().isEmpty()) {
            Msg.error(this, "API key authentication failed: no API key configured in settings");
            sendUnauthorizedResponse(httpResponse, "Server configuration error");
            return;
        }

        if (!providedApiKey.equals(configuredApiKey)) {
            Msg.warn(this, "API key authentication failed: invalid API key from " +
                     getClientInfo(httpRequest));
            sendUnauthorizedResponse(httpResponse, "Invalid API key");
            return;
        }

        // API key is valid - allow the request to continue
        Msg.debug(this, "API key authentication successful for " + getClientInfo(httpRequest));
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // No cleanup needed
    }

    /**
     * Send an HTTP 401 Unauthorized response
     * @param response The HTTP response to modify
     * @param message The error message to include
     * @throws IOException If writing the response fails
     */
    private void sendUnauthorizedResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");

        // Use Jackson to properly serialize JSON and prevent injection
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error", "Unauthorized");
        errorResponse.put("message", message);

        response.getWriter().write(JSON_MAPPER.writeValueAsString(errorResponse));
    }

    /**
     * Get client information for logging
     * @param request The HTTP request
     * @return A string with client IP and user agent
     */
    private String getClientInfo(HttpServletRequest request) {
        String clientIP = null;
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            // X-Forwarded-For can contain multiple IPs, the first is the original client
            clientIP = xForwardedFor.split(",")[0].trim();
        } else {
            String xRealIp = request.getHeader("X-Real-IP");
            if (xRealIp != null && !xRealIp.isEmpty()) {
                clientIP = xRealIp;
            } else {
                clientIP = request.getRemoteAddr();
            }
        }
        String userAgent = request.getHeader("User-Agent");
        return clientIP + (userAgent != null ? " (" + userAgent + ")" : "");
    }
}