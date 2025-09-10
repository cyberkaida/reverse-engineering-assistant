package reva.server;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import reva.plugin.ConfigManager;

/**
 * Simple API key authentication filter for the MCP server.
 */
public class ApiKeyAuthFilter implements Filter {

    public static final String API_KEY_HEADER = "X-API-Key";

    private final ConfigManager configManager;

    public ApiKeyAuthFilter(ConfigManager configManager) {
        this.configManager = configManager;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // no-op
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String expectedKey = configManager.getServerApiKey();
        if (expectedKey == null || expectedKey.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String providedKey = httpRequest.getHeader(API_KEY_HEADER);

        if (expectedKey.equals(providedKey)) {
            chain.doFilter(request, response);
        } else {
            httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    @Override
    public void destroy() {
        // no-op
    }
}
