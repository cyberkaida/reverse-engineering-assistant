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
package reva.util;

import ghidra.util.Msg;
import reva.plugin.ConfigManager;
import reva.util.RevaInternalServiceRegistry;

/**
 * Debug logger utility that respects the debug configuration setting.
 * Provides specialized logging for connection debugging and performance monitoring.
 */
public class DebugLogger {
    
    private static ConfigManager getConfigManager() {
        return RevaInternalServiceRegistry.getService(ConfigManager.class);
    }
    
    /**
     * Log a debug message if debug mode is enabled
     * @param source The source object for the log message
     * @param message The message to log
     */
    public static void debug(Object source, String message) {
        ConfigManager config = getConfigManager();
        if (config != null && config.isDebugMode()) {
            Msg.info(source, "[DEBUG] " + message);
        }
    }
    
    /**
     * Log a debug message with an exception if debug mode is enabled
     * @param source The source object for the log message
     * @param message The message to log
     * @param throwable The exception to include
     */
    public static void debug(Object source, String message, Throwable throwable) {
        ConfigManager config = getConfigManager();
        if (config != null && config.isDebugMode()) {
            Msg.info(source, "[DEBUG] " + message, throwable);
        }
    }
    
    /**
     * Log a connection-related debug message if debug mode is enabled
     * @param source The source object for the log message
     * @param message The message to log
     */
    public static void debugConnection(Object source, String message) {
        ConfigManager config = getConfigManager();
        if (config != null && config.isDebugMode()) {
            Msg.info(source, "[DEBUG-CONNECTION] " + message);
        }
    }
    
    /**
     * Log a performance-related debug message if debug mode is enabled
     * @param source The source object for the log message
     * @param operation The operation being timed
     * @param durationMs The duration in milliseconds
     */
    public static void debugPerformance(Object source, String operation, long durationMs) {
        ConfigManager config = getConfigManager();
        if (config != null && config.isDebugMode()) {
            Msg.info(source, "[DEBUG-PERF] " + operation + " took " + durationMs + "ms");
        }
    }
    
    /**
     * Log a tool execution debug message if debug mode is enabled
     * @param source The source object for the log message
     * @param toolName The name of the tool being executed
     * @param status The status (START, END, ERROR, etc.)
     * @param details Additional details
     */
    public static void debugToolExecution(Object source, String toolName, String status, String details) {
        ConfigManager config = getConfigManager();
        if (config != null && config.isDebugMode()) {
            String message = "[DEBUG-TOOL] " + toolName + " - " + status;
            if (details != null && !details.isEmpty()) {
                message += ": " + details;
            }
            Msg.info(source, message);
        }
    }
    
    /**
     * Log an MCP request lifecycle event if debug mode is enabled
     * @param source The source object for the log message
     * @param sessionId The MCP session ID
     * @param requestId The request ID (can be null for notifications)
     * @param method The MCP method name
     * @param status The status (START, SUCCESS, ERROR, TIMEOUT, CANCEL)
     * @param durationMs The duration in milliseconds (null for START events)
     * @param details Additional details or error message
     */
    public static void debugMcpRequest(Object source, String sessionId, Object requestId, 
                                      String method, String status, Long durationMs, String details) {
        ConfigManager config = getConfigManager();
        if (config != null && config.isDebugMode()) {
            StringBuilder message = new StringBuilder("[DEBUG-MCP] ");
            message.append("Session:").append(sessionId);
            if (requestId != null) {
                message.append(" Request:").append(requestId);
            }
            message.append(" ").append(method).append(" - ").append(status);
            if (durationMs != null) {
                message.append(" (").append(durationMs).append("ms)");
            }
            if (details != null && !details.isEmpty()) {
                message.append(": ").append(details);
            }
            Msg.info(source, message.toString());
        }
    }
    
    /**
     * Log an MCP request start event
     * @param source The source object for the log message
     * @param sessionId The MCP session ID
     * @param requestId The request ID
     * @param method The MCP method name
     * @param details Additional request details
     */
    public static void debugMcpRequestStart(Object source, String sessionId, Object requestId, 
                                           String method, String details) {
        debugMcpRequest(source, sessionId, requestId, method, "START", null, details);
    }
    
    /**
     * Log an MCP request success event
     * @param source The source object for the log message
     * @param sessionId The MCP session ID
     * @param requestId The request ID
     * @param method The MCP method name
     * @param durationMs The duration in milliseconds
     */
    public static void debugMcpRequestSuccess(Object source, String sessionId, Object requestId, 
                                             String method, long durationMs) {
        debugMcpRequest(source, sessionId, requestId, method, "SUCCESS", durationMs, null);
    }
    
    /**
     * Log an MCP request error event
     * @param source The source object for the log message
     * @param sessionId The MCP session ID
     * @param requestId The request ID
     * @param method The MCP method name
     * @param durationMs The duration in milliseconds
     * @param error The error message
     */
    public static void debugMcpRequestError(Object source, String sessionId, Object requestId, 
                                           String method, long durationMs, String error) {
        debugMcpRequest(source, sessionId, requestId, method, "ERROR", durationMs, error);
    }
    
    /**
     * Log an MCP request timeout event
     * @param source The source object for the log message
     * @param sessionId The MCP session ID
     * @param requestId The request ID
     * @param method The MCP method name
     * @param timeoutMs The timeout duration in milliseconds
     */
    public static void debugMcpRequestTimeout(Object source, String sessionId, Object requestId, 
                                             String method, long timeoutMs) {
        debugMcpRequest(source, sessionId, requestId, method, "TIMEOUT", timeoutMs, 
                       "Request timed out after " + timeoutMs + "ms");
    }
    
    /**
     * Check if debug mode is currently enabled
     * @return true if debug mode is enabled, false otherwise
     */
    public static boolean isDebugEnabled() {
        ConfigManager config = getConfigManager();
        return config != null && config.isDebugMode();
    }
}