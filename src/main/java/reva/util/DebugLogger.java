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
     * Check if debug mode is currently enabled
     * @return true if debug mode is enabled, false otherwise
     */
    public static boolean isDebugEnabled() {
        ConfigManager config = getConfigManager();
        return config != null && config.isDebugMode();
    }
}