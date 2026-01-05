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
package reva.debug;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import ghidra.util.extensions.ExtensionDetails;
import ghidra.util.extensions.ExtensionUtils;

import reva.plugin.ConfigManager;
import reva.plugin.RevaProgramManager;
import reva.server.McpServerManager;
import reva.tools.ToolProvider;
import reva.util.RevaInternalServiceRegistry;

/**
 * Collects debug information from the system, Ghidra, and ReVa for troubleshooting.
 * All collected information is returned as Maps for easy JSON serialization.
 */
public class DebugInfoCollector {

    /**
     * Collect all debug information into a single map.
     * @param userMessage Optional user-provided message describing the issue
     * @return Map containing all collected debug information
     */
    public Map<String, Object> collectAll(String userMessage) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("captureTimestamp", Instant.now().toString());
        info.put("userMessage", userMessage != null ? userMessage : "(No message provided)");
        info.put("system", collectSystemInfo());
        info.put("ghidra", collectGhidraInfo());
        info.put("reva", collectRevaInfo());
        info.put("mcpServer", collectMcpServerInfo());
        info.put("programs", collectOpenPrograms());
        return info;
    }

    /**
     * Collect system information (Java, OS).
     */
    public Map<String, Object> collectSystemInfo() {
        Map<String, Object> system = new LinkedHashMap<>();
        system.put("javaVersion", System.getProperty("java.version"));
        system.put("javaVendor", System.getProperty("java.vendor"));
        system.put("osName", System.getProperty("os.name"));
        system.put("osVersion", System.getProperty("os.version"));
        system.put("osArch", System.getProperty("os.arch"));
        return system;
    }

    /**
     * Collect Ghidra information (version, extensions).
     */
    public Map<String, Object> collectGhidraInfo() {
        Map<String, Object> ghidra = new LinkedHashMap<>();

        try {
            ghidra.put("version", Application.getApplicationVersion());
        } catch (Exception e) {
            ghidra.put("version", "Error: " + e.getMessage());
        }

        // Collect installed extensions
        List<Map<String, Object>> extensions = new ArrayList<>();
        try {
            Set<ExtensionDetails> installedExtensions = ExtensionUtils.getInstalledExtensions();
            for (ExtensionDetails ext : installedExtensions) {
                Map<String, Object> extInfo = new LinkedHashMap<>();
                extInfo.put("name", ext.getName());
                extInfo.put("version", ext.getVersion());
                extInfo.put("author", ext.getAuthor());
                extInfo.put("description", ext.getDescription());
                extensions.add(extInfo);
            }
        } catch (Exception e) {
            Map<String, Object> errorInfo = new LinkedHashMap<>();
            errorInfo.put("error", "Failed to get extensions: " + e.getMessage());
            extensions.add(errorInfo);
        }
        ghidra.put("extensions", extensions);

        return ghidra;
    }

    /**
     * Collect ReVa configuration and status.
     */
    public Map<String, Object> collectRevaInfo() {
        Map<String, Object> reva = new LinkedHashMap<>();
        reva.put("version", getRevaVersion());

        // Get configuration
        ConfigManager config = RevaInternalServiceRegistry.getService(ConfigManager.class);
        if (config != null) {
            Map<String, Object> configInfo = new LinkedHashMap<>();
            configInfo.put("serverEnabled", config.isServerEnabled());
            configInfo.put("serverPort", config.getServerPort());
            configInfo.put("serverHost", config.getServerHost());
            configInfo.put("debugMode", config.isDebugMode());
            configInfo.put("apiKeyEnabled", config.isApiKeyEnabled());
            configInfo.put("decompilerTimeoutSeconds", config.getDecompilerTimeoutSeconds());
            configInfo.put("maxDecompilerSearchFunctions", config.getMaxDecompilerSearchFunctions());
            reva.put("config", configInfo);
        } else {
            reva.put("config", "ConfigManager not available");
        }

        return reva;
    }

    /**
     * Collect MCP server status and registered tools.
     */
    public Map<String, Object> collectMcpServerInfo() {
        Map<String, Object> mcpServer = new LinkedHashMap<>();

        McpServerManager serverManager = RevaInternalServiceRegistry.getService(McpServerManager.class);
        if (serverManager != null) {
            mcpServer.put("running", serverManager.isServerRunning());
            mcpServer.put("port", serverManager.getServerPort());
            mcpServer.put("host", serverManager.getServerHost());
            mcpServer.put("headlessMode", serverManager.isHeadlessMode());

            // Get registered tool provider names
            List<String> toolProviderNames = new ArrayList<>();
            List<ToolProvider> toolProviders = serverManager.getToolProviders();
            if (toolProviders != null) {
                for (ToolProvider provider : toolProviders) {
                    toolProviderNames.add(provider.getClass().getSimpleName());
                }
            }
            mcpServer.put("toolProviders", toolProviderNames);

            // Get registered PluginTools count
            mcpServer.put("registeredToolsCount", serverManager.getRegisteredToolsCount());
        } else {
            mcpServer.put("error", "McpServerManager not available");
        }

        return mcpServer;
    }

    /**
     * Collect information about open programs.
     */
    public List<Map<String, Object>> collectOpenPrograms() {
        List<Map<String, Object>> programs = new ArrayList<>();

        try {
            for (Program program : RevaProgramManager.getOpenPrograms()) {
                Map<String, Object> progInfo = new LinkedHashMap<>();
                progInfo.put("path", program.getDomainFile().getPathname());
                progInfo.put("name", program.getName());
                progInfo.put("language", program.getLanguage().getLanguageID().getIdAsString());
                progInfo.put("compilerSpec", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
                progInfo.put("functionCount", program.getFunctionManager().getFunctionCount());
                progInfo.put("symbolCount", program.getSymbolTable().getNumSymbols());
                programs.add(progInfo);
            }
        } catch (Exception e) {
            Map<String, Object> errorInfo = new LinkedHashMap<>();
            errorInfo.put("error", "Failed to get programs: " + e.getMessage());
            programs.add(errorInfo);
        }

        return programs;
    }

    /**
     * Get the ReVa extension version from the installed extension metadata.
     * Falls back to "dev" if the extension is not found (e.g., running from source).
     */
    private String getRevaVersion() {
        try {
            Set<ExtensionDetails> installedExtensions = ExtensionUtils.getInstalledExtensions();
            for (ExtensionDetails ext : installedExtensions) {
                if ("ReVa".equals(ext.getName())) {
                    String version = ext.getVersion();
                    // Return version if available and not the placeholder
                    if (version != null && !version.isEmpty() && !version.contains("@")) {
                        return version;
                    }
                }
            }
        } catch (Exception e) {
            // Fall through to default
        }
        return "dev";
    }
}
