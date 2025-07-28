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
package reva.plugin;

import java.util.List;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import reva.services.RevaMcpService;
import reva.ui.RevaProvider;
import reva.util.RevaInternalServiceRegistry;

/**
 * ReVa (Reverse Engineering Assistant) tool plugin for Ghidra.
 * This tool-level plugin connects to the application-level MCP server
 * and handles program lifecycle events for this specific tool.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "ReVa",
    category = PluginCategoryNames.COMMON,
    shortDescription = "Reverse Engineering Assistant (Tool)",
    description = "Tool-level ReVa plugin that connects to the application-level MCP server"
)
public class RevaPlugin extends ProgramPlugin {
    private RevaProvider provider;
    private RevaMcpService mcpService;

    /**
     * Plugin constructor.
     * @param tool The plugin tool that this plugin is added to.
     */
    public RevaPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "ReVa Tool Plugin initializing...");

        // Register this plugin in the service registry so components can access it
        RevaInternalServiceRegistry.registerService(RevaPlugin.class, this);
    }

    @Override
    public void init() {
        super.init();

        // Get the MCP service from the application plugin
        mcpService = tool.getService(RevaMcpService.class);

        // Fallback for testing environments where ApplicationLevelPlugin isn't available
        if (mcpService == null) {
            mcpService = RevaInternalServiceRegistry.getService(RevaMcpService.class);
        }

        if (mcpService == null) {
            Msg.error(this, "RevaMcpService not available - RevaApplicationPlugin may not be loaded and no fallback service found");
            return;
        }

        // Register this tool with the MCP server
        mcpService.registerTool(tool);

        // TODO: Create the UI provider when needed
        // provider = new RevaProvider(this, getName());
        // tool.addComponentProvider(provider, false);

        Msg.info(this, "ReVa Tool Plugin initialization complete - connected to application-level MCP server");
    }

    @Override
    protected void programOpened(Program program) {
        Msg.info(this, "Program opened: " + program.getName());
        // Notify the program manager to handle cache management
        RevaProgramManager.programOpened(program);

        // Notify the MCP service about the program opening in this tool
        if (mcpService != null) {
            mcpService.programOpened(program, tool);
        }
    }

    @Override
    protected void programClosed(Program program) {
        Msg.info(this, "Program closed: " + program.getName());
        // Notify the program manager to clear stale cache
        RevaProgramManager.programClosed(program);

        // Notify the MCP service about the program closing in this tool
        if (mcpService != null) {
            mcpService.programClosed(program, tool);
        }
    }

    @Override
    protected void cleanup() {
        // Remove the UI provider
        if (provider != null) {
            tool.removeComponentProvider(provider);
        }

        // Unregister this tool from the MCP service
        if (mcpService != null) {
            mcpService.unregisterTool(tool);
        }

        // Only clear tool-specific services, not the application-level ones
        RevaInternalServiceRegistry.unregisterService(RevaPlugin.class);

        super.cleanup();
    }

    /**
     * Get all currently open programs in any Ghidra tool
     * @return List of open programs
     */
    public List<Program> getOpenPrograms() {
        return RevaProgramManager.getOpenPrograms();
    }

    /**
     * Get the MCP service instance
     * @return The MCP service, or null if not available
     */
    public RevaMcpService getMcpService() {
        return mcpService;
    }
}
