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

import reva.server.McpServerManager;
import reva.ui.RevaProvider;
import reva.util.RevaInternalServiceRegistry;

/**
 * ReVa (Reverse Engineering Assistant) plugin for Ghidra.
 * The main plugin class that initializes all components and
 * provides a Model Context Protocol server for interacting with Ghidra.
 */
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "ReVa",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Reverse Engineering Assistant",
    description = "Provides a Model Context Protocol server for interacting with Ghidra"
)
public class RevaPlugin extends ProgramPlugin {
    private RevaProvider provider;
    private McpServerManager serverManager;

    /**
     * Plugin constructor.
     * @param tool The plugin tool that this plugin is added to.
     */
    public RevaPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "ReVa initializing...");

        // Register this plugin in the service registry so components can access it
        RevaInternalServiceRegistry.registerService(RevaPlugin.class, this);

        // Initialize the MCP server (singleton)
        serverManager = McpServerManager.getInstance(tool);
    }

    @Override
    public void init() {
        super.init();

        // Create the UI provider
        provider = new RevaProvider(this, getName());

        // Start the server
        serverManager.startServer();

        Msg.info(this, "ReVa initialization complete");
    }

    @Override
    protected void programOpened(Program program) {
        Msg.info(this, "Program opened: " + program.getName());
        if (serverManager != null) {
            serverManager.programOpened(program);
        }
    }

    @Override
    protected void programClosed(Program program) {
        Msg.info(this, "Program closed: " + program.getName());
        if (serverManager != null) {
            serverManager.programClosed(program);
        }
    }

    @Override
    protected void cleanup() {
        // Clean up all registered services
        if (serverManager != null) {
            serverManager.shutdown();
        }

        // Clean up the service registry
        RevaInternalServiceRegistry.clearAllServices();

        super.cleanup();
    }

    /**
     * Get all currently open programs in any Ghidra tool
     * @return List of open programs
     */
    public List<Program> getOpenPrograms() {
        return RevaProgramManager.getOpenPrograms();
    }
}
