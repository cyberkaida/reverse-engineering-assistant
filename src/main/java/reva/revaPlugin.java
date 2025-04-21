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
package reva;

import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import com.fasterxml.jackson.databind.ObjectMapper;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

import io.modelcontextprotocol.server.*;
import io.modelcontextprotocol.server.transport.*;
import io.modelcontextprotocol.spec.*;;

/**
 * Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "ReVa",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class revaPlugin extends ProgramPlugin {
	private static final ObjectMapper JSON = new ObjectMapper();
	// TODO: Why do we define these?
	private static final String MCP_MSG_ENDPOINT = "/mcp/message";
	private static final String MCP_SSE_ENDPOINT = "/mcp/sse";
	// TODO: Get these from plugin properties
	private static final String MCP_SERVER_NAME = "ReVa";
	private static final String MCP_SERVER_VERSION = "1.0.0";

	private static List<Program> programs = new ArrayList<Program>();

	MyProvider provider;

	private static McpSyncServer server;

	static {

		McpSchema.ServerCapabilities serverCapabilities = McpSchema.ServerCapabilities.builder()
			.prompts(true)
			.resources(true, true)
			.resources(true, true)
			.build();

		HttpServletSseServerTransportProvider transportProvider = new HttpServletSseServerTransportProvider(
			JSON, MCP_MSG_ENDPOINT, MCP_SSE_ENDPOINT);
		// Construct a model context protocol server
		// https://modelcontextprotocol.io/sdk/java/mcp-server
		// https://github.com/codeboyzhou/mcp-java-sdk-examples/blob/main/mcp-server-filesystem/filesystem-native-sdk-example/src/main/java/com/github/mcp/examples/server/filesystem/McpSseServer.java

		server = McpServer.sync(transportProvider)
			.serverInfo(MCP_SERVER_NAME, MCP_SERVER_VERSION)
			.capabilities(serverCapabilities)
			.build();

		// Use a ghidra.framework.cmd.BackgroundCommand to run the server in
		// the background. Stop the BackgroundCommand whe the plugin is closed.
	}

	@Override
	protected void programOpened(Program program) {
		super.programOpened(program);
	}

	@Override
	protected void programClosed(Program program) {
		programs.remove(program);
		super.programClosed(program);
		if (programs.size() == 0) {
			server.closeGracefully();
		}
	}

	/**
	 * Plugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public revaPlugin(PluginTool tool) {
		super(tool);

		// Start the MCP server for this tool

		// Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName);

		// Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();

		// Acquire services if necessary
	}

	// If provider is desired, it is recommended to move it to its own file
	private static class MyProvider extends ComponentProvider {

		private JPanel panel;
		private DockingAction action;

		public MyProvider(Plugin plugin, String owner) {
			super(plugin.getTool(), "reva Provider", owner);
			buildPanel();
			createActions();
		}

		// Customize GUI
		private void buildPanel() {
			panel = new JPanel(new BorderLayout());
			JTextArea textArea = new JTextArea(5, 25);
			textArea.setEditable(false);
			panel.add(new JScrollPane(textArea));
			setVisible(true);
		}

		// Customize actions
		private void createActions() {
			action = new DockingAction("My Action", getOwner()) {
				@Override
				public void actionPerformed(ActionContext context) {
					Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
				}
			};
			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			dockingTool.addLocalAction(this, action);
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}
