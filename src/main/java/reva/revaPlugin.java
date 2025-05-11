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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.*;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import generic.concurrent.GThreadPool;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

import io.modelcontextprotocol.server.*;
import io.modelcontextprotocol.server.transport.*;
import io.modelcontextprotocol.spec.*;
import io.modelcontextprotocol.spec.McpSchema.Content;
import io.modelcontextprotocol.spec.McpSchema.ReadResourceResult;
import io.modelcontextprotocol.spec.McpSchema.Resource;
import io.modelcontextprotocol.spec.McpSchema.ResourceContents;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.TextResourceContents;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;

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
	private static Server httpServer;
	private static final GThreadPool threadPool;

	static {
		// Debugging!
		// npx @modelcontextprotocol/inspector
		// Then connect to the server on http://localhost:8080/mcp/sse

		threadPool = GThreadPool.getPrivateThreadPool("ReVa");

		McpSchema.ServerCapabilities serverCapabilities = McpSchema.ServerCapabilities.builder()
			.prompts(true)
			.resources(true, true)
			.tools(true)
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

		// MARK: Add resources and tools
		addResourceProgramList();
		// Add the get-strings tool
		addToolGetStrings();
		// Add the list-programs tool
		addToolListPrograms();

		// Run the transport provider in a runnable using the thread pool
		startHosting(transportProvider);

		// Register the base level resources
		// These will be the open programs, the client can request
		// resources from these programs

	}

	static void startHosting(HttpServletSseServerTransportProvider transportProvider) {
		assert server != null;
		assert transportProvider != null;
		assert threadPool != null;

		ServletContextHandler servletContextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
		servletContextHandler.setContextPath("/");
		ServletHolder servletHolder = new ServletHolder(transportProvider);
		servletContextHandler.addServlet(servletHolder, "/*");

		httpServer = new Server(8080); // TODO: Configure port with Ghidra Option
		httpServer.setHandler(servletContextHandler);

		threadPool.submit(() -> {
			try {
				Msg.info(revaPlugin.class, "MCP server starting on port 8080");
				httpServer.start();
				Msg.info(revaPlugin.class, "MCP server started on port 8080");
				httpServer.join();
				Msg.warn(revaPlugin.class, "MCP server stopped");
			}
			catch (Exception e) {
				Msg.error(revaPlugin.class, "Error starting MCP server", e);
			}
		});
	}

	static void addResourceProgramList() {
		assert server != null;
		McpServerFeatures.SyncResourceSpecification resourceSpecification =
		new McpServerFeatures.SyncResourceSpecification(
			new Resource("ghidra://programs", "open-programs", "Currently open programs", "text/plain", null),
			(exchange, request) -> {
				List<ResourceContents> resourceContents = new ArrayList<>();
				for (Program program : programs) {

					// TODO: Output JSON
					String metaString = program.getMetadata().toString();

					resourceContents.add(
						new TextResourceContents(
							"ghidra://programs/" + program.getName(),
							"text/plain",
							metaString
						)
					);
				}
				return new ReadResourceResult(
					resourceContents
				);
			}
		);
		server.addResource(resourceSpecification);
	}

	/***
	 * Get strings from the selected program
	 */
	static void addToolGetStrings() {
		assert server != null;

		// Create a JSON schema for the tool that requires a programPath parameter


		JsonSchema schema = new JsonSchema(
			"object",
			Map.of(
				"programPath", Map.of(
					"type", "string",
					"description", "Path in the Ghidra Project to the program to get strings from"
				)
			),
			List.of("programPath"),
			false
		);

		McpSchema.Tool tool = new McpSchema.Tool(
			"get-strings",
			"Get strings from the selected program",
			schema
		);

		McpServerFeatures.SyncToolSpecification toolSpecification =
			new McpServerFeatures.SyncToolSpecification(
				tool,
				(exchange, args) -> {
					// Get the program path from the request
					String programPath = (String) args.get("programPath");
					if (programPath == null) {
						return new McpSchema.CallToolResult(
							List.of(new TextContent("No program path provided")),
							true
						);
					}
					// Get the program from the path
					Program program = programs.stream()
						.filter(p -> p.getDomainFile().getPathname().equals(programPath))
						.findFirst()
						.orElse(null);
					if (program == null) {
						return new McpSchema.CallToolResult(List.of(new TextContent("Failed to find Program")), true);
					}

					// Get the defined strings from the program
					List<Map<String, Object>> stringData = new ArrayList<>();
					FlatProgramAPI flatProgramAPI = new FlatProgramAPI(program);
					program.getListing().getDefinedData(true)
						.forEach(data -> {
							if (data.getValue() instanceof String) {
								Msg.debug(revaPlugin.class, "Found string: " + data.getValue());
								String stringValue = (String) data.getValue();

								Map<String, Object> stringInfo = new HashMap<String, Object>();
								stringInfo.put("address", "0x" + data.getAddress().toString()); // TODO: Probably contains namespace
								stringInfo.put("content", stringValue);
								stringInfo.put("length", stringValue.length());

								byte[] bytes = null;;
								try {
									bytes = data.getBytes();
								} catch (MemoryAccessException e) {
									bytes = null;
								}

								if (bytes != null) {
									// Convert bytes to hex string
									StringBuilder hexString = new StringBuilder();
									for (byte b : bytes) {
										hexString.append(String.format("%02x", b & 0xff));
									}
									stringInfo.put("bytes", hexString.toString());
								}
								stringData.add(stringInfo);
							}
						});

					try {
						List<Content> contents = new ArrayList<>();
						for (Map<String, Object> stringInfo : stringData) {
							contents.add(new TextContent(JSON.writeValueAsString(stringInfo)));
						}
						return new McpSchema.CallToolResult(contents, false);
					}
					catch (Exception e) {
						Msg.error(revaPlugin.class, "Error converting string data to JSON", e);
						return new McpSchema.CallToolResult(
							List.of(new TextContent("Error converting string data to JSON: " + e.getMessage())),
							true
						);
					}
				}
			);

		server.addTool(toolSpecification);
		Msg.info(revaPlugin.class, "Added get-strings tool to MCP server");
	}

	/***
	 * List all currently open programs with their paths
	 */
	static void addToolListPrograms() {
		assert server != null;

		// No parameters needed for this tool
		JsonSchema schema = new JsonSchema(
			"object",
			Map.of(),
			List.of(),
			false
		);

		McpSchema.Tool tool = new McpSchema.Tool(
			"list-programs",
			"List all currently open programs in Ghidra",
			schema
		);

		McpServerFeatures.SyncToolSpecification toolSpecification =
			new McpServerFeatures.SyncToolSpecification(
				tool,
				(exchange, args) -> {
					List<Map<String, Object>> programsData = new ArrayList<>();
					for (Program program : programs) {
						Map<String, Object> programInfo = Map.of(
							"name", program.getName(),
							"path", program.getDomainFile().getPathname(),
							"language", program.getLanguage().toString(),
							"creationDate", program.getCreationDate().toString()
						);
						programsData.add(programInfo);
					}

					try {
						List<Content> contents = new ArrayList<>();
						if (programsData.isEmpty()) {
							contents.add(new TextContent("No programs are currently open"));
						} else {
							for (Map<String, Object> programInfo : programsData) {
								contents.add(new TextContent(JSON.writeValueAsString(programInfo)));
							}
						}
						return new McpSchema.CallToolResult(contents, false);
					}
					catch (Exception e) {
						Msg.error(revaPlugin.class, "Error converting program data to JSON", e);
						return new McpSchema.CallToolResult(
							List.of(new TextContent("Error converting program data to JSON: " + e.getMessage())),
							true
						);
					}
				}
			);

		server.addTool(toolSpecification);
		Msg.info(revaPlugin.class, "Added list-programs tool to MCP server");
	}

	@Override
	protected void programOpened(Program program) {
		if (!programs.contains(program)) {
			Msg.info(this, "Registering program: " + program.getName());
			programs.add(program);
		}
		super.programOpened(program);
	}

	@Override
	protected void programClosed(Program program) {
		programs.remove(program);
		Msg.info(this, "Unregistering program: " + program.getName());
		super.programClosed(program);
	}


	private Boolean addedListProjectFiles = false;
	/***
	 * List all files in the project
	 */
	private void addToolListProjectFiles() {
		// Note: This tool should be added to the MCP
		// server in the default constructor. It will
		// need access to the project.
		assert server != null;
		if (addedListProjectFiles) {
			// This should not be added twice
			Msg.warn(this, "Tool already added");
			return;
		}
		addedListProjectFiles = true;

		// Get the project from the tool
		Project project = tool.getProject();
		if (project == null) {
			Msg.warn(this, "No project is currently open");
			return;
		}

		// No parameters needed for this tool
		JsonSchema schema = new JsonSchema(
			"object",
			Map.of(),
			List.of(),
			false
		);

		McpSchema.Tool tool = new McpSchema.Tool(
			"list-project-files",
			"List all files/programs in the current Ghidra project",
			schema
		);

		McpServerFeatures.SyncToolSpecification toolSpecification =
			new McpServerFeatures.SyncToolSpecification(
				tool,
				(exchange, args) -> {
					// Get the project again when the tool is called
					Project currentProject = this.tool.getProject();
					if (currentProject == null) {
						return new McpSchema.CallToolResult(
							List.of(new TextContent("No project is currently open")),
							true
						);
					}

					List<Map<String, Object>> filesData = new ArrayList<>();

					// Recursively collect all domain files in the project
					collectDomainFiles(currentProject.getProjectData().getRootFolder(), "", filesData);

					try {
						List<Content> contents = new ArrayList<>();
						if (filesData.isEmpty()) {
							contents.add(new TextContent("No files found in the project"));
						} else {
							for (Map<String, Object> fileInfo : filesData) {
								contents.add(new TextContent(JSON.writeValueAsString(fileInfo)));
							}
						}
						return new McpSchema.CallToolResult(contents, false);
					}
					catch (Exception e) {
						Msg.error(this, "Error converting project files data to JSON", e);
						return new McpSchema.CallToolResult(
							List.of(new TextContent("Error converting project files data to JSON: " + e.getMessage())),
							true
						);
					}
				}
			);

		server.addTool(toolSpecification);
		server.notifyToolsListChanged();
		Msg.info(this, "Added list-project-files tool to MCP server");
	}

	/**
	 * Helper method to recursively collect domain files from project folders
	 *
	 * @param folder The folder to collect domain files from
	 * @param path The current path in the project
	 * @param filesData The list to store file information in
	 */
	private void collectDomainFiles(ghidra.framework.model.DomainFolder folder, String path, List<Map<String, Object>> filesData) {
		if (folder == null) return;

		// Process all files in this folder
		for (ghidra.framework.model.DomainFile file : folder.getFiles()) {
			String filePath = path.isEmpty() ? file.getName() : path + "/" + file.getName();
			Map<String, Object> fileInfo = Map.of(
				"name", file.getName(),
				"path", filePath,
				"contentType", file.getContentType(),
				"isVersioned", file.isVersioned() ? "true" : "false"
			);
			filesData.add(fileInfo);
		}

		// Process all subfolders recursively
		for (ghidra.framework.model.DomainFolder subFolder : folder.getFolders()) {
			String newPath = path.isEmpty() ? subFolder.getName() : path + "/" + subFolder.getName();
			collectDomainFiles(subFolder, newPath, filesData);
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
	protected void cleanup() {
		// Clean up our thread pool
		server.closeGracefully();
		threadPool.shutdownNow();
		super.cleanup();
	}

	@Override
	public void init() {
		super.init();
		// Acquire services if necessary

		// Register the list-project-files tool
		addToolListProjectFiles();
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
