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
import java.io.IOException;
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
import ghidra.app.plugin.core.progmgr.ProgramLocator;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.task.ProgramOpener;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
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
 * ReVa (Reverse Engineering Assistant) plugin for Ghidra.
 * Provides a Model Context Protocol server for interacting with Ghidra.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "ReVa",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Reverse Engineering Assistant",
	description = "Provides a Model Context Protocol server for interacting with Ghidra"
)
//@formatter:on
public class revaPlugin extends ProgramPlugin {
	private static final ObjectMapper JSON = new ObjectMapper();
	private static final String MCP_MSG_ENDPOINT = "/mcp/message";
	private static final String MCP_SSE_ENDPOINT = "/mcp/sse";
	private static final String MCP_SERVER_NAME = "ReVa";
	private static final String MCP_SERVER_VERSION = "1.0.0";

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

				// Get programs directly from the plugin tool
				List<Program> openPrograms = getOpenPrograms();
				for (Program program : openPrograms) {
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

	/**
	 * Get all currently open programs in any Ghidra tool
	 * @return List of open programs
	 */
	private static List<Program> getOpenPrograms() {
		List<Program> openPrograms = new ArrayList<>();

		// Get all tools from the tool manager
		ToolManager toolManager = AppInfo.getActiveProject().getToolManager();
		if (toolManager != null) {
			for (PluginTool pluginTool : toolManager.getRunningTools()) {
				// Get program manager service from each tool
				ProgramManager programManager = pluginTool.getService(ProgramManager.class);
				if (programManager != null) {
					// Get all open programs in the program manager
					for (Program program : programManager.getAllOpenPrograms()) {
						if (program != null && !openPrograms.contains(program)) {
							openPrograms.add(program);
						}
					}
				}
			}
		}

		return openPrograms;
	}

	/**
	 * Get a program by its path
	 * @param programPath Path to the program
	 * @return Program object or null if not found
	 */
	private static Program getProgramByPath(String programPath) {
		List<Program> openPrograms = getOpenPrograms();

		// First try to find among open programs
		for (Program program : openPrograms) {
			if (program.getDomainFile().getPathname().equals(programPath)) {
				return program;
			}
		}

		// Get the DomainFile for the program path
		Project project = AppInfo.getActiveProject();
		if (project == null) {
			Msg.error(revaPlugin.class, "No project is currently open");
			return null;
		}

		DomainFile domainFile = project.getProjectData().getRootFolder().getFile(programPath);
		if (domainFile == null) {
			Msg.error(revaPlugin.class, "Failed to find program: " + programPath);
			return null;
		}

		// TODO: Tie the lifetime to a better object.
		// TODO: This is a leak
		ProgramOpener programOpener = new ProgramOpener(revaPlugin.class);
		ProgramLocator locator = new ProgramLocator(domainFile);
		Program program = programOpener.openProgram(locator, TaskMonitor.DUMMY);
		return program;
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
					Program program = getProgramByPath(programPath);
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
		try {
			server.addTool(toolSpecification);
		} catch (McpError e) {
			// This can happen when the tool is already added
			Msg.error(revaPlugin.class, "Error adding tool to MCP server", e);
			return;
		}
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
			"list-open-files",
			"List all currently open programs in Ghidra",
			schema
		);

		McpServerFeatures.SyncToolSpecification toolSpecification =
			new McpServerFeatures.SyncToolSpecification(
				tool,
				(exchange, args) -> {
					List<Map<String, Object>> programsData = new ArrayList<>();
					List<Program> openPrograms = getOpenPrograms();

					for (Program program : openPrograms) {
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

		try {
			server.addTool(toolSpecification);
		} catch (McpError e) {
			// This can happen when the tool is already added
			Msg.error(revaPlugin.class, "Error adding tool to MCP server", e);
			return;
		}
		Msg.info(revaPlugin.class, "Added list-open-files tool to MCP server");
	}

	/***
	 * List functions from the selected program
	 */
	static void addToolListFunctions() {
		assert server != null;

		// Create a JSON schema for the tool that requires a programPath parameter
		JsonSchema schema = new JsonSchema(
			"object",
			Map.of(
				"programPath", Map.of(
					"type", "string",
					"description", "Path in the Ghidra Project to the program to get functions from"
				)
			),
			List.of("programPath"),
			false
		);

		McpSchema.Tool tool = new McpSchema.Tool(
			"get-functions",
			"Get functions from the selected program",
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
					Program program = getProgramByPath(programPath);
					if (program == null) {
						return new McpSchema.CallToolResult(List.of(new TextContent("Failed to find Program")), true);
					}

					// Get the functions from the program
					List<Map<String, Object>> functionData = new ArrayList<>();
					FlatProgramAPI flatProgramAPI = new FlatProgramAPI(program);

					// Iterate through all functions
					program.getFunctionManager().getFunctions(true).forEach(function -> {
						Map<String, Object> functionInfo = new HashMap<String, Object>();
						functionInfo.put("name", function.getName());
						functionInfo.put("address", "0x" + function.getEntryPoint().toString());

						// Get the function's body to determine the end address and size
						ghidra.program.model.address.AddressSetView body = function.getBody();
						ghidra.program.model.address.Address startAddr = function.getEntryPoint();
						ghidra.program.model.address.Address endAddr = body.getMaxAddress();

						// Add end address and calculate size
						functionInfo.put("endAddress", endAddr != null ? "0x" + endAddr.toString() : "unknown");

						// Calculate size in bytes if both addresses are available
						if (startAddr != null && endAddr != null) {
							// Use offset to calculate size in bytes, add 1 because ranges are inclusive
							long sizeInBytes = endAddr.getOffset() - startAddr.getOffset() + 1;
							functionInfo.put("sizeInBytes", sizeInBytes);
						} else {
							functionInfo.put("sizeInBytes", 0);
						}

						functionInfo.put("signature", function.getSignature().toString());
						functionInfo.put("returnType", function.getReturnType().toString());
						functionInfo.put("isExternal", function.isExternal());
						functionInfo.put("isThunk", function.isThunk());
						functionInfo.put("bodySize", function.getBody().getNumAddresses());

						// Add parameters info
						List<Map<String, String>> parameters = new ArrayList<>();
						for (int i = 0; i < function.getParameterCount(); i++) {
							Map<String, String> paramInfo = new HashMap<>();
							paramInfo.put("name", function.getParameter(i).getName());
							paramInfo.put("dataType", function.getParameter(i).getDataType().toString());
							parameters.add(paramInfo);
						}
						functionInfo.put("parameters", parameters);

						functionData.add(functionInfo);
					});

					try {
						List<Content> contents = new ArrayList<>();
						for (Map<String, Object> functionInfo : functionData) {
							contents.add(new TextContent(JSON.writeValueAsString(functionInfo)));
						}
						return new McpSchema.CallToolResult(contents, false);
					}
					catch (Exception e) {
						Msg.error(revaPlugin.class, "Error converting function data to JSON", e);
						return new McpSchema.CallToolResult(
							List.of(new TextContent("Error converting function data to JSON: " + e.getMessage())),
							true
						);
					}
				}
			);
		try {
			server.addTool(toolSpecification);
		} catch (McpError e) {
			// This can happen when the tool is already added
			Msg.error(revaPlugin.class, "Error adding tool to MCP server", e);
			return;
		}
		Msg.info(revaPlugin.class, "Added get-functions tool to MCP server");
	}

	/***
	 * Get data at a specific address in a program
	 */
	static void addToolGetDataAtAddress() {
		assert server != null;

		// Create a JSON schema for the tool that requires programPath and address parameters
		JsonSchema schema = new JsonSchema(
			"object",
			Map.of(
				"programPath", Map.of(
					"type", "string",
					"description", "Path in the Ghidra Project to the program containing the data"
				),
				"address", Map.of(
					"type", "string",
					"description", "Address to get data from (e.g., '0x00400000')"
				)
			),
			List.of("programPath", "address"),
			false
		);

		McpSchema.Tool tool = new McpSchema.Tool(
			"get-data-at-address",
			"Get data at a specific address in a program",
			schema
		);

		McpServerFeatures.SyncToolSpecification toolSpecification =
			new McpServerFeatures.SyncToolSpecification(
				tool,
				(exchange, args) -> {
					// Get the program path and address from the request
					String programPath = (String) args.get("programPath");
					String addressString = (String) args.get("address");

					if (programPath == null) {
						return new McpSchema.CallToolResult(
							List.of(new TextContent("No program path provided")),
							true
						);
					}

					if (addressString == null) {
						return new McpSchema.CallToolResult(
							List.of(new TextContent("No address provided")),
							true
						);
					}

					// Get the program from the path
					Program program = getProgramByPath(programPath);
					if (program == null) {
						return new McpSchema.CallToolResult(
							List.of(new TextContent("Failed to find program: " + programPath)),
							true
						);
					}

					// Parse the address string
					ghidra.program.model.address.Address address;
					try {
						// Handle hex addresses with or without 0x prefix
						if (addressString.toLowerCase().startsWith("0x")) {
							addressString = addressString.substring(2);
						}
						address = program.getAddressFactory().getDefaultAddressSpace().getAddress(
							Long.parseUnsignedLong(addressString, 16));
					} catch (Exception e) {
						return new McpSchema.CallToolResult(
							List.of(new TextContent("Invalid address format: " + addressString +
								". Use hexadecimal format like '0x00400000'")),
							true
						);
					}

					// Get the listing
					ghidra.program.model.listing.Listing listing = program.getListing();

					// Get data at the address
					ghidra.program.model.listing.Data data = listing.getDataContaining(address);
					if (data == null) {
						return new McpSchema.CallToolResult(
							List.of(new TextContent("No data found at address: " + addressString)),
							true
						);
					}

					// Create result data
					Map<String, Object> resultData = new HashMap<>();
					resultData.put("address", "0x" + data.getAddress().toString());
					resultData.put("dataType", data.getDataType().getName());
					resultData.put("length", data.getLength());

					// Get the bytes and convert to hex
					StringBuilder hexString = new StringBuilder();
					try {
						byte[] bytes = data.getBytes();
						for (byte b : bytes) {
							hexString.append(String.format("%02x", b & 0xff));
						}
						resultData.put("hexBytes", hexString.toString());
					} catch (MemoryAccessException e) {
						resultData.put("hexBytesError", "Memory access error: " + e.getMessage());
					}

					// Get the string representation that would be shown in the listing
					String representation = data.getDefaultValueRepresentation();
					resultData.put("representation", representation);

					// Get the value object
					Object value = data.getValue();
					if (value != null) {
						resultData.put("valueType", value.getClass().getSimpleName());
						resultData.put("value", value.toString());
					} else {
						resultData.put("value", null);
					}

					try {
						List<Content> contents = new ArrayList<>();
						contents.add(new TextContent(JSON.writeValueAsString(resultData)));
						return new McpSchema.CallToolResult(contents, false);
					} catch (Exception e) {
						Msg.error(revaPlugin.class, "Error converting data to JSON", e);
						return new McpSchema.CallToolResult(
							List.of(new TextContent("Error converting data to JSON: " + e.getMessage())),
							true
						);
					}
				}
			);

		try {
			server.addTool(toolSpecification);
		} catch (McpError e) {
			// This can happen when the tool is already added
			Msg.error(revaPlugin.class, "Error adding tool to MCP server", e);
			return;
		}
		Msg.info(revaPlugin.class, "Added get-data-at-address tool to MCP server");
	}

	/***
	 * Get decompiled and disassembled code for a function
	 */
	static void addToolGetDecompiledFunction() {
		assert server != null;

		// Create a JSON schema for the tool that requires programPath and functionName parameters
		JsonSchema schema = new JsonSchema(
			"object",
			Map.of(
				"programPath", Map.of(
					"type", "string",
					"description", "Path in the Ghidra Project to the program containing the function"
				),
				"functionName", Map.of(
					"type", "string",
					"description", "Name of the function to decompile"
				)
			),
			List.of("programPath", "functionName"),
			false
		);

		McpSchema.Tool tool = new McpSchema.Tool(
			"get-decompiled-function",
			"Get decompiled and disassembled code for a function",
			schema
		);

		McpServerFeatures.SyncToolSpecification toolSpecification =
			new McpServerFeatures.SyncToolSpecification(
				tool,
				(exchange, args) -> {
					// Get the program path and function name from the request
					String programPath = (String) args.get("programPath");
					String functionName = (String) args.get("functionName");

					if (programPath == null) {
						return new McpSchema.CallToolResult(
							List.of(new TextContent("No program path provided")),
							true
						);
					}

					if (functionName == null) {
						return new McpSchema.CallToolResult(
							List.of(new TextContent("No function name provided")),
							true
						);
					}

					// Get the program from the path
					Program program = getProgramByPath(programPath);
					if (program == null) {
						return new McpSchema.CallToolResult(
							List.of(new TextContent("Failed to find program: " + programPath)),
							true
						);
					}

					Map<String, Object> resultData = new HashMap<>();
					resultData.put("programName", program.getName());
					resultData.put("functionName", functionName);

					// Get the function by name
					ghidra.program.model.listing.FunctionManager functionManager = program.getFunctionManager();
					ghidra.program.model.listing.Function function = null;

					// First try an exact match
					ghidra.program.model.listing.FunctionIterator functions = functionManager.getFunctions(true);
					while (functions.hasNext()) {
						ghidra.program.model.listing.Function f = functions.next();
						if (f.getName().equals(functionName)) {
							function = f;
							break;
						}
					}

					// If no exact match, try case-insensitive
					if (function == null) {
						functions = functionManager.getFunctions(true);
						while (functions.hasNext()) {
							ghidra.program.model.listing.Function f = functions.next();
							if (f.getName().equalsIgnoreCase(functionName)) {
								function = f;
								break;
							}
						}
					}

					if (function == null) {
						return new McpSchema.CallToolResult(
							List.of(new TextContent("Function not found: " + functionName + " in program " + program.getName())),
							true
						);
					}

					// Add function details
					resultData.put("address", "0x" + function.getEntryPoint().toString());

					// Get function metadata
					Map<String, String> metadata = new HashMap<>();
					metadata.put("signature", function.getSignature().toString());
					metadata.put("returnType", function.getReturnType().toString());
					metadata.put("callingConvention", function.getCallingConventionName());
					metadata.put("isExternal", Boolean.toString(function.isExternal()));
					metadata.put("isThunk", Boolean.toString(function.isThunk()));

					// Get parameters info
					List<Map<String, String>> parameters = new ArrayList<>();
					for (int i = 0; i < function.getParameterCount(); i++) {
						Map<String, String> paramInfo = new HashMap<>();
						paramInfo.put("name", function.getParameter(i).getName());
						paramInfo.put("dataType", function.getParameter(i).getDataType().toString());
						paramInfo.put("ordinal", Integer.toString(i));
						parameters.add(paramInfo);
					}
					metadata.put("parameterCount", Integer.toString(function.getParameterCount()));
					resultData.put("metadata", metadata);
					resultData.put("parameters", parameters);

					// Get function bounds
					ghidra.program.model.address.AddressSetView body = function.getBody();
					resultData.put("startAddress", "0x" + function.getEntryPoint().toString());
					resultData.put("endAddress", "0x" + body.getMaxAddress().toString());
					resultData.put("sizeInBytes", body.getNumAddresses());

					// Get disassembly
					StringBuilder disassembly = new StringBuilder();
					ghidra.program.model.listing.Listing listing = program.getListing();
					ghidra.program.model.listing.InstructionIterator instructions =
						listing.getInstructions(body, true);

					while (instructions.hasNext()) {
						ghidra.program.model.listing.Instruction instruction = instructions.next();
						disassembly.append("0x").append(instruction.getAddress()).append(": ");
						disassembly.append(instruction.toString()).append("\n");
					}
					resultData.put("disassembly", disassembly.toString());

					// Get decompilation using DecompInterface
					try {
						ghidra.app.decompiler.DecompInterface decompiler = new ghidra.app.decompiler.DecompInterface();
						decompiler.toggleCCode(true);
						decompiler.toggleSyntaxTree(true);
						decompiler.setSimplificationStyle("decompile");

						// Initialize and open the decompiler on the current program
						boolean decompInitialized = decompiler.openProgram(program);
						if (!decompInitialized) {
							resultData.put("decompilationError", "Failed to initialize decompiler");
							resultData.put("decompilation", "");
						} else {
							// Decompile the function
							ghidra.app.decompiler.DecompileResults decompileResults =
								decompiler.decompileFunction(function, 0, TaskMonitor.DUMMY);

							if (decompileResults.decompileCompleted()) {
								// Get the decompiled code as C
								ghidra.app.decompiler.DecompiledFunction decompiledFunction =
									decompileResults.getDecompiledFunction();
								String decompCode = decompiledFunction.getC();
								resultData.put("decompilation", decompCode);

								 // Get additional details like high-level function signature
								resultData.put("decompSignature", decompiledFunction.getSignature());
							} else {
								resultData.put("decompilationError", "Decompilation failed: " +
									decompileResults.getErrorMessage());
								resultData.put("decompilation", "");
							}

							// Clean up
							decompiler.dispose();
						}
					} catch (Exception e) {
						Msg.error(revaPlugin.class, "Error during decompilation", e);
						resultData.put("decompilationError", "Exception during decompilation: " + e.getMessage());
						resultData.put("decompilation", "");
					}

					try {
						List<Content> contents = new ArrayList<>();
						contents.add(new TextContent(JSON.writeValueAsString(resultData)));
						return new McpSchema.CallToolResult(contents, false);
					} catch (Exception e) {
						Msg.error(revaPlugin.class, "Error converting decompilation data to JSON", e);
						return new McpSchema.CallToolResult(
							List.of(new TextContent("Error converting decompilation data to JSON: " + e.getMessage())),
							true
						);
					}
				}
			);

		try {
			server.addTool(toolSpecification);
		} catch (McpError e) {
			// This can happen when the tool is already added
			Msg.error(revaPlugin.class, "Error adding tool to MCP server", e);
			return;
		}
		Msg.info(revaPlugin.class, "Added get-decompiled-function tool to MCP server");
	}

	@Override
	protected void programOpened(Program program) {
		Msg.info(this, "Program opened: " + program.getName());
		super.programOpened(program);
	}

	@Override
	protected void programClosed(Program program) {
		Msg.info(this, "Program closed: " + program.getName());
		super.programClosed(program);
	}

	/***
	 * Open a domain file from the project
	 */
	private void addToolOpenProjectFile() {
		assert server != null;

		JsonSchema schema = new JsonSchema(
			"object",
			Map.of(
				"filePath", Map.of(
					"type", "string",
					"description", "Path to the file in the project"
				)
			),
			List.of("filePath"),
			false
		);

		McpSchema.Tool mcpTool = new McpSchema.Tool(
			"open-project-file",
			"Open a program from the project",
			schema
		);

		McpServerFeatures.SyncToolSpecification toolSpecification =
			new McpServerFeatures.SyncToolSpecification(
				mcpTool,
				(exchange, args) -> {
					String filePath = (String) args.get("filePath");
					if (filePath == null) {
						return new McpSchema.CallToolResult(
							List.of(new TextContent("No file path provided")),
							true
						);
					}

						// Get the project and verify it's open
					Project project = tool.getProject();
					if (project == null) {
						return new McpSchema.CallToolResult(
							List.of(new TextContent("No project is currently open")),
							true
						);
					}

					DomainFile domainFile = project.getProjectData().getRootFolder().getFile(filePath);
					if (domainFile == null) {
						return new McpSchema.CallToolResult(
							List.of(new TextContent("Failed to find file: " + filePath)),
							true
						);
					}

						// Get the program manager from the tool
					ProgramManager programManager = tool.getService(ProgramManager.class);
					if (programManager == null) {
						return new McpSchema.CallToolResult(
							List.of(new TextContent("Program Manager service not available")),
							true
						);
					}

						// Open the program using the program manager
					try {
						// Open the program in the tool
						Program program = programManager.openProgram(domainFile);
						if (program != null) {
							Msg.info(this, "Opened program: " + program.getName());
							return new McpSchema.CallToolResult(
								List.of(new TextContent("Opened program: " + program.getName())),
								false
							);
						} else {
							return new McpSchema.CallToolResult(
								List.of(new TextContent("Failed to open program: " + filePath)),
								true
							);
						}
					} catch (Exception e) {
						Msg.error(this, "Error opening file: " + filePath, e);
						return new McpSchema.CallToolResult(
							List.of(new TextContent("Error opening file: " + filePath + ": " + e.getMessage())),
							true
						);
					}
				}
			);
		try {
			server.addTool(toolSpecification);
		} catch (McpError e) {
			// This can happen when the tool is already added
			Msg.error(this, "Error adding tool to MCP server", e);
			return;
		}
		Msg.info(this, "Added open-project-file tool to MCP server");
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

		try {
			server.addTool(toolSpecification);
		} catch (McpError e) {
			// This can happen when the tool is already added
			Msg.error(this, "Error adding tool to MCP server", e);
			return;
		}
		server.notifyToolsListChanged();
		Msg.info(this, "Added list-project-files tool to MCP server");
	}

	private void collectDomainFiles(ghidra.framework.model.DomainFolder folder, String path, List<Map<String, Object>> filesData) {
		if (folder == null) return;

		// Process all files in this folder
		for (ghidra.framework.model.DomainFile file : folder.getFiles()) {
			Map<String, Object> fileInfo = Map.of(
				"path", file.getPathname(),
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

		// Register the list-project-files tool
		addToolListProjectFiles();
		addToolOpenProjectFile();
		// Add tool to list functions
		addToolListFunctions();
		// Add tool to get decompiled function
		addToolGetDecompiledFunction();
		// Add tool to get data at a specific address
		addToolGetDataAtAddress();

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
