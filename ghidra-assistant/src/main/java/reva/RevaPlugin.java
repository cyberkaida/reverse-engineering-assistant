package reva;

import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.util.Msg;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Server;
import io.grpc.ServerBuilder;

import java.io.IOException;
import java.net.ServerSocket;

import java.util.List;

import docking.action.builder.ActionBuilder;
import reva.Handlers.*;

@PluginInfo(
        status = PluginStatus.STABLE, // probably a lie
        packageName = "ReVa",
        category = PluginCategoryNames.ANALYSIS,
        shortDescription = "Reverse Engineering Assistant",
        description = "An AI companion for your Ghidra project",
	servicesRequired = {  },
	servicesProvided = {  }
)
public class RevaPlugin extends ProgramPlugin {
	TaskMonitor serviceMonitor;
	Server serverHandle;


	public String getExtensionHostname() {
		return "127.0.0.1";
	}

	public int getExtensionPort() {
		return serverHandle.getPort();
	}

	public enum RevaInferenceType {
		// These values must match to the arguments taken
		// by `reva-server`.
		OpenAI("OpenAI"),
		Ollama("Ollama");

		private String value;

		RevaInferenceType(String string) {
			this.value = string;
		}

		public String getValue() {
			return value;
		}
	}

	public Program getCurrentProgram() {
		return currentProgram;
	}

	@Override
	protected void programActivated(Program program) {
		Msg.info(this, "Starting ReVa service for " + program.getName());
	}

	@Override
	protected void programDeactivated(Program program) {
	}

	public String inferenceHostname;
	public int inferencePort;
	public void registerInference(String hostname, int port) {
		ManagedChannelBuilder<?> channel = ManagedChannelBuilder.forAddress(hostname, port);
		channel.usePlaintext();
		channel.enableRetry();
		Msg.info(this, String.format("Connected channel to %s:%s", hostname, port));
		inferenceHostname = hostname;
		inferencePort = port;
		// TODO: Register each of the inference handlers
	}

	public int findAvailablePort() {
		int port = -1;
		try (ServerSocket socket = new ServerSocket(0)) {
			port = socket.getLocalPort();
			socket.close();
		} catch (IOException e) {
			Msg.error(this, "Error finding an open port: " + e.getMessage());
		}
		return port;
	}

	private void startInferenceServer() {

		TaskBuilder task = new TaskBuilder("ReVa Server", (monitor) -> {
			try {
				Msg.info(this, "Started Extension RPC server...");
				serverHandle.awaitTermination();
				Msg.error(this, "ReVa server exited!");
			} catch (Exception e) {
				Msg.error(this, "Error starting ReVa server: " + e.getMessage());
			}
		});

		TaskBuilder inferenceTask = new TaskBuilder("ReVa Inference", (monitor) -> {
			ProcessBuilder processBuilder = new ProcessBuilder();
			String portString = String.format("%d", serverHandle.getPort());
			String[] command = {
				"reva-server",
				"--connect-host", getExtensionHostname(),
				"--connect-port", portString,
			};
			processBuilder.command(command);
			processBuilder.redirectError(ProcessBuilder.Redirect.DISCARD);
			processBuilder.redirectOutput(ProcessBuilder.Redirect.DISCARD);
			Msg.info(this, "Starting inference server... " + String.join(" ", command));
			try {
				final Process inferenceProcess = processBuilder.start();
				try {
					Msg.info(this, String.format("Inference process pid: %d", inferenceProcess.pid()));
					// If the monitor is cancelled we are going down and we take the inference
					// process down too
					monitor.addCancelledListener(() -> {
						Msg.info(this, "Cancelling inference process...");
						inferenceProcess.destroy();
					});

					inferenceProcess.waitFor();
					byte[] b = inferenceProcess.getErrorStream().readAllBytes();
					Msg.info(this, new String(b));
					Msg.warn(this, "Inference process exited!");
				} catch (Exception e) {
					Msg.error(this, "Error starting ReVa inference server: " + e.getMessage(), e);
					if (inferenceProcess != null) {
						inferenceProcess.destroy();
					}
				}
			} catch (IOException e) {
				Msg.error(this, "Error starting ReVa inference server: " + e.getMessage(), e);
			}

		}).setCanCancel(true);

		try {
			serverHandle.start();
		} catch (IOException e) {
			Msg.error(this, "Error starting ReVa server: " + e.getMessage(), e);
		}
		task.launchInBackground(serviceMonitor);
		inferenceTask.launchInBackground(serviceMonitor);
	}

	public RevaPlugin(PluginTool tool) {
		super(tool);
		serviceMonitor = new TaskMonitorAdapter(true);
		Msg.info(this, "ReVa plugin loaded!");

		int port = findAvailablePort();
		ServerBuilder<?> server = ServerBuilder.forPort(port);
		server.addService(new RevaHandshake(this));
		//server.addService(new RevaGetCursor(this));
		//server.addService(new RevaHeartbeat());
		//server.addService(new RevaGetDecompilation(this));
		serverHandle = server.build();

		Options options = tool.getOptions("ReVa");

		options.registerOption("Path to reva-server", OptionType.STRING_TYPE, "reva-server", null, "Path to the reva-server binary, or `reva-server` if it is on the system path.");
		options.registerOption("Inference type", OptionType.ENUM_TYPE, RevaInferenceType.OpenAI, null, "The type of inference server to connect to.");

		// Install all the UI hooks
		installChatCommand();

		startInferenceServer();
	}

	@Override
	protected void dispose() {
		serverHandle.shutdown();
		this.serviceMonitor.cancel();
		super.dispose();
	}


	/**
     * Given a function name from ReVa, find the function in the current program.
     * @param functionName
     * @return The function, or null if not found.
     */
    public Function findFunction(String functionName) {
        Function function = null;
        for (Function f : this.currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName(true).equals(functionName)) {
                function = f;
                break;
            }
        }

        if (function == null) {
            // Let's find the function by symbol
            for (Symbol symbol : this.currentProgram.getSymbolTable().getAllSymbols(true)) {
                if (symbol.getName().equals(functionName)) {
                    function = this.currentProgram.getFunctionManager().getFunctionAt(symbol.getAddress());
                    if (function != null) {
                        break;
                    }
                }
            }
        }
        return function;
    }

    public Address addressFromAddressOrSymbol(String addressOrSymbol) {
        Address address = this.currentProgram.getAddressFactory().getAddress(addressOrSymbol);
        if (address == null) {
            // OK, it's not an address, let's try a symbol
            List<Symbol> symbols = this.currentProgram.getSymbolTable().getGlobalSymbols(addressOrSymbol);
            if (symbols.size() > 0) {
                Symbol symbol = symbols.get(0);
                if (symbol != null) {
                    address = symbol.getAddress();
                }
            }
        }
        return address;
    }

	void installChatCommand() {
		new ActionBuilder("ReVa Chat", "ReVa")
			.menuPath("ReVa", "Chat")
			.onAction((event) -> {
				Msg.info(this, "Chat command clicked!");
				// TODO: Open a chat window

				// Start a process to open a chat window
				// The program is:
				// reva-chat --host localhost --port <port> --program <program>
				// This should open in a new terminal window

				String[] command = {
					"reva-chat",
					"--host", this.inferenceHostname,
					"--port", String.format("%d", this.inferencePort),
					"--program", this.currentProgram.getName()
				};
				Msg.info(this, command);
			})
			.enabledWhen((context) -> this.inferenceHostname != null && this.inferencePort != 0)
			.buildAndInstall(tool);
	}
}
