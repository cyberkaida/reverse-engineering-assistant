package reva;

import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

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

	@Override
	protected void programActivated(Program program) {
		Msg.info(this, "Starting ReVa service for " + program.getName());
	}

	@Override
	protected void programDeactivated(Program program) {
	}

	public void registerInference(String hostname, int port) {
		ManagedChannelBuilder<?> channel = ManagedChannelBuilder.forAddress(hostname, port);
		Msg.info(this, String.format("Connected channel to %s:%s", hostname, port));
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
		/*
		 * TODO: Start our server, launch the subprocess for the inference
		 * side, pass our hostname and port as an argument. Wait for the
		 * inference process to call back to us with its hostname and port.
		 */
		TaskBuilder task = new TaskBuilder("ReVa Server", (monitor) -> {
			try {
				serverHandle.start();
				serverHandle.awaitTermination();
			} catch (Exception e) {
				Msg.error(this, "Error starting ReVa server: " + e.getMessage());
			}
		});

		TaskBuilder inferenceTask = new TaskBuilder("ReVa Inference", (monitor) -> {
			ProcessBuilder processBuilder = new ProcessBuilder();
			String[] command = {
				"reva-server",
				"--connect-host", "localhost",
				"--connect-port", String.format("%d", serverHandle.getPort())
			};
			processBuilder.command(command);
			Msg.info(this, "Starting inference server...");
			try {
				final Process inferenceProcess = processBuilder.start();;
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
		server.addService(new RevaGetCursor(this));
		server.addService(new RevaHeartbeat());
		serverHandle = server.build();

		Options options = tool.getOptions("ReVa");

		options.registerOption("Path to reva-server", OptionType.STRING_TYPE, "reva-server", null, "Path to the reva-server binary, or `reva-server` if it is on the system path.");
		options.registerOption("Inference type", OptionType.ENUM_TYPE, RevaInferenceType.OpenAI, null, "The type of inference server to connect to.");

		startInferenceServer();
	}

	@Override
	protected void dispose() {
		serverHandle.shutdown();
		this.serviceMonitor.cancel();
		super.dispose();
	}
}
