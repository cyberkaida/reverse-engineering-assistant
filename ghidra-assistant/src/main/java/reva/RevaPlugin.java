package reva;

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

	@Override
	protected void programActivated(Program program) {
		Msg.info(this, "Starting ReVa service for " + program.getName());
	}

	@Override
	protected void programDeactivated(Program program) {
	}

	public void registerInference(String hostname, int port) {
		ManagedChannelBuilder<?> channel = ManagedChannelBuilder.forAddress(hostname, port);
		// TODO: Register each of the inference handlers
	}

	public RevaPlugin(PluginTool tool) {
		super(tool);
		serviceMonitor = new TaskMonitorAdapter(true);
		Msg.info(this, "ReVa plugin loaded!");
		ServerBuilder<?> server = ServerBuilder.forPort(50051);
		server.addService(new RevaGetCursor(this));
		serverHandle = server.build();

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
			// TODO: Create a subprocess to run the inference side.
			// and pass the hostname and port.
		});

		task.launchInBackground(serviceMonitor);
		inferenceTask.launchInBackground(serviceMonitor);
	}

	@Override
	protected void dispose() {
		serverHandle.shutdown();
		this.serviceMonitor.cancel();
		super.dispose();
	}
}
