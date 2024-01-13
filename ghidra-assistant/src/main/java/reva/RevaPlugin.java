package reva;

import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskListener;
import resources.Icons;
import reva.RevaProtocol.RevaHeartbeat;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;




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
	RevaService service;
	private DockingAction heartbeatAction;

	@Override
	protected void programActivated(Program program) {
		// TODO: Start a ReVa service for the program
	}

	public RevaPlugin(PluginTool tool) {
		super(tool);
		service = new RevaService(currentProgram);
		TaskLauncher.launch(service);
		Msg.info(this, "ReVa plugin loaded!");
		heartbeatAction = new ActionBuilder("ReVa Heartbeat", getName())
			.toolBarIcon(Icons.REFRESH_ICON)
			.description("Send a heartbeat to ReVa")
			.withContext(ProgramActionContext.class)
			.onAction(context -> {
				Msg.info(context, "Sending heartbeat! 💜");
				service.sendMessage(new RevaHeartbeat());
			})
			.buildAndInstall(tool);
	}

	@Override
	protected void dispose() {
		service.cancel();
		super.dispose();
	}



}
