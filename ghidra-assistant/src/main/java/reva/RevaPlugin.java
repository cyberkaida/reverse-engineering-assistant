package reva;

import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskListener;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;


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
	Task serviceTask;

	RevaPlugin(PluginTool tool) {
		super(tool);
		serviceTask = new RevaService(currentProgram);
		TaskLauncher.launch(serviceTask);
	}

	@Override
	protected void dispose() {
		serviceTask.cancel();
		super.dispose();
	}
}
