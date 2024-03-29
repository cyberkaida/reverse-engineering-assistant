package reva;

import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.util.Msg;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskMonitor;
import resources.Icons;
import reva.RevaProtocol.RevaExplain;
import reva.RevaProtocol.RevaGetNewSymbolName;
import reva.RevaProtocol.RevaGetNewVariableName;
import reva.RevaProtocol.RevaHeartbeat;
import reva.RevaProtocol.RevaHeartbeatResponse;
import reva.RevaProtocol.RevaLocation;
import reva.RevaProtocol.RevaVariable;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;

import ghidra.util.task.TaskMonitorAdapter;

import java.util.HashMap;

import org.python.antlr.ast.List;

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
	private DockingAction heartbeatAction;

	HashMap<Program, RevaService> services = new HashMap<Program, RevaService>();


	@Override
	protected void programActivated(Program program) {
		// TODO: Start a ReVa service for the program
		RevaService service = new RevaService(program);
		Msg.info(this, "Starting ReVa service for " + program.getName());
		TaskBuilder.withTask(service)
		.setCanCancel(true)
		.setHasProgress(false)
		.setTitle("ReVa communications")
		.launchInBackground(serviceMonitor);

		services.put(program, service);
	}

	@Override
	protected void programDeactivated(Program program) {
		services.remove(program);
	}



	public RevaPlugin(PluginTool tool) {
		super(tool);
		serviceMonitor = new TaskMonitorAdapter(true);

		Msg.info(this, "ReVa plugin loaded!");
		setupConnectionMonitor(tool);
		setupActionRenameFunctionVariable(tool);
		setupActionDescribeFunction(tool);
		setupActionRenameSymbol(tool);
	}

	@Override
	protected void dispose() {
		for (RevaService service : services.values()) {
			Msg.info(this, "Stopping ReVa service for " + service.currentProgram.getName());
			service.cancel();
		}
		super.dispose();
	}

	// MARK: - Actions

	private void setupConnectionMonitor(PluginTool tool) {
		DockingAction ab = new ActionBuilder("ReVa Connection Monitor", getName())
		.description("Monitor the connection to the ReVa service")
		.toolBarIcon(Icons.REFRESH_ICON)
		.enabledWhen(context -> {
			// Get the current program, look up the RevaService
			// and check the `connected` property
			if (context instanceof ProgramActionContext) {
				ProgramActionContext programContext = (ProgramActionContext) context;
				Program program = programContext.getProgram();
				if (program != null) {
					RevaService service = services.get(program);
					if (service != null) {
						return true;
					}
				}
			}
			return false;
		})
		.onAction(context -> {
			// Get the current program, look up the RevaService
			// and check the `connected` property
			if (context instanceof ProgramActionContext) {
				ProgramActionContext programContext = (ProgramActionContext) context;
				Program program = programContext.getProgram();
				if (program != null) {
					RevaService service = services.get(program);
					if (service != null) {
						Msg.info(this, "Sending heartbeat");
						RevaHeartbeatResponse response = (RevaHeartbeatResponse)service.communicateToReva(new RevaHeartbeat());
						if (response != null) {
							Msg.info(this, "Got heartbeat response: " + response.toJson());
							Msg.showInfo(this, context.getSourceComponent(), "ReVa", "Connected to ReVa service");
						} else {
							Msg.error(this, "No heartbeat response");
							Msg.showError(this, context.getSourceComponent(), "ReVa", "Not connected to ReVa service");
						}
					}
				}
			}
		})
		.buildAndInstall(tool);
	}

	/**
	 * Right click menu action to rename the selected variable.
	 * @param tool
	 */
	private void setupActionRenameFunctionVariable(PluginTool tool) {
		new ActionBuilder("ReVa Rename", getName())
		.description("Rename the selection")
		.popupMenuPath("ReVa", "Rename")
		.popupMenuGroup("ReVa")
		.onAction(context -> {
			DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
			DecompilerPanel panel = decompilerContext.getDecompilerPanel();

			ProgramLocation location = panel.getCurrentLocation();
			var token = panel.getTokenAtCursor();

			Msg.info(this, "Renaming " + token.getText());
			HighVariable highVariable = token.getHighVariable();
			if (highVariable == null) {
				Msg.error(this, "No high variable found, we can't rename this yet.");
				return;
			}

			RevaGetNewVariableName message = new RevaGetNewVariableName();
			RevaVariable messageVariable = new RevaVariable();
			messageVariable.name = highVariable.getName();
			messageVariable.data_type = highVariable.getDataType().getName();
			messageVariable.storage = highVariable.getSymbol().getStorage().toString();
			message.variable = messageVariable;
			message.function_name = highVariable.getHighFunction().getFunction().getName(true);

			// Send the message to ReVa, we don't expect a response
			RevaService service = services.get(decompilerContext.getProgram());
			service.sendToReva(message);
		})
		.enabledWhen(context -> { return context instanceof DecompilerActionContext; })
		.buildAndInstall(tool);
	}

	private void setupActionRenameSymbol(PluginTool tool) {
		new ActionBuilder("ReVa Rename", getName())
		.description("Rename the selection")
		.popupMenuPath("ReVa", "Rename")
		.popupMenuGroup("ReVa")
		.onAction(context -> {
			ListingActionContext listingContext = (ListingActionContext) context;

			ProgramLocation location = listingContext.getLocation();
			Symbol symbol = listingContext.getProgram().getSymbolTable().getPrimarySymbol(location.getAddress());
			if (symbol == null) {
				Msg.error(this, "No symbol found, we can't rename this yet.");
				return;
			}

			RevaGetNewSymbolName message = new RevaGetNewSymbolName();
			message.symbol_name = symbol.getName();
			// Send the message to ReVa, we don't expect a response
			RevaService service = services.get(listingContext.getProgram());
			service.sendToReva(message);
		})
		.enabledWhen(context -> { return context instanceof ListingActionContext; })
		.buildAndInstall(tool);
	}

	/**
	 * Right click menu action to describe the selected function
	 * and place a comment on it with the description.
	 * @param tool
	 */
	private void setupActionDescribeFunction(PluginTool tool) {
		new ActionBuilder("ReVa Describe", getName())
		.description("Describe the selected")
		.popupMenuPath("ReVa", "Describe selection")
		.popupMenuGroup("ReVa")
		.onAction(context -> {
			// This should be active in both the listing and decompiler view
			Address currentAddress;
			Program program;
			RevaService service;

			if (context instanceof DecompilerActionContext) {
				DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
				program = decompilerActionContext.getProgram();
				ProgramLocation location = decompilerActionContext.getLocation();
				currentAddress = location.getAddress();
				service = services.get(decompilerActionContext.getProgram());
			} else if (context instanceof ListingActionContext) {
				ListingActionContext listingActionContext = (ListingActionContext) context;
				program = listingActionContext.getProgram();
				ProgramLocation location = listingActionContext.getLocation();
				currentAddress = location.getAddress();
				service = services.get(listingActionContext.getProgram());
			} else {
				Msg.error(this, "Unknown context type");
				return;
			}

			RevaExplain message = new RevaExplain();
			RevaLocation location = new RevaLocation();


			Function currentFunction = program.getFunctionManager().getFunctionContaining(currentAddress);
			if (currentFunction != null) {
				Msg.info(this, "Describing function " + currentFunction.getName());
				location.function_name = currentFunction.getName();
			}

			// If there is something specific selected, let's send that too
			if (context instanceof ListingActionContext) {
				// If the user right clicked in the listing, we'll get the selection
				if (currentFunction == null || !currentFunction.getEntryPoint().equals(currentAddress)) {
					// The LLM can get confused if we specify both the start address
					// and the name. So we only add the address when we aren't selecting the entry point
					location.cursor_address = currentAddress.toString();
				}

				ListingActionContext listingActionContext = (ListingActionContext) context;
				ProgramSelection selected = listingActionContext.getHighlight();
				if (selected!= null &&!selected.isEmpty()) {
					location.start_address = selected.getMinAddress().toString();
					location.end_address = selected.getMaxAddress().toString();
				}
			} else if (context instanceof DecompilerActionContext) {
				DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
				ProgramSelection selected = decompilerActionContext.getSelection();
				if (selected != null && !selected.isEmpty()) {
					// TODO: We want to get the text of the selection,
					// but none of these techniques work.

					// If we set these two without "content" set, the LLM
					// will place the comment in the wrong place

					location.start_address = selected.getMinAddress().toString();
					location.end_address = selected.getMaxAddress().toString();

					// Get the selected text from the decompilation
					DecompilerPanel panel = decompilerActionContext.getDecompilerPanel();
					Msg.info(this, "Highlighted: " + panel.getHighlightedText());
					Msg.info(this, "Selected: " +  panel.getSelectedText());
					Msg.info(this, "Cursor: " + panel.getTextUnderCursor());
				}
			}

			message.location = location;
			// Send the message to ReVa, we don't expect a response
			service.sendToReva(message);
			return;
		})
		.enabledWhen(context -> {
			return (context instanceof DecompilerActionContext || context instanceof ListingActionContext);
		})
		.buildAndInstall(tool);
	}
}
