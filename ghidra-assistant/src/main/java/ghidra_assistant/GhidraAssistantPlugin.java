package ghidra_assistant;

import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.plugin.core.interpreter.InterpreterPanelService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.BufferedInputStream;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitorAdapter;

import ghidra.util.task.ConsoleTaskMonitor;
import java.util.Collections;

import java.util.List;

import javax.swing.Icon;
import resources.Icons;

import com.dropbox.core.json.JsonReader.FileLoadException.IOError;

import docking.ActionContext;
import docking.action.DockingAction;
import generic.jar.ResourceFile;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.Ghidra;
import ghidra.app.plugin.PluginCategoryNames;
import docking.action.ToolBarData;

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;

import java.io.IOException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.file.Files;

@PluginInfo(
        status = PluginStatus.STABLE,
        packageName = "GhidraAssistant",
        category = PluginCategoryNames.ANALYSIS,
        shortDescription = "Ghidra Assistant",
        description = "An AI companian for your Ghidra project",
	servicesRequired = { InterpreterPanelService.class },
	servicesProvided = { GhidraAssistantPluginRegistration.class }
)


public class GhidraAssistantPlugin extends ProgramPlugin implements InterpreterConnection, GhidraAssistantPluginRegistration {

	public class PythonThread extends Thread {
		private GhidraAssistantPlugin plugin;
		GhidraScript assistantScript;

		PythonThread(GhidraAssistantPlugin plugin) {
			this.plugin = plugin;
		}

		@Override
		public void run() {
			Msg.info(this, "Starting Python3 thread");
			GhidraScriptUtil util = new GhidraScriptUtil();	
			ResourceFile script = GhidraScriptUtil.findScriptByName("assistant_analysis.py");
			Msg.debug(this, "Found script: " + script);
			GhidraScriptProvider provider = GhidraScriptUtil.getProvider(script);
			try {
				this.assistantScript = provider.getScriptInstance(script, plugin.console.getErrWriter());
				// Create a state
				GhidraState state = new GhidraState(
						plugin.getTool(), 
						plugin.getTool().getProject(),
						plugin.getCurrentProgram(),
						plugin.getProgramLocation(),
						plugin.getProgramSelection(),
						plugin.getProgramHighlight());
				Msg.info(this, "Starting Python3 script");
				this.assistantScript.execute(
						state,
						new ConsoleTaskMonitor(),
						console.getOutWriter()
						);
			} catch (Exception e) {
				Msg.error(this, "Error loading script", e);
			}
		}
	}


        private InterpreterConsole console;
	private PythonThread pythonThread = null;

	private GhidraAssistantScript assistantScriptInterface = null;
	private GhidraScript assistantScript;

	private String questionFifoPath;
	private String answerFifoPath;

	private Boolean shouldUpdateEmbeddingsFlag = false;

	@Override
	public Boolean shouldUpdateEmbeddings() {
		return this.shouldUpdateEmbeddingsFlag;
	}

	@Override
	public void embeddingsUpdated() {
		this.shouldUpdateEmbeddingsFlag = false;
	}

	public void registerScript(GhidraAssistantScript assistantScript) {
		Msg.info(this, "Registering script");
		this.assistantScriptInterface = assistantScript;
	}

        public GhidraAssistantPlugin(PluginTool tool) {
                super(tool);
        }

	public InterpreterConsole getConsole() {
		return this.console;
	}

	public String readConsole() {
		String input = new String();
		try {
			InputStreamReader stdin_stream = new InputStreamReader(this.console.getStdin());
			BufferedReader stdin_reader = new BufferedReader(stdin_stream);
			while (this.console.getStdin().available() > 0) {
				input += stdin_reader.readLine() + "\n";
			}
		} catch (IOException e) {
			Msg.error(this, "Error reading from console", e);
		}
		return input.strip();
	}

	public void writeConsole(String output) {
		try {
			this.console.getStdOut().write(output.getBytes());
			this.console.getStdOut().flush();
		} catch (IOException e) {
			Msg.error(this, "Error writing to console", e);
		}
	}

        @Override
        protected void init() {
                super.init();
		Msg.info(this, "Ghidra Assistant plugin loading");
                this.console = this.getTool().getService(InterpreterPanelService.class).createInterpreterPanel(this, false);
		this.console.addFirstActivationCallback(
				() -> this.startPython()
				);
		this.console.setPrompt("assistant> ");
		// https://github.com/NationalSecurityAgency/ghidra/blob/26d4bd9104809747c21f2528cab8aba9aef9acd5/Ghidra/Features/Python/src/main/java/ghidra/python/PythonPlugin.java#L156C1-L170C34
		// Reset Assistant
		DockingAction resetAction = new DockingAction("Reset Assistant", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				reset();
			}
		};
		resetAction.setDescription("Reset Assistant");
		resetAction.setToolBarData(
			new ToolBarData(Icons.REFRESH_ICON, null));
		resetAction.setEnabled(true);
		console.addAction(resetAction);
        }

	public void reset() {
		this.pythonThread.interrupt();
		try {
			// Three seconds to tidy up
			this.pythonThread.join(3000);
			this.pythonThread = null;
			this.startPython();
		} catch (InterruptedException e) {
			Msg.error(this, "Error joining python thread", e);
		}
	}


        @Override
        public String getTitle() {
                return "Ghidra Assistant";
        }

        @Override
        public Icon getIcon() {
                return null;
        }

        @Override
        public List<CodeCompletion> getCompletions(String arg0) {
                return Collections.<CodeCompletion>emptyList();
        }

        /**
         * This method will call down to the Ghidrathon interpreter
         * and call into our python script to reset the embeddings.
         */
        private void startPython() {
		pythonThread = new PythonThread(this);
		pythonThread.start();
        }

	@Override
	protected void dispose() {
		this.reset();
		super.dispose();
	}
}
