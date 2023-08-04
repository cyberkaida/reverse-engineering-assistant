package ghidra_assistant;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;


public interface GhidraAssistantPluginRegistration {
	public InterpreterConsole getConsole();	
	public String readConsole();	
	public void writeConsole(String output);
}
