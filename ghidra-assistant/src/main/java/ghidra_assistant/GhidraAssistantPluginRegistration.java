package ghidra_assistant;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;


public interface GhidraAssistantPluginRegistration {
	public InterpreterConsole getConsole();	
	public String readConsole();	
	public void writeConsole(String output);

	/**
	 * Returns true if the plugin should update the embeddings
	 * once the embeddings are updated, ``embeddingsUpdated()``
	 * should be called.
	 */
	public Boolean shouldUpdateEmbeddings();
	public void embeddingsUpdated();
}
