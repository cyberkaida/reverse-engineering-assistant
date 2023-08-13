package ghidra_assistant;

/**
 * This interface is implemented in the python side.
 */
public interface GhidraAssistantScript {
	/**
	 * Trigger an update of the LLM embeddings
	 */
	public void updateEmbeddings();
	public String askQuestion(String question);
	public void shutdown();
}
