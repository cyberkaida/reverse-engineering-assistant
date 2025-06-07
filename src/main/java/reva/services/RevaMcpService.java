package reva.services;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

/**
 * Service interface for accessing the application-level MCP server.
 * This service is provided by the RevaApplicationPlugin and consumed by tool-level plugins
 * to register with the shared MCP server that persists across tool sessions.
 */
public interface RevaMcpService {
    
    /**
     * Register a tool with the MCP server.
     * This allows the tool to receive program lifecycle notifications
     * and participate in MCP server operations.
     * 
     * @param tool The tool to register
     */
    void registerTool(PluginTool tool);
    
    /**
     * Unregister a tool from the MCP server.
     * Called when a tool is closing or no longer needs MCP services.
     * 
     * @param tool The tool to unregister
     */
    void unregisterTool(PluginTool tool);
    
    /**
     * Notify the MCP server that a program has been opened in a tool.
     * The server will track which programs are open in which tools.
     * 
     * @param program The program that was opened
     * @param tool The tool where the program was opened
     */
    void programOpened(Program program, PluginTool tool);
    
    /**
     * Notify the MCP server that a program has been closed in a tool.
     * The server will update its tracking of program-to-tool mappings.
     * 
     * @param program The program that was closed
     * @param tool The tool where the program was closed
     */
    void programClosed(Program program, PluginTool tool);
    
    /**
     * Check if the MCP server is currently running and accepting connections.
     * 
     * @return true if the server is running, false otherwise
     */
    boolean isServerRunning();
    
    /**
     * Get the port number the MCP server is listening on.
     * 
     * @return The server port number, or -1 if server is not running
     */
    int getServerPort();
    
    /**
     * Get the currently active program for MCP operations.
     * This is typically the program that was most recently opened
     * or the one in the currently focused tool.
     * 
     * @return The active program, or null if no program is active
     */
    Program getActiveProgram();
    
    /**
     * Set the active program for MCP operations.
     * This is typically called when focus changes between tools.
     * 
     * @param program The program to set as active
     * @param tool The tool containing the active program
     */
    void setActiveProgram(Program program, PluginTool tool);
}