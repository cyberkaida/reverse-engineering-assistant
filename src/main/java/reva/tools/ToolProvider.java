/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.tools;

import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpError;

/**
 * Interface for MCP tool providers.
 * Tool providers are responsible for registering and managing
 * MCP tools that allow interactive operations with Ghidra data.
 */
public interface ToolProvider {
    /**
     * Register all tools with the MCP server
     * @throws McpError if there's an error registering the tools
     */
    void registerTools() throws McpError;

    /**
     * Notify the provider that a program has been opened
     * @param program The program that was opened
     */
    void programOpened(Program program);

    /**
     * Notify the provider that a program has been closed
     * @param program The program that was closed
     */
    void programClosed(Program program);

    /**
     * Clean up any resources or state
     */
    void cleanup();
}
