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
package reva.resources;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpSyncServer;

/**
 * Base implementation of the ResourceProvider interface.
 * Provides common functionality for all resource providers.
 */
public abstract class AbstractResourceProvider implements ResourceProvider {
    protected final McpSyncServer server;

    /**
     * Constructor
     * @param server The MCP server to register resources with
     */
    public AbstractResourceProvider(McpSyncServer server) {
        this.server = server;
    }

    @Override
    public void programOpened(Program program) {
        // Default implementation does nothing
    }

    @Override
    public void programClosed(Program program) {
        // Default implementation does nothing
    }

    @Override
    public void cleanup() {
        // Default implementation does nothing
    }

    /**
     * Log an error message
     * @param message The message to log
     */
    protected void logError(String message) {
        Msg.error(this, message);
    }

    /**
     * Log an error message with an exception
     * @param message The message to log
     * @param e The exception that caused the error
     */
    protected void logError(String message, Exception e) {
        Msg.error(this, message, e);
    }

    /**
     * Log an informational message
     * @param message The message to log
     */
    protected void logInfo(String message) {
        Msg.info(this, message);
    }
}
