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
package reva.resources.impl;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpServerFeatures.SyncResourceSpecification;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema.ReadResourceResult;
import io.modelcontextprotocol.spec.McpSchema.Resource;
import io.modelcontextprotocol.spec.McpSchema.ResourceContents;
import io.modelcontextprotocol.spec.McpSchema.TextResourceContents;
import reva.plugin.RevaProgramManager;
import reva.resources.AbstractResourceProvider;

/**
 * Resource provider that exposes the list of currently open programs.
 */
public class ProgramListResource extends AbstractResourceProvider {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String RESOURCE_ID = "ghidra://programs";
    private static final String RESOURCE_NAME = "open-programs";
    private static final String RESOURCE_DESCRIPTION = "Currently open programs";
    private static final String RESOURCE_MIME_TYPE = "text/plain";

    /**
     * Constructor
     * @param server The MCP server to register with
     */
    public ProgramListResource(McpSyncServer server) {
        super(server);
    }

    @Override
    public void register() {
        Resource resource = new Resource(
            RESOURCE_ID,
            RESOURCE_NAME,
            RESOURCE_DESCRIPTION,
            RESOURCE_MIME_TYPE,
            null  // No schema needed for this resource
        );

        SyncResourceSpecification resourceSpec = new SyncResourceSpecification(
            resource,
            (exchange, request) -> {
                List<ResourceContents> resourceContents = new ArrayList<>();

                // Get all open programs
                List<Program> openPrograms = RevaProgramManager.getOpenPrograms();

                for (Program program : openPrograms) {
                    try {
                        // Create program info object
                        String programPath = program.getDomainFile().getPathname();
                        String programLanguage = program.getLanguage().getLanguageID().getIdAsString();
                        String programCompilerSpec = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
                        long programSize = program.getMemory().getSize();

                        // Create a JSON object with program metadata
                        String metaString = JSON.writeValueAsString(
                            new ProgramInfo(programPath, programLanguage, programCompilerSpec, programSize)
                        );

                        // Add to resource contents
                        // URL encode the program path to ensure URI safety
                        String encodedProgramPath = URLEncoder.encode(programPath, StandardCharsets.UTF_8);
                        resourceContents.add(
                            new TextResourceContents(
                                RESOURCE_ID + "/" + encodedProgramPath,
                                RESOURCE_MIME_TYPE,
                                metaString
                            )
                        );
                    } catch (JsonProcessingException e) {
                        logError("Error serializing program metadata", e);
                    }
                }

                return new ReadResourceResult(resourceContents);
            }
        );

        server.addResource(resourceSpec);
        logInfo("Registered resource: " + RESOURCE_NAME);
    }

    /**
     * Simple class to hold program information for JSON serialization
     */
    private static class ProgramInfo {
        @SuppressWarnings("unused")
        public String programPath;

        @SuppressWarnings("unused")
        public String language;

        @SuppressWarnings("unused")
        public String compilerSpec;

        @SuppressWarnings("unused")
        public long sizeBytes;

        public ProgramInfo(String programPath, String language, String compilerSpec, long sizeBytes) {
            this.programPath = programPath;
            this.language = language;
            this.compilerSpec = compilerSpec;
            this.sizeBytes = sizeBytes;
        }
    }
}
