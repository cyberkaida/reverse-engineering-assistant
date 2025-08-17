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
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.SystemUtilities;
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
    private static final String RESOURCE_DESCRIPTION = "Currently open programs with execution context information. Each program includes an 'isAnalyzed' flag indicating whether Ghidra's auto-analysis has been run. Unanalyzed programs (isAnalyzed: false) will have limited function discovery, minimal string detection, and basic symbol information. If you encounter limited results when working with a specific program's functions, strings, or data structures, run the 'analyze-program' tool on that program to improve the available information.";
    private static final String RESOURCE_MIME_TYPE = "application/json";

    /**
     * Constructor
     * @param server The MCP server to register with
     */
    public ProgramListResource(McpSyncServer server) {
        super(server);
    }

    /**
     * Check if we're running in headless mode
     * @return true if in headless mode
     */
    private boolean isHeadlessMode() {
        return Boolean.getBoolean("java.awt.headless") || 
               Boolean.getBoolean(SystemUtilities.HEADLESS_PROPERTY);
    }

    /**
     * Check if we're in PyGhidra mode
     * @return true if in PyGhidra mode
     */
    private boolean isPyGhidraMode() {
        return isHeadlessMode() && System.getProperty("pyghidra.mode") != null;
    }

    /**
     * Get the current execution context
     * @return String describing the context
     */
    private String getExecutionContext() {
        if (isPyGhidraMode()) {
            return "pyghidra";
        } else if (isHeadlessMode()) {
            return "headless";
        } else {
            return "gui";
        }
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

                try {
                    // Get all open programs
                    List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
                    String executionContext = getExecutionContext();

                    // Create overall context information
                    ContextInfo contextInfo = new ContextInfo(
                        executionContext,
                        openPrograms.size(),
                        System.currentTimeMillis()
                    );

                    // Create program list with detailed information
                    List<ProgramInfo> programInfos = new ArrayList<>();
                    for (Program program : openPrograms) {
                        String programPath = program.getDomainFile().getPathname();
                        String programLanguage = program.getLanguage().getLanguageID().getIdAsString();
                        String programCompilerSpec = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
                        long programSize = program.getMemory().getSize();
                        String executablePath = program.getExecutablePath();
                        boolean isAnalyzed = GhidraProgramUtilities.isAnalyzed(program);

                        String programName = program.getDomainFile().getName();
                        
                        programInfos.add(new ProgramInfo(
                            programPath,
                            programName,
                            programLanguage,
                            programCompilerSpec,
                            programSize,
                            executablePath,
                            isAnalyzed
                        ));
                    }

                    // Create comprehensive program list response
                    ProgramListResponse response = new ProgramListResponse(contextInfo, programInfos);
                    String responseJson = JSON.writeValueAsString(response);

                    resourceContents.add(
                        new TextResourceContents(
                            RESOURCE_ID,
                            RESOURCE_MIME_TYPE,
                            responseJson
                        )
                    );

                } catch (JsonProcessingException e) {
                    logError("Error serializing program list", e);
                    // Return error information
                    try {
                        String errorJson = JSON.writeValueAsString(
                            java.util.Map.of(
                                "error", "Failed to serialize program list",
                                "message", e.getMessage(),
                                "context", getExecutionContext()
                            )
                        );
                        resourceContents.add(
                            new TextResourceContents(
                                RESOURCE_ID,
                                RESOURCE_MIME_TYPE,
                                errorJson
                            )
                        );
                    } catch (JsonProcessingException ex) {
                        logError("Error creating error response", ex);
                    }
                }

                return new ReadResourceResult(resourceContents);
            }
        );

        server.addResource(resourceSpec);
        logInfo("Registered resource: " + RESOURCE_NAME);
    }

    /**
     * Class to hold execution context information
     */
    private static class ContextInfo {
        @SuppressWarnings("unused")
        public String executionMode;

        @SuppressWarnings("unused")
        public int programCount;

        @SuppressWarnings("unused")
        public long timestamp;

        public ContextInfo(String executionMode, int programCount, long timestamp) {
            this.executionMode = executionMode;
            this.programCount = programCount;
            this.timestamp = timestamp;
        }
    }

    /**
     * Enhanced class to hold program information for JSON serialization
     */
    private static class ProgramInfo {
        @SuppressWarnings("unused")
        public String programPath;

        @SuppressWarnings("unused")
        public String name;

        @SuppressWarnings("unused")
        public String language;

        @SuppressWarnings("unused")
        public String compilerSpec;

        @SuppressWarnings("unused")
        public long sizeBytes;

        @SuppressWarnings("unused")
        public String executablePath;

        @SuppressWarnings("unused")
        public boolean isAnalyzed;

        public ProgramInfo(String programPath, String name, String language, String compilerSpec, 
                          long sizeBytes, String executablePath, boolean isAnalyzed) {
            this.programPath = programPath;
            this.name = name;
            this.language = language;
            this.compilerSpec = compilerSpec;
            this.sizeBytes = sizeBytes;
            this.executablePath = executablePath;
            this.isAnalyzed = isAnalyzed;
        }
    }

    /**
     * Complete response structure for program list
     */
    private static class ProgramListResponse {
        @SuppressWarnings("unused")
        public ContextInfo context;

        @SuppressWarnings("unused")
        public List<ProgramInfo> programs;

        public ProgramListResponse(ContextInfo context, List<ProgramInfo> programs) {
            this.context = context;
            this.programs = programs;
        }
    }
}
