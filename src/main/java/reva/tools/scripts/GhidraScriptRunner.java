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
package reva.tools.scripts;

import java.io.PrintWriter;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptControls;
import ghidra.app.script.UnsupportedScriptProvider;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Production {@link PythonScriptExecutor.ScriptRunner} that drives Ghidra's
 * scripting framework. Boundary class: depends on multiple static
 * {@code GhidraScriptUtil} entry points, so it's covered by integration and
 * Python-e2e tests rather than unit tests.
 *
 * <p>Detects PyGhidra unavailability by inspecting the provider returned by
 * {@code GhidraScriptUtil.getProvider()}: a {@code null} provider, an
 * {@link UnsupportedScriptProvider}, or a {@link GhidraScriptLoadException}
 * thrown from {@code getScriptInstance} all become
 * {@link PyGhidraNotAvailableException} with launch guidance.
 */
public class GhidraScriptRunner implements PythonScriptExecutor.ScriptRunner {

    static final String PYGHIDRA_LAUNCH_HINT =
        "Python scripting requires Ghidra to be launched via PyGhidra. " +
        "Use `pyghidra-gui` for GUI work, or run ReVa via `mcp-reva` / " +
        "`reva_headless_server.py`.";

    @Override
    public void run(
            ResourceFile scriptFile,
            Program program,
            PluginTool tool,
            PrintWriter outWriter,
            PrintWriter errWriter,
            TaskMonitor monitor)
            throws PyGhidraNotAvailableException, Exception {

        GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
        if (provider == null) {
            throw new PyGhidraNotAvailableException(
                "No script provider for " + scriptFile.getName() + ". " +
                PYGHIDRA_LAUNCH_HINT);
        }
        if (provider instanceof UnsupportedScriptProvider) {
            throw new PyGhidraNotAvailableException(PYGHIDRA_LAUNCH_HINT);
        }

        GhidraScriptUtil.acquireBundleHostReference();
        try {
            Project project = (tool != null) ? tool.getProject() : null;
            GhidraState globalState =
                new GhidraState(tool, project, program, null, null, null);
            GhidraState scriptState = new GhidraState(globalState);

            GhidraScript script;
            try {
                script = provider.getScriptInstance(scriptFile, errWriter);
            } catch (GhidraScriptLoadException e) {
                throw new PyGhidraNotAvailableException(
                    e.getMessage() + " " + PYGHIDRA_LAUNCH_HINT, e);
            }

            ScriptControls controls =
                new ScriptControls(outWriter, errWriter, monitor);
            script.execute(scriptState, controls);
        } finally {
            GhidraScriptUtil.releaseBundleHostReference();
        }
    }
}
