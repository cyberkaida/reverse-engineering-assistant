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
package reva.decompiler;

import java.util.concurrent.TimeUnit;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;

import reva.plugin.ConfigManager;
import reva.util.RevaInternalServiceRegistry;

/**
 * The one decompiler configuration used by every tool that decompiles for display or line mapping.
 */
public final class ConfiguredDecompiler {

    private ConfiguredDecompiler() {
    }

    /**
     * Open a decompiler with C code and syntax tree on, style "decompile", unreachable code kept.
     * Returns null (after disposing) if openProgram fails. The caller disposes.
     */
    public static DecompInterface open(Program program) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        DecompileOptions options = new DecompileOptions();
        options.setEliminateUnreachable(false);
        decompiler.setOptions(options);

        if (!decompiler.openProgram(program)) {
            Msg.error(ConfiguredDecompiler.class, "Failed to initialize decompiler for " + program.getName());
            decompiler.dispose();
            return null;
        }
        return decompiler;
    }

    /**
     * Decompile with the configured timeout. Error strings match the tools' existing messages.
     */
    public static DecompilationResult decompile(DecompInterface decompiler, Program program, Function function) {
        int timeoutSeconds = RevaInternalServiceRegistry.getService(ConfigManager.class).getDecompilerTimeoutSeconds();
        TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
        DecompileResults results = decompiler.decompileFunction(function, 0, monitor);

        if (monitor.isCancelled()) {
            String msg = "Decompilation timed out after " + timeoutSeconds + " seconds";
            Msg.error(ConfiguredDecompiler.class, msg + " for " + function.getName());
            return DecompilationResult.failure(DecompilationResult.FailureKind.TIMED_OUT, msg);
        }
        if (!results.decompileCompleted()) {
            String msg = "Decompilation failed: " + results.getErrorMessage();
            Msg.error(ConfiguredDecompiler.class, msg + " for " + function.getName());
            return DecompilationResult.failure(msg);
        }
        return DecompilationResult.success(DecompilationSnapshot.from(program, results));
    }
}
