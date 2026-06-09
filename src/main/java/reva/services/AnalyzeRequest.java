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
package reva.services;

import java.util.List;

import ghidra.program.model.listing.Program;
import reva.util.ProgramPersistenceUtil.PersistMode;

/**
 * Immutable carrier describing one background auto-analysis run for {@link AnalysisJobRunner}.
 * Analyzer-name validation is expected to have already happened in the caller.
 */
public final class AnalyzeRequest {

    public final Program program;
    public final List<String> enableAnalyzers;
    public final List<String> disableAnalyzers;
    public final boolean forceFullAnalysis;
    /** Maximum analysis time in seconds; {@code -1} means no timeout. */
    public final int timeoutSeconds;
    public final PersistMode persistMode;

    public AnalyzeRequest(Program program, List<String> enableAnalyzers,
            List<String> disableAnalyzers, boolean forceFullAnalysis, int timeoutSeconds,
            PersistMode persistMode) {
        this.program = program;
        this.enableAnalyzers = enableAnalyzers != null ? List.copyOf(enableAnalyzers) : List.of();
        this.disableAnalyzers = disableAnalyzers != null ? List.copyOf(disableAnalyzers) : List.of();
        this.forceFullAnalysis = forceFullAnalysis;
        this.timeoutSeconds = timeoutSeconds;
        this.persistMode = persistMode;
    }
}
