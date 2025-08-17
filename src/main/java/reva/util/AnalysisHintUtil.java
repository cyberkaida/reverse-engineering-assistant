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
package reva.util;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;

/**
 * Utility class for generating analysis state hints for MCP tool responses.
 * Provides standardized hints about whether programs need analysis and suggestions
 * for using the analyze-program tool.
 */
public class AnalysisHintUtil {

    /**
     * Check if a program has been analyzed and return a hint if it hasn't.
     * 
     * @param program The program to check
     * @return A hint message if analysis is needed, null if no hint needed
     */
    public static String getAnalysisHint(Program program) {
        if (program == null) {
            return null;
        }

        boolean isAnalyzed = GhidraProgramUtilities.isAnalyzed(program);
        if (!isAnalyzed) {
            return "This program has not been analyzed yet. Use the 'analyze-program' tool to run Ghidra analysis for better results.";
        }

        return null; // No hint needed
    }

    /**
     * Get detailed analysis state information for inclusion in tool responses.
     * 
     * @param program The program to check
     * @return Map containing analysis state information
     */
    public static Map<String, Object> getAnalysisStateInfo(Program program) {
        Map<String, Object> analysisInfo = new HashMap<>();
        
        if (program == null) {
            analysisInfo.put("analyzed", false);
            analysisInfo.put("hint", "Program is null");
            return analysisInfo;
        }

        boolean isAnalyzed = GhidraProgramUtilities.isAnalyzed(program);
        analysisInfo.put("analyzed", isAnalyzed);
        
        if (!isAnalyzed) {
            analysisInfo.put("hint", "This program has not been analyzed yet. Use the 'analyze-program' tool to run Ghidra analysis for better results.");
            analysisInfo.put("suggestedTool", "analyze-program");
            analysisInfo.put("toolParameters", Map.of(
                "programPath", program.getDomainFile().getPathname(),
                "force", false
            ));
        }

        // Add basic stats regardless of analysis state
        analysisInfo.put("functionCount", program.getFunctionManager().getFunctionCount());
        analysisInfo.put("symbolCount", program.getSymbolTable().getNumSymbols());

        return analysisInfo;
    }

    /**
     * Create a standardized analysis hint for tools that require analysis.
     * This method returns a hint with specific suggestions for the analyze-program tool.
     * 
     * @param program The program to check
     * @param toolName The name of the tool making the request (for context)
     * @return A detailed hint message if analysis is needed, null if no hint needed
     */
    public static String getAnalysisHintForTool(Program program, String toolName) {
        if (program == null) {
            return null;
        }

        boolean isAnalyzed = GhidraProgramUtilities.isAnalyzed(program);
        if (!isAnalyzed) {
            String programPath = program.getDomainFile().getPathname();
            return String.format(
                "The '%s' tool works best with analyzed programs. " +
                "Program '%s' has not been analyzed yet. " +
                "Use the 'analyze-program' tool with programPath: '%s' to run Ghidra analysis first.",
                toolName, programPath, programPath
            );
        }

        return null; // No hint needed
    }

    /**
     * Check if a program likely needs analysis for the requested operation.
     * This provides a heuristic for tools to decide whether to include analysis hints.
     * 
     * @param program The program to check
     * @param requiresDecompilation Whether the operation requires decompilation
     * @param requiresFunctions Whether the operation requires function analysis
     * @return true if analysis is recommended for this operation
     */
    public static boolean recommendsAnalysis(Program program, boolean requiresDecompilation, boolean requiresFunctions) {
        if (program == null) {
            return false;
        }

        boolean isAnalyzed = GhidraProgramUtilities.isAnalyzed(program);
        
        // If already analyzed, no need to recommend analysis
        if (isAnalyzed) {
            return false;
        }

        // If the operation requires specific analysis results, recommend analysis
        if (requiresDecompilation || requiresFunctions) {
            return true;
        }

        // For basic operations, analysis might not be necessary
        return false;
    }

    /**
     * Get a brief status message about the program's analysis state.
     * 
     * @param program The program to check
     * @return A brief status message suitable for inclusion in responses
     */
    public static String getAnalysisStatus(Program program) {
        if (program == null) {
            return "Program unavailable";
        }

        boolean isAnalyzed = GhidraProgramUtilities.isAnalyzed(program);
        if (isAnalyzed) {
            return "Program has been analyzed";
        } else {
            return "Program not yet analyzed";
        }
    }
}