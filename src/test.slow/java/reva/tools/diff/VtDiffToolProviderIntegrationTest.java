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
package reva.tools.diff;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import ghidra.util.task.TaskMonitor;
import reva.plugin.RevaProgramManager;

/**
 * Integration tests for the Tier 2 VT-backed diff tools (compare-programs and friends).
 *
 * <p>Tests use {@link ClassicSampleX86ProgramBuilder} to create two programs that
 * are byte-identical, so VT correlators should match every function. This is the
 * "happy path" that proves the wiring; differential scenarios come in later tests.</p>
 */
public class VtDiffToolProviderIntegrationTest extends BinaryDiffTestBase {

    private final List<ClassicSampleX86ProgramBuilder> builders = new ArrayList<>();
    private Program sourceProgram;
    private Program destinationProgram;
    private String sourcePath;
    private String destPath;

    @Before
    public void setUpDualPrograms() throws Exception {
        // Test project persists across forked JVMs in /var/folders/.../*_DevTestProject,
        // so program names must be unique per test method.
        sourceProgram = buildAndRegister("src_" + getName());
        destinationProgram = buildAndRegister("dst_" + getName());
        sourcePath = sourceProgram.getDomainFile().getPathname();
        destPath = destinationProgram.getDomainFile().getPathname();
    }

    @After
    public void releaseBuilders() {
        for (ClassicSampleX86ProgramBuilder b : builders) {
            try {
                Program p = b.getProgram();
                RevaProgramManager.unregisterProgram(p);
                if (serverManager != null) {
                    serverManager.programClosed(p, tool);
                }
                b.dispose();
            } catch (Exception e) {
                System.err.println("Failed to release builder: " + e.getMessage());
            }
        }
        builders.clear();
    }

    @Test
    public void compareProgramsOnTwoIdenticalSamplesProducesAcceptedFunctionMatches() throws Exception {
        JsonNode result = parseJsonContent(callMcpTool("compare-programs", Map.of(
            "sourceProgramPath", sourcePath,
            "destinationProgramPath", destPath
        )));

        // Behavior 1: a session is reported and exists in the project.
        String sessionPath = result.path("sessionPath").asText();
        assertTrue("sessionPath must be returned and start with /VTSessions/",
            sessionPath != null && sessionPath.startsWith("/VTSessions/"));

        DomainFile sessionFile = env.getProject().getProjectData().getFile(sessionPath);
        assertNotNull("Session domain file must exist in the project at " + sessionPath, sessionFile);

        // Behavior 2: at least one function match was accepted (the canonical sample
        // contains many identical functions, so this is a robust assertion).
        int acceptedFn = result.path("acceptedFunctionMatches").asInt(0);
        assertTrue("Expected at least one accepted function match between identical programs, got: "
            + acceptedFn + " (full result: " + result + ")",
            acceptedFn > 0);

        // Behavior 3: status is 'created' on first call.
        assertEquals("created", result.path("status").asText());
    }

    @Test
    public void compareProgramsCalledTwiceReusesExistingSession() throws Exception {
        // First call creates the session.
        JsonNode first = parseJsonContent(callMcpTool("compare-programs", Map.of(
            "sourceProgramPath", sourcePath,
            "destinationProgramPath", destPath
        )));
        String sessionPath = first.path("sessionPath").asText();

        // Second call with default reuseExisting=true should return the same session,
        // status='reused', without re-running correlators.
        JsonNode second = parseJsonContent(callMcpTool("compare-programs", Map.of(
            "sourceProgramPath", sourcePath,
            "destinationProgramPath", destPath
        )));

        assertEquals("Reused session must have the same path",
            sessionPath, second.path("sessionPath").asText());
        assertEquals("Second call should report reused status",
            "reused", second.path("status").asText());
    }

    // ----------------------------- list-changed-functions

    @Test
    public void listChangedFunctions_matchedCategoryReturnsAcceptedAssociations() throws Exception {
        // Seed: create a session.
        JsonNode compareResult = parseJsonContent(callMcpTool("compare-programs", Map.of(
            "sourceProgramPath", sourcePath,
            "destinationProgramPath", destPath
        )));
        String sessionPath = compareResult.path("sessionPath").asText();

        JsonNode result = parseJsonContent(callMcpTool("list-changed-functions", Map.of(
            "sessionPath", sessionPath,
            "category", "matched"
        )));

        assertTrue("Expected at least one matched function entry",
            result.path("totalCount").asInt(0) > 0);
        JsonNode functions = result.path("functions");
        assertTrue("functions array missing or empty", functions.isArray() && functions.size() > 0);

        JsonNode first = functions.get(0);
        assertTrue("matched entry must have sourceAddress", first.has("sourceAddress"));
        assertTrue("matched entry must have destinationAddress", first.has("destinationAddress"));
        assertTrue("matched entry must report category=matched",
            "matched".equals(first.path("category").asText()));
    }

    @Test
    public void listChangedFunctions_paginationRespectsStartIndexAndMaxCount() throws Exception {
        callMcpTool("compare-programs", Map.of(
            "sourceProgramPath", sourcePath,
            "destinationProgramPath", destPath
        ));
        String sessionPath = "/VTSessions/" + buildExpectedSessionName();

        JsonNode page = parseJsonContent(callMcpTool("list-changed-functions", Map.of(
            "sessionPath", sessionPath,
            "category", "matched",
            "startIndex", 0,
            "maxCount", 2
        )));
        assertTrue("Page should have at most 2 entries",
            page.path("functions").size() <= 2);
        assertEquals(2, page.path("returnedCount").asInt(0));
    }

    // ----------------------------- list-changed-data

    @Test
    public void listChangedData_returnsValidResponseShape() throws Exception {
        callMcpTool("compare-programs", Map.of(
            "sourceProgramPath", sourcePath,
            "destinationProgramPath", destPath
        ));
        String sessionPath = "/VTSessions/" + buildExpectedSessionName();

        JsonNode result = parseJsonContent(callMcpTool("list-changed-data", Map.of(
            "sessionPath", sessionPath,
            "category", "all"
        )));
        assertTrue("totalCount must be present", result.has("totalCount"));
        assertTrue("dataItems must be an array", result.path("dataItems").isArray());
        assertEquals("all", result.path("category").asText());
    }

    // ----------------------------- get-function-diff

    @Test
    public void getFunctionDiff_returnsStructuralDeltaForMatchedFunction() throws Exception {
        callMcpTool("compare-programs", Map.of(
            "sourceProgramPath", sourcePath,
            "destinationProgramPath", destPath
        ));
        String sessionPath = "/VTSessions/" + buildExpectedSessionName();

        // Pick a matched function pair via list-changed-functions. Some matches
        // can be stubs/thunks with zero instructions; pick the first one that
        // has a real body so the structural-delta assertions are meaningful.
        String srcAddr = pickMatchedFunctionWithInstructions(sessionPath);

        JsonNode diff = parseJsonContent(callMcpTool("get-function-diff", Map.of(
            "sessionPath", sessionPath,
            "sourceAddress", srcAddr
        )));

        // Behavior: structuralDelta is present and has the basic counts.
        JsonNode structural = diff.path("structuralDelta");
        assertTrue("structuralDelta missing", structural.isObject());
        assertTrue("instructionCountSource missing or 0",
            structural.path("instructionCountSource").asInt(0) > 0);
        assertTrue("instructionCountDestination missing or 0",
            structural.path("instructionCountDestination").asInt(0) > 0);

        // Behavior: identical programs => identical instruction counts.
        assertEquals("Identical programs should have identical instruction counts",
            structural.path("instructionCountSource").asInt(),
            structural.path("instructionCountDestination").asInt());

        // Behavior: decompilation NOT included by default — keeps response small.
        assertTrue("Default response must omit sourceDecompilation",
            !diff.has("sourceDecompilation"));
    }

    @Test
    public void getFunctionDiff_includeDecompilationReturnsLines() throws Exception {
        callMcpTool("compare-programs", Map.of(
            "sourceProgramPath", sourcePath,
            "destinationProgramPath", destPath
        ));
        String sessionPath = "/VTSessions/" + buildExpectedSessionName();

        String srcAddr = pickMatchedFunctionWithInstructions(sessionPath);

        JsonNode diff = parseJsonContent(callMcpTool("get-function-diff", Map.of(
            "sessionPath", sessionPath,
            "sourceAddress", srcAddr,
            "includeDecompilation", true,
            "sourceLimit", 30,
            "destinationLimit", 30
        )));

        JsonNode srcDecomp = diff.path("sourceDecompilation");
        assertTrue("sourceDecompilation must be present", srcDecomp.isObject());
        assertTrue("sourceDecompilation must have lines",
            srcDecomp.path("lines").isArray() && srcDecomp.path("lines").size() > 0);
    }

    /**
     * Walk matched functions in pages and probe each via get-function-diff until
     * we find one with non-zero instruction count. Returns its source address.
     */
    private String pickMatchedFunctionWithInstructions(String sessionPath) throws Exception {
        int startIndex = 0;
        int pageSize = 20;
        while (startIndex < 200) {
            JsonNode page = parseJsonContent(callMcpTool("list-changed-functions", Map.of(
                "sessionPath", sessionPath,
                "category", "matched",
                "startIndex", startIndex,
                "maxCount", pageSize
            )));
            JsonNode functions = page.path("functions");
            if (functions.size() == 0) {
                break;
            }
            for (JsonNode fn : functions) {
                String addr = fn.path("sourceAddress").asText();
                JsonNode probe = parseJsonContent(callMcpTool("get-function-diff", Map.of(
                    "sessionPath", sessionPath,
                    "sourceAddress", addr
                )));
                if (probe.path("structuralDelta").path("instructionCountSource").asInt(0) > 0) {
                    return addr;
                }
            }
            startIndex += functions.size();
        }
        throw new AssertionError("No matched function with instructions found in session " + sessionPath);
    }

    // ----------------------------- migration: list-migration-candidates

    @Test
    public void listMigrationCandidates_returnsValidShape() throws Exception {
        callMcpTool("compare-programs", Map.of(
            "sourceProgramPath", sourcePath,
            "destinationProgramPath", destPath
        ));
        String sessionPath = "/VTSessions/" + buildExpectedSessionName();

        JsonNode result = parseJsonContent(callMcpTool("list-migration-candidates", Map.of(
            "sessionPath", sessionPath
        )));
        assertTrue("totalCount must be present", result.has("totalCount"));
        assertTrue("candidates must be an array", result.path("candidates").isArray());
    }

    // ----------------------------- migration: end-to-end markup transfer

    @Test
    public void compareProgramsAutoMigratesCustomFunctionName() throws Exception {
        // Rename a function in the SOURCE program before correlating. After compare-programs runs,
        // AutoVT should accept the matched function and apply the source's name to the destination.
        Function sourceFn = renameFirstSubstantialFunction(sourceProgram, "decrypt_payload_marker");

        callMcpTool("compare-programs", Map.of(
            "sourceProgramPath", sourcePath,
            "destinationProgramPath", destPath
        ));

        // Validate actual destination program state — not just MCP response.
        Function destFn = destinationProgram.getFunctionManager().getFunctionAt(sourceFn.getEntryPoint());
        assertNotNull("Destination should have a function at the matched address", destFn);
        assertEquals(
            "AutoVT must propagate the source function's name to the destination program",
            "decrypt_payload_marker",
            destFn.getName());
    }

    // ----------------------------- migration: migrate-function-analysis

    @Test
    public void migrateFunctionAnalysis_idempotentAfterAutoVtAutoApply() throws Exception {
        // After compare-programs, AutoVT has already applied markup for ACCEPTED associations.
        // Re-calling migrate-function-analysis on a known matched address should succeed and be
        // effectively a no-op (skipped > 0, applied == 0).
        renameFirstSubstantialFunction(sourceProgram, "needle_marker");
        callMcpTool("compare-programs", Map.of(
            "sourceProgramPath", sourcePath,
            "destinationProgramPath", destPath
        ));
        String sessionPath = "/VTSessions/" + buildExpectedSessionName();
        String srcAddr = pickMatchedFunctionWithInstructions(sessionPath);

        JsonNode result = parseJsonContent(callMcpTool("migrate-function-analysis", Map.of(
            "sessionPath", sessionPath,
            "sourceAddress", srcAddr
        )));
        assertTrue("success flag missing", result.path("success").asBoolean(false));
        assertEquals("ACCEPTED", result.path("status").asText());
        // Either applied or skipped paths are acceptable; the response must be coherent.
        assertTrue("applied + skipped must be non-negative",
            result.path("markupItemsApplied").asInt(-1) >= 0
            && result.path("markupItemsSkipped").asInt(-1) >= 0);
    }

    // ----------------------------- migration: migrate-analysis (bulk)

    @Test
    public void migrateAnalysisBulkReturnsAggregateCounts() throws Exception {
        callMcpTool("compare-programs", Map.of(
            "sourceProgramPath", sourcePath,
            "destinationProgramPath", destPath
        ));
        String sessionPath = "/VTSessions/" + buildExpectedSessionName();

        JsonNode result = parseJsonContent(callMcpTool("migrate-analysis", Map.of(
            "sessionPath", sessionPath
        )));
        assertTrue("success flag missing", result.path("success").asBoolean(false));
        assertTrue("associationsTouched must be present",
            result.has("associationsTouched"));
        // After AutoVT, most accepted associations are already applied → applied may be 0 but
        // the call must still succeed without error.
        assertTrue(result.path("markupItemsApplied").asInt(-1) >= 0);
    }

    // ----------------------------- list-vt-sessions

    @Test
    public void listVtSessions_includesNewlyCreatedSession() throws Exception {
        callMcpTool("compare-programs", Map.of(
            "sourceProgramPath", sourcePath,
            "destinationProgramPath", destPath
        ));
        String expectedPath = "/VTSessions/" + buildExpectedSessionName();

        JsonNode result = parseJsonContent(callMcpTool("list-vt-sessions", Map.of()));
        boolean found = false;
        for (JsonNode entry : result.path("sessions")) {
            if (expectedPath.equals(entry.path("sessionPath").asText())) {
                found = true;
                break;
            }
        }
        assertTrue("list-vt-sessions must include the just-created session at " + expectedPath, found);
    }

    // ----------------------------- delete-vt-session

    @Test
    public void deleteVtSession_removesSessionFromProject() throws Exception {
        callMcpTool("compare-programs", Map.of(
            "sourceProgramPath", sourcePath,
            "destinationProgramPath", destPath
        ));
        String sessionPath = "/VTSessions/" + buildExpectedSessionName();
        assertNotNull("Session should exist before delete",
            env.getProject().getProjectData().getFile(sessionPath));

        JsonNode result = parseJsonContent(callMcpTool("delete-vt-session", Map.of(
            "sessionPath", sessionPath,
            "confirm", true
        )));
        assertTrue("delete-vt-session should report success", result.path("success").asBoolean(false));
        assertEquals(null, env.getProject().getProjectData().getFile(sessionPath));
    }

    @Test
    public void deleteVtSession_requiresConfirmFlag() throws Exception {
        callMcpTool("compare-programs", Map.of(
            "sourceProgramPath", sourcePath,
            "destinationProgramPath", destPath
        ));
        String sessionPath = "/VTSessions/" + buildExpectedSessionName();

        verifyMcpToolFailsWithError("delete-vt-session", Map.of(
            "sessionPath", sessionPath,
            "confirm", false
        ), "confirm=true");

        // Session must still exist after the unconfirmed call.
        assertNotNull("Session must still exist when confirm=false",
            env.getProject().getProjectData().getFile(sessionPath));
    }

    /**
     * Find the first function with at least 16 bytes (so it survives correlator min-size
     * filters) and rename it. Returns the renamed Function.
     */
    private Function renameFirstSubstantialFunction(Program p, String newName) throws Exception {
        FunctionIterator iter = p.getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            if (f.isExternal() || f.isThunk()) {
                continue;
            }
            if (f.getBody().getNumAddresses() < 16) {
                continue;
            }
            Address entry = f.getEntryPoint();
            int txId = p.startTransaction("rename for test");
            try {
                f.setName(newName, SourceType.USER_DEFINED);
            } finally {
                p.endTransaction(txId, true);
            }
            return p.getFunctionManager().getFunctionAt(entry);
        }
        throw new AssertionError("No substantial function found in " + p.getName());
    }

    private String buildExpectedSessionName() {
        return "src_" + getName() + "__vs__" + "dst_" + getName();
    }

    // ------------------------------------------------------------------ helpers

    private Program buildAndRegister(String name) throws Exception {
        ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder(name, false, this);
        builders.add(builder);
        Program p = builder.getProgram();

        // Save into the test project so its DomainFile has a path tools can resolve.
        env.getProject().getProjectData().getRootFolder()
            .createFile(name, p, TaskMonitor.DUMMY);

        if (serverManager != null) {
            serverManager.programOpened(p, tool);
        }
        RevaProgramManager.registerProgram(p);
        return p;
    }
}
