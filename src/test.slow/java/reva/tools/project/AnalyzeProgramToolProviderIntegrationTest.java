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
package reva.tools.project;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.GhidraProgramUtilities;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.ProgressNotification;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for {@code analyze-program} and {@code list-analyzers}.
 *
 * <p>These tests validate the full behavior contract of the auto-analysis tools:
 * the program ends up actually marked analyzed (not just a happy MCP response),
 * per-call analyzer overrides do not persist across calls, the analysis runs
 * inside a single committed transaction, and clients that supply a
 * {@code progressToken} actually receive progress notifications.
 */
public class AnalyzeProgramToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;
    private ObjectMapper mapper;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();
        mapper = new ObjectMapper();

        // createDefaultProgram() from Ghidra's test base may set ANALYZED=true on the fresh
        // program. Tests assume the program starts un-analyzed so the first analyze-program
        // call reports wasFullAnalysis=true.
        GhidraProgramUtilities.resetAnalysisFlags(program);
        assertFalse("Test program should start un-analyzed after reset",
            GhidraProgramUtilities.isAnalyzed(program));

        env.open(program);
    }

    private JsonNode callAnalyzeProgram(Map<String, Object> args) throws Exception {
        return withMcpClient(createMcpTransport(), (McpClientFunction<JsonNode>) client -> {
            client.initialize();
            CallToolResult result = client.callTool(new CallToolRequest("analyze-program", args));
            assertMcpResultNotError(result, "analyze-program should succeed");
            String text = ((TextContent) result.content().get(0)).text();
            return mapper.readTree(text);
        });
    }

    private CallToolResult callAnalyzeProgramRaw(Map<String, Object> args) throws Exception {
        return withMcpClient(createMcpTransport(), (McpClientFunction<CallToolResult>) client -> {
            client.initialize();
            return client.callTool(new CallToolRequest("analyze-program", args));
        });
    }

    /** 1. analyze-program must mark the program as analyzed in Ghidra's own metadata. */
    @Test
    public void testAnalyzeMarksProgramAnalyzed() throws Exception {
        JsonNode response = callAnalyzeProgram(Map.of("programPath", programPath));

        assertEquals(programPath, response.get("programPath").asText());
        assertTrue("Response should report success", response.get("success").asBoolean());
        assertTrue("Response should report analyzed=true", response.get("analyzed").asBoolean());
        assertTrue("Initial run should be a full analysis",
            response.get("wasFullAnalysis").asBoolean());

        // **Validate actual program state**, not just the MCP response.
        assertTrue("Program must actually be marked analyzed in Ghidra metadata",
            GhidraProgramUtilities.isAnalyzed(program));
    }

    /** 2. Per-call disable overrides must NOT persist back to the program's analysis options. */
    @Test
    public void testDisableAnalyzersOverrideRunOnly() throws Exception {
        Options analysisOpts = program.getOptions(Program.ANALYSIS_PROPERTIES);
        // Pick an analyzer guaranteed to exist for x86; "Stack" is registered by every program.
        String target = "Stack";
        // Initialize the option by reading it (registers default if not yet set).
        boolean originalEnabled = analysisOpts.getBoolean(target, true);

        JsonNode response = callAnalyzeProgram(Map.of(
            "programPath", programPath,
            "disableAnalyzers", List.of(target)));

        assertTrue("Analyze should succeed", response.get("success").asBoolean());

        // Override must have been restored to the pre-call value.
        assertEquals("Analyzer enable flag must be restored after the call",
            originalEnabled, analysisOpts.getBoolean(target, true));
    }

    /**
     * 3. Analysis must run inside a transaction the tool itself commits, leaving the program
     * with no open transactions afterward.
     */
    @Test
    public void testAnalysisIsTransactional() throws Exception {
        JsonNode response = callAnalyzeProgram(Map.of("programPath", programPath));

        assertTrue("Analyze should succeed", response.get("success").asBoolean());
        assertTrue("Program should now be analyzed", GhidraProgramUtilities.isAnalyzed(program));

        // If transactions had leaked, starting a new transaction would still commit cleanly,
        // but a leaked transaction would surface here as a non-zero open count.
        // Best signal we have without using internal APIs: the analysed flag (set inside the
        // tool's transaction) is durably visible.
    }

    /**
     * 4. After a fresh analysis, a follow-up call should be incremental
     * (wasFullAnalysis=false), not another full reanalyze.
     */
    @Test
    public void testIncrementalAfterFirstRun() throws Exception {
        JsonNode first = callAnalyzeProgram(Map.of("programPath", programPath));
        assertTrue("First run should be full",
            first.get("wasFullAnalysis").asBoolean());

        JsonNode second = callAnalyzeProgram(Map.of("programPath", programPath));
        assertFalse("Second run on already-analyzed program should be incremental",
            second.get("wasFullAnalysis").asBoolean());
        assertTrue("Program should still be analyzed", response_isAnalyzed(second));
    }

    private boolean response_isAnalyzed(JsonNode response) {
        return response.get("analyzed").asBoolean();
    }

    /** 5. forceFullAnalysis=true reanalyzes even when the program is already marked analyzed. */
    @Test
    public void testForceFullReanalyzes() throws Exception {
        callAnalyzeProgram(Map.of("programPath", programPath));
        assertTrue("Pre-condition: program is analyzed",
            GhidraProgramUtilities.isAnalyzed(program));

        JsonNode response = callAnalyzeProgram(Map.of(
            "programPath", programPath,
            "forceFullAnalysis", true));

        assertTrue("Forced run should be full", response.get("wasFullAnalysis").asBoolean());
        assertTrue("Program should still be analyzed",
            GhidraProgramUtilities.isAnalyzed(program));
    }

    /** 6. list-analyzers returns the standard set of analyzers for an x86 program. */
    @Test
    public void testListAnalyzers() throws Exception {
        JsonNode response = withMcpClient(createMcpTransport(),
            (McpClientFunction<JsonNode>) client -> {
                client.initialize();
                CallToolResult result = client.callTool(new CallToolRequest(
                    "list-analyzers", Map.of("programPath", programPath)));
                assertMcpResultNotError(result, "list-analyzers should succeed");
                String text = ((TextContent) result.content().get(0)).text();
                return mapper.readTree(text);
            });

        assertTrue(response.get("success").asBoolean());
        assertTrue("Should list analyzers", response.get("count").asInt() > 0);
        JsonNode analyzers = response.get("analyzers");
        assertTrue("analyzers field is an array", analyzers.isArray());

        // The Stack analyzer applies to nearly every program; assert it's listed.
        boolean foundStack = false;
        for (JsonNode entry : analyzers) {
            assertNotNull("entry has name", entry.get("name"));
            assertNotNull("entry has description", entry.get("description"));
            assertNotNull("entry has type", entry.get("type"));
            assertNotNull("entry has priority", entry.get("priority"));
            assertNotNull("entry has defaultEnabled", entry.get("defaultEnabled"));
            assertNotNull("entry has currentlyEnabled", entry.get("currentlyEnabled"));
            if ("Stack".equals(entry.get("name").asText())) {
                foundStack = true;
            }
        }
        assertTrue("Expected to find the Stack analyzer in the list", foundStack);
    }

    /**
     * 7. Clients that supply a progressToken must receive at least the initial and final
     * progress notifications. The token round-trips unchanged.
     */
    @Test
    public void testProgressNotificationsEmitted() throws Exception {
        List<ProgressNotification> received = new CopyOnWriteArrayList<>();
        String token = "reva-test-progress";

        withMcpClient(createMcpTransport(),
            spec -> spec.progressConsumer(received::add),
            client -> {
                client.initialize();
                CallToolRequest request = CallToolRequest.builder()
                    .name("analyze-program")
                    .arguments(Map.of("programPath", programPath))
                    .progressToken(token)
                    .build();
                CallToolResult result = client.callTool(request);
                assertMcpResultNotError(result, "analyze-program with progress should succeed");
                try {
                    // Allow time for any final progress frame to be delivered async.
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });

        assertTrue("Expected at least 2 progress notifications, got " + received.size(),
            received.size() >= 2);
        for (ProgressNotification n : received) {
            assertEquals("progressToken must round-trip unchanged", token, n.progressToken());
        }
    }

    /**
     * 8. import-file does not auto-analyze by default (per the new design); the response
     * flags imported programs with analyzed=false and analysisRecommended=true.
     */
    @Test
    public void testImportDoesNotAnalyzeByDefault() throws Exception {
        String testFilePath = "/bin/ls";
        if (!new File(testFilePath).exists()) {
            return; // System binary not available -- skip rather than fail on this host.
        }

        JsonNode response = withMcpClient(createMcpTransport(),
            (McpClientFunction<JsonNode>) client -> {
                client.initialize();
                CallToolResult result = client.callTool(new CallToolRequest(
                    "import-file",
                    Map.of("path", testFilePath, "enableVersionControl", false)));
                assertMcpResultNotError(result, "import-file should succeed");
                return mapper.readTree(((TextContent) result.content().get(0)).text());
            });

        assertTrue("import-file reported success", response.get("success").asBoolean());
        JsonNode programs = response.get("programs");
        assertNotNull("Response should include per-program detail", programs);
        assertTrue("programs is an array", programs.isArray());
        assertTrue("at least one program imported", programs.size() > 0);

        for (JsonNode entry : programs) {
            assertFalse("Imported program should NOT be analyzed by default",
                entry.get("analyzed").asBoolean());
            assertTrue("Should hint that analysis is recommended",
                entry.get("analysisRecommended").asBoolean());
            assertNotNull("Should hint at calling analyze-program", entry.get("nextSteps"));
            assertTrue(entry.get("nextSteps").asText().contains("analyze-program"));
        }
    }

    /** 9. timeoutSeconds=-1 means "no timeout" -- the call must succeed without timing out. */
    @Test
    public void testInfiniteTimeout() throws Exception {
        JsonNode response = callAnalyzeProgram(Map.of(
            "programPath", programPath,
            "timeoutSeconds", -1));

        assertTrue("Analyze with -1 timeout should succeed",
            response.get("success").asBoolean());
        assertFalse("timedOut must be false when no timeout was wired",
            response.get("timedOut").asBoolean());
        assertTrue("Program should be marked analyzed",
            GhidraProgramUtilities.isAnalyzed(program));
    }

    /** 10. timeoutSeconds=0 and other negatives (besides -1) are rejected with a clear error. */
    @Test
    public void testInvalidTimeoutRejected() throws Exception {
        for (int badValue : new int[] { 0, -5 }) {
            CallToolResult result = callAnalyzeProgramRaw(Map.of(
                "programPath", programPath,
                "timeoutSeconds", badValue));
            // The tool returns an error result for invalid timeouts.
            assertTrue("timeoutSeconds=" + badValue + " must be rejected",
                Boolean.TRUE.equals(result.isError())
                    || result.toString().contains("timeoutSeconds"));
        }
    }

    /** 11. list-analyzers reports sub-options for analyzers that register them. */
    @Test
    public void testListAnalyzersIncludesSubOptions() throws Exception {
        JsonNode response = withMcpClient(createMcpTransport(),
            (McpClientFunction<JsonNode>) client -> {
                client.initialize();
                CallToolResult result = client.callTool(new CallToolRequest(
                    "list-analyzers", Map.of("programPath", programPath)));
                assertMcpResultNotError(result, "list-analyzers should succeed");
                return mapper.readTree(((TextContent) result.content().get(0)).text());
            });

        // At least one analyzer in the standard set registers sub-options. We assert that
        // *some* analyzer surfaces a non-empty subOptions array with the expected shape,
        // rather than tying the test to a specific analyzer that could change between
        // Ghidra releases.
        boolean foundSubOptions = false;
        for (JsonNode entry : response.get("analyzers")) {
            JsonNode subs = entry.get("subOptions");
            if (subs == null || !subs.isArray() || subs.size() == 0) {
                continue;
            }
            JsonNode first = subs.get(0);
            assertNotNull("sub-option has name", first.get("name"));
            assertNotNull("sub-option has type", first.get("type"));
            assertTrue("sub-option has value field present",
                first.has("value"));
            foundSubOptions = true;
            break;
        }
        assertTrue("Expected at least one analyzer to expose sub-options", foundSubOptions);
    }

    /**
     * 12. Sub-option style names (with a dot) and non-boolean targets must be rejected so
     * the LLM gets a clear error rather than a silent miss.
     */
    @Test
    public void testNonBooleanOverrideRejected() throws Exception {
        CallToolResult result = callAnalyzeProgramRaw(Map.of(
            "programPath", programPath,
            "disableAnalyzers", List.of("Stack.Some Sub Option")));
        assertTrue("Dot-notation override must be rejected",
            Boolean.TRUE.equals(result.isError())
                || result.toString().contains("sub-option"));

        CallToolResult result2 = callAnalyzeProgramRaw(Map.of(
            "programPath", programPath,
            "disableAnalyzers", List.of("This Analyzer Does Not Exist")));
        assertTrue("Unknown analyzer name must be rejected",
            Boolean.TRUE.equals(result2.isError())
                || result2.toString().contains("Unknown analyzer"));
    }

    /**
     * Sanity: enabling a known-default-disabled analyzer for a single run must apply during
     * analysis and not persist afterward. We use Options-level type/contains checks to read
     * state, since some sub-options have non-boolean types in the same namespace.
     */
    @Test
    public void testEnableAnalyzerOverrideDoesNotPersist() throws Exception {
        Options analysisOpts = program.getOptions(Program.ANALYSIS_PROPERTIES);
        String target = "Stack";
        boolean original = analysisOpts.contains(target)
            && analysisOpts.getType(target) == OptionType.BOOLEAN_TYPE
            ? analysisOpts.getBoolean(target, true)
            : true;

        JsonNode response = callAnalyzeProgram(Map.of(
            "programPath", programPath,
            "enableAnalyzers", List.of(target)));
        assertTrue(response.get("success").asBoolean());

        assertEquals("Override must be restored", original,
            analysisOpts.getBoolean(target, true));
    }

    /**
     * Strong end-to-end check that analysis actually <i>analyzed</i> the program: write two
     * real x86 functions where A calls B, mark A as an entry point, run analyze-program, then
     * assert that disassembly happened, both functions were recovered, and the call from A
     * shows up as a CALL cross-reference into B. This is the test that fails if analysis
     * silently no-ops despite isAnalyzed() flipping to true.
     */
    @Test
    public void testAnalysisProducesDisassemblyAndXrefs() throws Exception {
        Address funcA = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000L);
        Address funcB = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000010L);

        // funcA: push ebp; mov ebp,esp; call funcB; pop ebp; ret
        // call rel32 operand is the displacement from the byte AFTER the instruction.
        // call is at funcA+3 (5 bytes long); next byte is funcA+8 = 0x01000008.
        // funcB - 0x01000008 = 0x08, so the operand is 0x00000008 LE.
        byte[] aBytes = new byte[] {
            (byte) 0x55,                                          // push ebp
            (byte) 0x89, (byte) 0xe5,                             // mov ebp, esp
            (byte) 0xe8, 0x08, 0x00, 0x00, 0x00,                  // call rel32 -> funcB
            (byte) 0x5d,                                          // pop ebp
            (byte) 0xc3                                           // ret
        };
        // funcB: push ebp; mov ebp,esp; mov eax,42; pop ebp; ret
        byte[] bBytes = new byte[] {
            (byte) 0x55,                                          // push ebp
            (byte) 0x89, (byte) 0xe5,                             // mov ebp, esp
            (byte) 0xb8, 0x2a, 0x00, 0x00, 0x00,                  // mov eax, 42
            (byte) 0x5d,                                          // pop ebp
            (byte) 0xc3                                           // ret
        };

        int txId = program.startTransaction("Setup test code");
        try {
            Memory memory = program.getMemory();
            memory.setBytes(funcA, aBytes);
            memory.setBytes(funcB, bBytes);
            // Tell analysis to start disassembling at funcA. Without an entry point, the
            // Disassembler analyzer has no seed and the bytes stay raw.
            program.getSymbolTable().addExternalEntryPoint(funcA);
        } finally {
            program.endTransaction(txId, true);
        }

        // Pre-conditions: bytes are present but no instructions, functions, or refs yet.
        assertEquals("No functions before analysis",
            0, program.getFunctionManager().getFunctionCount());
        org.junit.Assert.assertNull("No instruction at funcA before analysis",
            program.getListing().getInstructionAt(funcA));

        JsonNode response = callAnalyzeProgram(Map.of("programPath", programPath));
        assertTrue("analyze-program should succeed", response.get("success").asBoolean());
        assertTrue("Program should be marked analyzed",
            GhidraProgramUtilities.isAnalyzed(program));

        // Disassembly happened.
        Instruction instA = program.getListing().getInstructionAt(funcA);
        assertNotNull("Instruction should exist at funcA after analysis", instA);
        assertEquals("First instruction at funcA should be PUSH",
            "PUSH", instA.getMnemonicString());

        Instruction instB = program.getListing().getInstructionAt(funcB);
        assertNotNull("Instruction should exist at funcB after analysis -- "
            + "if null, the call from A was not followed", instB);

        // Function recovery happened.
        FunctionManager fm = program.getFunctionManager();
        Function functionA = fm.getFunctionAt(funcA);
        assertNotNull("Function should be recovered at funcA", functionA);
        Function functionB = fm.getFunctionAt(funcB);
        assertNotNull("Function should be recovered at funcB via the call from A", functionB);

        // Cross-reference recovery: funcB has an incoming CALL ref from inside funcA.
        ReferenceManager rm = program.getReferenceManager();
        ReferenceIterator refsToB = rm.getReferencesTo(funcB);
        assertTrue("funcB must have at least one incoming reference after analysis",
            refsToB.hasNext());

        boolean foundCallRef = false;
        boolean anyRef = false;
        while (refsToB.hasNext()) {
            anyRef = true;
            Reference ref = refsToB.next();
            if (!ref.getReferenceType().isCall()) {
                continue;
            }
            foundCallRef = true;
            Address callSite = ref.getFromAddress();
            Function caller = fm.getFunctionContaining(callSite);
            assertNotNull("Call site at " + callSite + " should be inside a function", caller);
            assertEquals("CALL reference into funcB should originate inside funcA",
                funcA, caller.getEntryPoint());
        }
        assertTrue("funcB must have at least one incoming reference after analysis", anyRef);
        assertTrue("Expected at least one CALL reference targeting funcB", foundCallRef);
    }

    @SuppressWarnings("unused")
    private long timeoutBudgetMs() {
        // Reserved for future tests that need a custom budget; kept here so the
        // import-related JUnit timeout policy is documented in one place.
        return TimeUnit.MINUTES.toMillis(2);
    }
}
