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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;

/**
 * Integration tests for the Tier 1 cheap-diff tools.
 */
public class CheapDiffToolProviderIntegrationTest extends BinaryDiffTestBase {

    @Test
    public void diffProgramMetadata_identicalArchitecture_reportsNoArchitectureDifference() throws Exception {
        // The base-class `program` is x86:LE:32. Make a sibling with the same arch.
        Program programB = createAndOpenSecondProgram("programB_sameArch", "x86:LE:32:default");

        String json = callMcpTool("diff-program-metadata", Map.of(
            "programA", program.getDomainFile().getPathname(),
            "programB", programB.getDomainFile().getPathname()
        ));
        JsonNode result = parseJsonContent(json);

        // Both sides report the same languageId.
        assertEquals("x86:LE:32:default", result.path("programA").path("languageId").asText());
        assertEquals("x86:LE:32:default", result.path("programB").path("languageId").asText());

        // No 'languageId' field appears in the differences[] list when the architectures match.
        assertFalse("languageId must not be flagged as different when architectures match",
            differencesContainsField(result, "languageId"));
    }

    @Test
    public void diffProgramMetadata_differentArchitectures_surfacesLanguageIdDifference() throws Exception {
        Program programB = createAndOpenSecondProgram("programB_diffArch", "x86:LE:64:default");

        String json = callMcpTool("diff-program-metadata", Map.of(
            "programA", program.getDomainFile().getPathname(),
            "programB", programB.getDomainFile().getPathname()
        ));
        JsonNode result = parseJsonContent(json);

        assertTrue("Different architectures must surface a languageId difference",
            differencesContainsField(result, "languageId"));
    }

    @Test
    public void diffProgramMetadata_differentImageBase_surfacesImageBaseDifference() throws Exception {
        Program programB = createAndOpenSecondProgram("programB_rebased", "x86:LE:32:default");

        // Move programB's image base. This is one of the most diagnostic differences for
        // malware-variant analysis: rebased binaries cannot be sensibly compared address-for-address.
        Address newBase = programB.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000000);
        int txId = programB.startTransaction("rebase");
        try {
            programB.setImageBase(newBase, true);
        } finally {
            programB.endTransaction(txId, true);
        }

        String json = callMcpTool("diff-program-metadata", Map.of(
            "programA", program.getDomainFile().getPathname(),
            "programB", programB.getDomainFile().getPathname()
        ));
        JsonNode result = parseJsonContent(json);

        assertTrue("Image-base mismatch must be surfaced as a difference",
            differencesContainsField(result, "imageBase"));
    }

    // ========================================================================
    // diff-sections
    // ========================================================================

    @Test
    public void diffSections_classifiesBlocksAsOnlyInAOnlyInBAndCommon() throws Exception {
        Program programB = createAndOpenSecondProgram("programB_sections", "x86:LE:32:default");

        // The base 'test' block at 0x01000000 already exists in both programs.
        // Add a uniquely-named block to A and a different one to B.
        addBlock(program, "shared_extra", 0x02000000, 0x100);
        addBlock(programB, "shared_extra", 0x02000000, 0x100);   // same block in both
        addBlock(program, "only_in_a", 0x03000000, 0x100);
        addBlock(programB, "only_in_b", 0x04000000, 0x100);

        JsonNode result = parseJsonContent(callMcpTool("diff-sections", Map.of(
            "programA", program.getDomainFile().getPathname(),
            "programB", programB.getDomainFile().getPathname()
        )));

        assertContainsKey(result, "onlyInA", "only_in_a");
        assertContainsKey(result, "onlyInB", "only_in_b");
        assertContainsKey(result, "inBoth", "shared_extra");
        assertContainsKey(result, "inBoth", "test");
    }

    // ========================================================================
    // diff-symbols
    // ========================================================================

    @Test
    public void diffSymbols_classifiesUserDefinedLabels() throws Exception {
        Program programB = createAndOpenSecondProgram("programB_symbols", "x86:LE:32:default");
        addLabel(program, 0x01000010, "alpha_sym");
        addLabel(program, 0x01000020, "shared_sym");
        addLabel(programB, 0x01000020, "shared_sym");
        addLabel(programB, 0x01000030, "beta_sym");

        JsonNode result = parseJsonContent(callMcpTool("diff-symbols", Map.of(
            "programA", program.getDomainFile().getPathname(),
            "programB", programB.getDomainFile().getPathname()
        )));

        assertContainsKey(result, "onlyInA", "alpha_sym");
        assertContainsKey(result, "onlyInB", "beta_sym");
        assertContainsKey(result, "inBoth", "shared_sym");
    }

    // ========================================================================
    // diff-exports
    // ========================================================================

    @Test
    public void diffExports_classifiesExternalEntryPoints() throws Exception {
        Program programB = createAndOpenSecondProgram("programB_exports", "x86:LE:32:default");
        // Symbols at the export addresses make the entry-point names meaningful.
        addLabel(program, 0x01000040, "exp_a");
        addLabel(program, 0x01000050, "exp_shared");
        addLabel(programB, 0x01000050, "exp_shared");
        addLabel(programB, 0x01000060, "exp_b");
        addEntryPoint(program, 0x01000040);
        addEntryPoint(program, 0x01000050);
        addEntryPoint(programB, 0x01000050);
        addEntryPoint(programB, 0x01000060);

        JsonNode result = parseJsonContent(callMcpTool("diff-exports", Map.of(
            "programA", program.getDomainFile().getPathname(),
            "programB", programB.getDomainFile().getPathname()
        )));

        assertContainsKey(result, "onlyInA", "exp_a");
        assertContainsKey(result, "onlyInB", "exp_b");
        assertContainsKey(result, "inBoth", "exp_shared");
    }

    // ========================================================================
    // diff-strings
    // ========================================================================

    @Test
    public void diffStrings_classifiesDefinedStringValues() throws Exception {
        Program programB = createAndOpenSecondProgram("programB_strings", "x86:LE:32:default");
        addCStringAt(program, 0x01000080, "alpha_str");
        addCStringAt(program, 0x01000100, "shared_str");
        addCStringAt(programB, 0x01000080, "shared_str");
        addCStringAt(programB, 0x01000100, "beta_str");

        JsonNode result = parseJsonContent(callMcpTool("diff-strings", Map.of(
            "programA", program.getDomainFile().getPathname(),
            "programB", programB.getDomainFile().getPathname()
        )));

        assertContainsValue(result, "onlyInA", "alpha_str");
        assertContainsValue(result, "onlyInB", "beta_str");
        assertContainsValue(result, "inBoth", "shared_str");
    }

    // ========================================================================
    // diff-imports
    // ========================================================================

    @Test
    public void diffImports_classifiesExternalFunctions() throws Exception {
        Program programB = createAndOpenSecondProgram("programB_imports", "x86:LE:32:default");
        addExternalImport(program, "KERNEL32.dll", "CreateFileW");
        addExternalImport(program, "KERNEL32.dll", "ReadFile");      // shared
        addExternalImport(programB, "KERNEL32.dll", "ReadFile");
        addExternalImport(programB, "KERNEL32.dll", "WriteFile");

        JsonNode result = parseJsonContent(callMcpTool("diff-imports", Map.of(
            "programA", program.getDomainFile().getPathname(),
            "programB", programB.getDomainFile().getPathname()
        )));

        assertContainsKey(result, "onlyInA", "CreateFileW");
        assertContainsKey(result, "onlyInB", "WriteFile");
        assertContainsKey(result, "inBoth", "ReadFile");
    }

    // ========================================================================
    // Test data helpers
    // ========================================================================

    private static void addBlock(Program p, String name, long addr, int size) throws Exception {
        int txId = p.startTransaction("add block " + name);
        try {
            p.getMemory().createInitializedBlock(name,
                p.getAddressFactory().getDefaultAddressSpace().getAddress(addr),
                size, (byte) 0, TaskMonitor.DUMMY, false);
        } finally {
            p.endTransaction(txId, true);
        }
    }

    private static void addLabel(Program p, long addr, String name) throws Exception {
        int txId = p.startTransaction("add label " + name);
        try {
            SymbolTable st = p.getSymbolTable();
            st.createLabel(p.getAddressFactory().getDefaultAddressSpace().getAddress(addr),
                name, SourceType.USER_DEFINED);
        } finally {
            p.endTransaction(txId, true);
        }
    }

    private static void addEntryPoint(Program p, long addr) throws Exception {
        int txId = p.startTransaction("add entry");
        try {
            p.getSymbolTable().addExternalEntryPoint(
                p.getAddressFactory().getDefaultAddressSpace().getAddress(addr));
        } finally {
            p.endTransaction(txId, true);
        }
    }

    private static void addCStringAt(Program p, long addr, String value) throws Exception {
        int txId = p.startTransaction("add string " + value);
        try {
            Address a = p.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
            byte[] bytes = (value + "\0").getBytes("US-ASCII");
            p.getMemory().setBytes(a, bytes);
            p.getListing().createData(a, StringDataType.dataType, bytes.length);
        } finally {
            p.endTransaction(txId, true);
        }
    }

    private static void addExternalImport(Program p, String library, String symbolName) throws Exception {
        int txId = p.startTransaction("add import " + symbolName);
        try {
            p.getExternalManager().addExtFunction(library, symbolName, null, SourceType.IMPORTED);
        } finally {
            p.endTransaction(txId, true);
        }
    }

    private static void assertContainsKey(JsonNode result, String bucket, String name) {
        JsonNode arr = result.path(bucket);
        assertTrue("Expected " + bucket + " to be an array", arr.isArray());
        for (JsonNode entry : arr) {
            if (name.equals(entry.path("name").asText())) {
                return;
            }
        }
        throw new AssertionError("Expected " + bucket + " to contain entry with name '" + name + "', got: " + arr);
    }

    private static void assertContainsValue(JsonNode result, String bucket, String value) {
        JsonNode arr = result.path(bucket);
        assertTrue("Expected " + bucket + " to be an array", arr.isArray());
        for (JsonNode entry : arr) {
            if (value.equals(entry.path("value").asText())) {
                return;
            }
        }
        throw new AssertionError("Expected " + bucket + " to contain entry with value '" + value + "', got: " + arr);
    }

    private static boolean differencesContainsField(JsonNode result, String fieldName) {
        JsonNode differences = result.path("differences");
        if (!differences.isArray()) {
            return false;
        }
        for (JsonNode d : differences) {
            if (fieldName.equals(d.path("field").asText())) {
                return true;
            }
        }
        return false;
    }
}
