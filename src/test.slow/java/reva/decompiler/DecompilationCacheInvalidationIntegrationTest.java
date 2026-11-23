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

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.client.McpSyncClient;
import reva.RevaIntegrationTestBase;

/**
 * One test per change source of {@link ModificationNumberIntegrationTest}: after the change a read of
 * {@code caller} must decompile afresh (a decompile delta of at least one) and show the change wherever it is
 * visible in the C text. {@code run-script} is covered by {@code tests/test_decompilation_cache_e2e.py}.
 */
public class DecompilationCacheInvalidationIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;
    private Function caller;
    private Function callee;

    @Before
    public void setUp() throws Exception {
        programPath = program.getDomainFile().getPathname();
        Function[] created = LineMapFixture.createCallerAndCallee(program);
        caller = created[0];
        callee = created[1];
        assertNotNull(caller);
        assertNotNull(callee);

        LineMapFixture.openInTools(env, tool, serverManager, program);
    }

    private interface Body {
        void run(McpSyncClient client) throws Exception;
    }

    private void withClient(Body body) throws Exception {
        withMcpClient(createMcpTransport(), (McpClientFunction<Void>) client -> {
            client.initialize();
            body.run(client);
            return null;
        });
    }

    /** Result of one read: the C text and how many decompiles the read cost. */
    private record Read(String text, long decompiles) {}

    private Read read(McpSyncClient client, String functionName) {
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", programPath);
        args.put("functionNameOrAddress", functionName);
        args.put("includeIncomingReferences", false);
        args.put("limit", 200);
        JsonNode[] json = new JsonNode[1];
        long delta = LineMapFixture.decompilesDuring(
            () -> json[0] = LineMapFixture.callJson(client, "get-decompilation", args));
        return new Read(json[0].get("decompilation").asText(), delta);
    }

    /** Reads caller twice so the first read is certainly cached, and returns its text. */
    private String warmCaller(McpSyncClient client) {
        Read first = read(client, "caller");
        Read second = read(client, "caller");
        assertEquals("Second read of an unchanged program is a hit", 0, second.decompiles());
        assertEquals(first.text(), second.text());
        return first.text();
    }

    private void renameCallee(String newName) throws Exception {
        LineMapFixture.renameFunction(program, callee, newName);
    }

    @Test
    public void testFreshTextAfterRevaEditToSameFunction() throws Exception {
        withClient(client -> {
            String before = warmCaller(client);
            assertFalse(before.contains("count"));
            LineMapFixture.setPrototype(client, programPath, "caller", "0x01000600", "int caller(int count)");
            assertEquals("count", caller.getParameter(0).getName());
            Read after = read(client, "caller");
            assertTrue("Fresh decompile expected", after.decompiles() >= 1);
            assertTrue("Text should show the new parameter: " + after.text(), after.text().contains("int count"));
        });
    }

    @Test
    public void testFreshTextAfterRevaEditToCallee() throws Exception {
        withClient(client -> {
            String before = warmCaller(client);
            LineMapFixture.setPrototype(client, programPath, "callee", "0x01000700", "int callee(int value)");
            assertEquals("value", callee.getParameter(0).getName());
            Read after = read(client, "caller");
            assertTrue("Fresh decompile expected", after.decompiles() >= 1);
            assertNotEquals("The call site should reflect the callee prototype", before, after.text());
            assertTrue("Call site should still call callee: " + after.text(), after.text().contains("callee("));
        });
    }

    @Test
    public void testFreshTextAfterRevaComment() throws Exception {
        withClient(client -> {
            warmCaller(client);
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("addressOrSymbol", "0x01000603");
            args.put("commentType", "pre");
            args.put("comment", "cache invalidation comment");
            LineMapFixture.callJson(client, "set-comment", args);
            Read after = read(client, "caller");
            assertTrue("Fresh decompile expected", after.decompiles() >= 1);
            assertTrue("Text shows the PRE comment: " + after.text(),
                after.text().contains("cache invalidation comment"));
            assertTrue("Text still calls callee: " + after.text(), after.text().contains("callee"));
        });
    }

    @Test
    public void testFreshTextAfterRevaBookmark() throws Exception {
        withClient(client -> {
            warmCaller(client);
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("addressOrSymbol", "0x01000600");
            args.put("type", "Note");
            args.put("category", "Analysis");
            args.put("comment", "cache invalidation bookmark");
            LineMapFixture.callJson(client, "set-bookmark", args);
            assertNotNull(program.getBookmarkManager().getBookmark(caller.getEntryPoint(), "Note", "Analysis"));
            Read after = read(client, "caller");
            assertTrue("Fresh decompile expected", after.decompiles() >= 1);
            assertTrue("Text is still the function: " + after.text(), after.text().contains("caller"));
            assertTrue("Text still calls callee: " + after.text(), after.text().contains("callee"));
        });
    }

    @Test
    public void testFreshTextAfterUndo() throws Exception {
        withClient(client -> {
            String original = warmCaller(client);
            renameCallee("renamedOnce");
            String renamed = read(client, "caller").text();
            assertTrue("Rename visible: " + renamed, renamed.contains("renamedOnce"));
            warmCaller(client);

            assertTrue(program.canUndo());
            program.undo();
            assertEquals("callee", callee.getName());
            Read after = read(client, "caller");
            assertTrue("Fresh decompile expected", after.decompiles() >= 1);
            assertEquals("Undo restores the original text", original, after.text());
        });
    }

    @Test
    public void testFreshTextAfterRedo() throws Exception {
        withClient(client -> {
            warmCaller(client);
            renameCallee("renamedOnce");
            String renamed = read(client, "caller").text();
            program.undo();
            assertEquals("callee", callee.getName());
            String undone = warmCaller(client);
            assertNotEquals(renamed, undone);

            assertTrue(program.canRedo());
            program.redo();
            assertEquals("renamedOnce", callee.getName());
            Read after = read(client, "caller");
            assertTrue("Fresh decompile expected", after.decompiles() >= 1);
            assertEquals("Redo restores the changed text", renamed, after.text());
        });
    }

    @Test
    public void testFreshTextAfterChangeInsideOpenTransaction() throws Exception {
        withClient(client -> {
            warmCaller(client);
            int txId = program.startTransaction("Rename inside open transaction");
            boolean ended = false;
            try {
                callee.setName("renamedInTx", SourceType.USER_DEFINED);
                Read during = read(client, "caller");
                assertTrue("Fresh decompile expected", during.decompiles() >= 1);
                assertTrue("Read inside the open transaction sees the rename: " + during.text(),
                    during.text().contains("renamedInTx"));
                program.endTransaction(txId, true);
                ended = true;
            } finally {
                if (!ended) {
                    program.endTransaction(txId, true);
                }
            }
            Read after = read(client, "caller");
            assertTrue("Text after the transaction ends still shows the rename: " + after.text(),
                after.text().contains("renamedInTx"));
        });
    }

    @Test
    public void testFreshTextAfterRolledBackTransaction() throws Exception {
        withClient(client -> {
            String original = warmCaller(client);
            int txId = program.startTransaction("Rename, then roll back");
            boolean ended = false;
            try {
                callee.setName("rolledBackName", SourceType.USER_DEFINED);
                Read during = read(client, "caller");
                assertTrue("Fresh decompile inside the transaction", during.decompiles() >= 1);
                assertTrue("Read inside the transaction sees the rename: " + during.text(),
                    during.text().contains("rolledBackName"));
                program.endTransaction(txId, false);
                ended = true;
            } finally {
                if (!ended) {
                    program.endTransaction(txId, false);
                }
            }
            assertEquals("The rollback restored the name", "callee", callee.getName());
            Read after = read(client, "caller");
            assertTrue("Fresh decompile after the rollback", after.decompiles() >= 1);
            assertEquals("The rollback restores the original text", original, after.text());
        });
    }

    @Test
    public void testFreshTextAfterDataTypeChange() throws Exception {
        Structure struct = new StructureDataType("CacheStruct", 0);
        struct.add(IntegerDataType.dataType, "first", null);
        Structure resolved;
        int setup = program.startTransaction("Create structure and use it");
        try {
            resolved = (Structure) program.getDataTypeManager()
                .resolve(struct, DataTypeConflictHandler.REPLACE_HANDLER);
            DataType ptr = new PointerDataType(resolved, program.getDataTypeManager());
            caller.replaceParameters(List.of(new ParameterImpl("s", ptr, program)),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(setup, true);
        }
        withClient(client -> {
            String before = warmCaller(client);
            assertTrue("Parameter type visible: " + before, before.contains("CacheStruct"));

            // A member added to the structure (the text need not change, but the entry must not be reused).
            int addTx = program.startTransaction("Add structure field");
            try {
                resolved.add(IntegerDataType.dataType, "second", null);
            } finally {
                program.endTransaction(addTx, true);
            }
            Read afterAdd = read(client, "caller");
            assertTrue("Fresh decompile after adding a member", afterAdd.decompiles() >= 1);
            assertTrue(afterAdd.text().contains("CacheStruct"));

            // A rename of the data type is visible in the C text.
            int renameTx = program.startTransaction("Rename structure");
            try {
                resolved.setName("RenamedCacheStruct");
            } finally {
                program.endTransaction(renameTx, true);
            }
            Read afterRename = read(client, "caller");
            assertTrue("Fresh decompile after renaming the type", afterRename.decompiles() >= 1);
            assertTrue("Text shows the renamed type: " + afterRename.text(),
                afterRename.text().contains("RenamedCacheStruct"));
        });
    }

    @Test
    public void testFreshTextAfterFunctionDeletedAndRecreated() throws Exception {
        withClient(client -> {
            String before = warmCaller(client);
            assertTrue(before.contains("callee"));

            Address entry = caller.getEntryPoint();
            Address end = entry.add(9);
            // PUSH EBP ; MOV EBP,ESP ; MOV dword ptr [0x01000900],7 ; POP EBP ; RET
            byte[] body = {
                (byte) 0x55, (byte) 0x89, (byte) 0xe5,
                (byte) 0xc7, 0x05, 0x00, 0x09, 0x00, 0x01, 0x07, 0x00, 0x00, 0x00,
                (byte) 0x5d, (byte) 0xc3};
            int txId = program.startTransaction("Delete and recreate caller");
            try {
                FunctionManager fm = program.getFunctionManager();
                fm.removeFunction(entry);
                program.getListing().clearCodeUnits(entry, end, false);
                program.getMemory().setBytes(entry, body);
                new DisassembleCommand(entry, null, true).applyTo(program, TaskMonitor.DUMMY);
                fm.createFunction("caller", entry, new AddressSet(entry, entry.add(body.length - 1)),
                    SourceType.USER_DEFINED);
            } finally {
                program.endTransaction(txId, true);
            }
            Read after = read(client, "caller");
            assertTrue("Fresh decompile expected", after.decompiles() >= 1);
            assertFalse("Old call must be gone: " + after.text(), after.text().contains("callee"));
            assertTrue("New body shows the store of 7: " + after.text(), after.text().contains("DAT_01000900 = 7;"));
        });
    }
}
