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
import ghidra.program.model.address.AddressSpace;
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
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Pins the assumption the decompilation cache is built on: {@code Program.getModificationNumber()}
 * increases for every kind of program change, so a cache entry stamped with the number can be
 * validated without knowing which tool or edit source made the change.
 *
 * <p>Every test asserts that the change really happened (tool result not an error, or the name or
 * member really changed) before it asserts that the number moved, so a pass is meaningful.
 *
 * <p>{@code run-script} cannot be driven from this harness (the Python runtime is only wired up under
 * PyGhidra); that source is covered by {@code tests/test_run_script_modnumber_e2e.py}.
 */
public class ModificationNumberIntegrationTest extends RevaIntegrationTestBase {

    private static final long CALLER_ADDR = 0x01000600L;
    private static final long CALLEE_ADDR = 0x01000700L;

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

        // Make the program findable by the MCP tools (same pattern as DecompilerToolProviderIntegrationTest).
        LineMapFixture.openInTools(env, tool, serverManager, program);
    }

    private void renameCallee(String newName) throws Exception {
        LineMapFixture.renameFunction(program, callee, newName);
    }

    private void setPrototype(String functionName, String address, String signature) {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            // Read first (read-before-modify tracker), then measure only the edit.
            LineMapFixture.callJson(client, "get-decompilation", Map.of("programPath", programPath,
                "functionNameOrAddress", functionName));
            long before = program.getModificationNumber();
            JsonNode json = LineMapFixture.callJson(client, "set-function-prototype",
                Map.of("programPath", programPath, "location", address, "signature", signature));
            assertTrue("set-function-prototype should report success: " + json, json.get("success").asBoolean());
            assertTrue("modification number must move", program.getModificationNumber() > before);
        });
    }

    @Test
    public void testRevaEditToSameFunctionMovesNumber() throws Exception {
        setPrototype("caller", "0x01000600", "int caller(int count)");
        assertEquals("count", caller.getParameter(0).getName());
    }

    @Test
    public void testRevaEditToCalleeMovesNumber() throws Exception {
        setPrototype("callee", "0x01000700", "int callee(int value)");
        assertEquals("value", callee.getParameter(0).getName());
    }

    @Test
    public void testRevaCommentMovesNumber() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            long before = program.getModificationNumber();
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("addressOrSymbol", "0x01000600");
            args.put("commentType", "eol");
            args.put("comment", "cache mod-number comment");
            LineMapFixture.callJson(client, "set-comment", args);
            assertEquals("cache mod-number comment",
                program.getListing().getComment(ghidra.program.model.listing.CommentType.EOL,
                    caller.getEntryPoint()));
            assertTrue("modification number must move", program.getModificationNumber() > before);
        });
    }

    @Test
    public void testRevaBookmarkMovesNumber() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            long before = program.getModificationNumber();
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("addressOrSymbol", "0x01000600");
            args.put("type", "Note");
            args.put("category", "Analysis");
            args.put("comment", "cache mod-number bookmark");
            LineMapFixture.callJson(client, "set-bookmark", args);
            assertNotNull("bookmark must exist",
                program.getBookmarkManager().getBookmark(caller.getEntryPoint(), "Note", "Analysis"));
            assertTrue("modification number must move", program.getModificationNumber() > before);
        });
    }

    @Test
    public void testUndoMovesNumber() throws Exception {
        renameCallee("renamedOnce");
        assertTrue("rename must be undoable", program.canUndo());
        long before = program.getModificationNumber();
        program.undo();
        assertEquals("undo must revert the name", "callee", callee.getName());
        assertTrue("modification number must move on undo", program.getModificationNumber() > before);
    }

    @Test
    public void testRedoMovesNumber() throws Exception {
        renameCallee("renamedOnce");
        program.undo();
        assertEquals("callee", callee.getName());
        assertTrue("undone rename must be redoable", program.canRedo());
        long before = program.getModificationNumber();
        program.redo();
        assertEquals("redo must reapply the name", "renamedOnce", callee.getName());
        assertTrue("modification number must move on redo", program.getModificationNumber() > before);
    }

    @Test
    public void testChangeInsideOpenTransactionMovesNumber() throws Exception {
        int txId = program.startTransaction("Rename inside open transaction");
        try {
            long before = program.getModificationNumber();
            callee.setName("renamedInTx", SourceType.USER_DEFINED);
            assertEquals("renamedInTx", callee.getName());
            assertTrue("modification number must move before the transaction ends",
                program.getModificationNumber() > before);
        } finally {
            program.endTransaction(txId, true);
        }
    }

    @Test
    public void testDataTypeChangeMovesNumber() throws Exception {
        // Setup: a structure that caller uses as its parameter type.
        Structure struct = new StructureDataType("CacheStruct", 0);
        struct.add(IntegerDataType.dataType, "first", null);
        int setup = program.startTransaction("Create structure and use it");
        Structure resolved;
        try {
            resolved = (Structure) program.getDataTypeManager()
                .resolve(struct, DataTypeConflictHandler.REPLACE_HANDLER);
            DataType ptr = new PointerDataType(resolved, program.getDataTypeManager());
            caller.replaceParameters(
                List.of(new ParameterImpl("s", ptr, program)),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(setup, true);
        }
        int before0 = resolved.getNumComponents();

        long before = program.getModificationNumber();
        int txId = program.startTransaction("Add structure field");
        try {
            resolved.add(IntegerDataType.dataType, "second", null);
        } finally {
            program.endTransaction(txId, true);
        }
        assertEquals("field must have been added", before0 + 1, resolved.getNumComponents());
        assertTrue("modification number must move", program.getModificationNumber() > before);
    }
}
