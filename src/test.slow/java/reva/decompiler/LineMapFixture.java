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

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.util.RevaInternalServiceRegistry;

/**
 * Shared fixture for the line-mapping and decompilation-cache integration tests: a small
 * hand-assembled x86 function and a helper that calls a tool and parses its JSON.
 */
public final class LineMapFixture {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private LineMapFixture() {
    }

    /**
     * Builds a function whose statements sit at known addresses:
     * <pre>
     *   0x01000500  PUSH EBP ; MOV EBP,ESP
     *   0x01000503  MOV dword ptr [0x01000900],1
     *   0x0100050d  CALL lineMapCalleeA
     *   0x01000512  MOV dword ptr [0x01000904],2
     *   0x0100051c  CALL lineMapCalleeB
     *   0x01000521  MOV dword ptr [0x01000908],3
     *   0x0100052b  POP EBP ; RET
     * </pre>
     */
    public static void createLineMapFunctions(Program program) throws Exception {
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Address fn = space.getAddress(0x01000500);
        Address calleeA = space.getAddress(0x01000600);
        Address calleeB = space.getAddress(0x01000620);
        byte[] body = {
            (byte) 0x55, (byte) 0x89, (byte) 0xe5,
            (byte) 0xc7, 0x05, 0x00, 0x09, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
            (byte) 0xe8, (byte) 0xee, 0x00, 0x00, 0x00,
            (byte) 0xc7, 0x05, 0x04, 0x09, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00,
            (byte) 0xe8, (byte) 0xff, 0x00, 0x00, 0x00,
            (byte) 0xc7, 0x05, 0x08, 0x09, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00,
            (byte) 0x5d, (byte) 0xc3};
        int txId = program.startTransaction("Create line-map functions");
        try {
            program.getMemory().setBytes(fn, body);
            program.getMemory().setBytes(calleeA, new byte[] {(byte) 0xc3});
            program.getMemory().setBytes(calleeB, new byte[] {(byte) 0xc3});
            for (Address start : List.of(calleeA, calleeB, fn)) {
                new DisassembleCommand(start, null, true).applyTo(program, TaskMonitor.DUMMY);
            }
            FunctionManager fm = program.getFunctionManager();
            fm.createFunction("lineMapCalleeA", calleeA, new AddressSet(calleeA, calleeA), SourceType.USER_DEFINED);
            fm.createFunction("lineMapCalleeB", calleeB, new AddressSet(calleeB, calleeB), SourceType.USER_DEFINED);
            fm.createFunction("lineMapFn", fn, new AddressSet(fn, fn.add(body.length - 1)), SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(txId, true);
        }
    }

    /**
     * Builds {@code tenTarget} (a lone RET at 0x01000700) and {@code tenCaller} (0x01000800) holding ten
     * {@code CALL tenTarget} instructions between {@code PUSH EBP ; MOV EBP,ESP} and {@code POP EBP ; RET}.
     */
    public static void createTenCallCaller(Program program) throws Exception {
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Address target = space.getAddress(0x01000700);
        Address caller = space.getAddress(0x01000800);
        int calls = 10;
        byte[] body = new byte[3 + 5 * calls + 2];
        body[0] = (byte) 0x55;
        body[1] = (byte) 0x89;
        body[2] = (byte) 0xe5;
        for (int i = 0; i < calls; i++) {
            int at = 3 + 5 * i;
            int rel = (int) (target.getOffset() - (caller.getOffset() + at + 5));
            body[at] = (byte) 0xe8;
            body[at + 1] = (byte) rel;
            body[at + 2] = (byte) (rel >> 8);
            body[at + 3] = (byte) (rel >> 16);
            body[at + 4] = (byte) (rel >> 24);
        }
        body[body.length - 2] = (byte) 0x5d;
        body[body.length - 1] = (byte) 0xc3;
        int txId = program.startTransaction("Create ten-call caller");
        try {
            program.getMemory().setBytes(target, new byte[] {(byte) 0xc3});
            program.getMemory().setBytes(caller, body);
            for (Address start : List.of(target, caller)) {
                new DisassembleCommand(start, null, true).applyTo(program, TaskMonitor.DUMMY);
            }
            FunctionManager fm = program.getFunctionManager();
            fm.createFunction("tenTarget", target, new AddressSet(target, target), SourceType.USER_DEFINED);
            fm.createFunction("tenCaller", caller, new AddressSet(caller, caller.add(body.length - 1)), SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(txId, true);
        }
    }

    public static final long CALLER_ADDR = 0x01000600L;
    public static final long CALLEE_ADDR = 0x01000700L;

    /**
     * Builds {@code caller} (0x01000600) calling {@code callee} (0x01000700):
     * {@code PUSH EBP ; MOV EBP,ESP ; CALL callee ; POP EBP ; RET}. Returns {caller, callee}.
     */
    public static Function[] createCallerAndCallee(Program program) throws Exception {
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Address callerAddr = space.getAddress(CALLER_ADDR);
        Address calleeAddr = space.getAddress(CALLEE_ADDR);
        byte[] body = {
            (byte) 0x55, (byte) 0x89, (byte) 0xe5,
            (byte) 0xe8, (byte) 0xf8, 0x00, 0x00, 0x00,
            (byte) 0x5d, (byte) 0xc3};
        int txId = program.startTransaction("Create caller and callee");
        try {
            program.getMemory().setBytes(callerAddr, body);
            program.getMemory().setBytes(calleeAddr, new byte[] {(byte) 0xc3});
            for (Address start : List.of(calleeAddr, callerAddr)) {
                new DisassembleCommand(start, null, true).applyTo(program, TaskMonitor.DUMMY);
            }
            FunctionManager fm = program.getFunctionManager();
            Function callee = fm.createFunction("callee", calleeAddr,
                new AddressSet(calleeAddr, calleeAddr), SourceType.USER_DEFINED);
            Function caller = fm.createFunction("caller", callerAddr,
                new AddressSet(callerAddr, callerAddr.add(body.length - 1)), SourceType.USER_DEFINED);
            return new Function[] {caller, callee};
        } finally {
            program.endTransaction(txId, true);
        }
    }

    /** The registered cache, fetched at each use. */
    public static DecompilationCache cache() {
        DecompilationCache cache = RevaInternalServiceRegistry.getService(DecompilationCache.class);
        if (cache == null) {
            throw new AssertionError("DecompilationCache should be registered");
        }
        return cache;
    }

    /** Number of decompiles the registered cache performed while the call ran. */
    public static long decompilesDuring(Runnable call) {
        long before = cache().stats().decompiles();
        call.run();
        return cache().stats().decompiles() - before;
    }

    /** Runs body with {@code replacement} registered, restoring the original instance afterwards. */
    public static void withRegisteredCache(DecompilationCache replacement, Runnable body) {
        DecompilationCache original = cache();
        RevaInternalServiceRegistry.registerService(DecompilationCache.class, replacement);
        try {
            body.run();
        } finally {
            RevaInternalServiceRegistry.registerService(DecompilationCache.class, original);
        }
    }

    /** Makes the program findable by the MCP tools (same pattern as DecompilerToolProviderIntegrationTest). */
    public static void openInTools(ghidra.test.TestEnv env, ghidra.framework.plugintool.PluginTool tool,
            reva.server.McpServerManager serverManager, Program program) throws Exception {
        env.open(program);
        ghidra.app.services.ProgramManager programManager = tool.getService(ghidra.app.services.ProgramManager.class);
        if (programManager != null) {
            programManager.openProgram(program);
        }
        if (serverManager != null) {
            serverManager.programOpened(program, tool);
        }
    }

    /** Renames a function in its own committed transaction and checks the name took. */
    public static void renameFunction(Program program, Function function, String newName) throws Exception {
        int txId = program.startTransaction("Rename " + function.getName());
        try {
            function.setName(newName, SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(txId, true);
        }
        if (!newName.equals(function.getName())) {
            throw new AssertionError("rename to " + newName + " did not take: " + function.getName());
        }
    }

    /** Reads the function (read-before-modify) and sets its prototype; requires success. */
    public static void setPrototype(McpSyncClient client, String programPath, String functionName,
            String address, String signature) {
        callJson(client, "get-decompilation", Map.of("programPath", programPath,
            "functionNameOrAddress", functionName, "includeIncomingReferences", false));
        JsonNode json = callJson(client, "set-function-prototype",
            Map.of("programPath", programPath, "location", address, "signature", signature));
        if (!json.get("success").asBoolean()) {
            throw new AssertionError("set-function-prototype should succeed: " + json);
        }
    }

    /** Calls a tool, requires a non-error result, and parses its first text content as JSON. */
    public static JsonNode callJson(McpSyncClient client, String tool, Map<String, Object> args) {
        try {
            CallToolResult result = client.callTool(new CallToolRequest(tool, args));
            if (result.isError()) {
                throw new AssertionError(tool + " should succeed: " + result);
            }
            return MAPPER.readTree(((TextContent) result.content().get(0)).text());
        } catch (AssertionError e) {
            throw e;
        } catch (Exception e) {
            throw new AssertionError(tool + " failed: " + e.getMessage(), e);
        }
    }
}
