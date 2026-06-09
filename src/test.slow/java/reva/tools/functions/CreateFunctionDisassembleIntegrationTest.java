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
package reva.tools.functions;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.app.services.ProgramManager;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

import reva.RevaIntegrationTestBase;

/**
 * Integration test for create-function disassembling on demand when the target
 * address has raw bytes but no instruction yet.
 */
public class CreateFunctionDisassembleIntegrationTest extends RevaIntegrationTestBase {

    private static final String FUNC_ADDR = "0x01001000";
    // push rbp; mov rbp,rsp; pop rbp; ret
    private static final byte[] FUNC_BODY =
        {(byte) 0x55, (byte) 0x48, (byte) 0x89, (byte) 0xe5, (byte) 0x5d, (byte) 0xc3};

    /**
     * Build an x86-64 program with an executable block whose bytes form a valid
     * RET-terminated function, but WITHOUT disassembling them. create-function
     * must disassemble first, then create the function.
     */
    private Program buildUndisassembledProgram(String name) throws Exception {
        ProgramBuilder b = new ProgramBuilder(name, ProgramBuilder._X64, this);
        MemoryBlock block = b.createMemory("text", FUNC_ADDR, 0x100);
        b.setExecute(block, true);
        b.setBytes(FUNC_ADDR, FUNC_BODY); // raw bytes only — never disassembled
        return b.getProgram();
    }

    @Test
    public void testCreateFunctionDisassemblesUndisassembledBytes() throws Exception {
        Program prog = buildUndisassembledProgram("create_fn_disasm");
        String programPath = prog.getDomainFile().getPathname();
        Address funcAddr = prog.getAddressFactory().getAddress(FUNC_ADDR);

        ProgramManager pm = tool.getService(ProgramManager.class);
        env.open(prog);
        pm.openProgram(prog);
        serverManager.programOpened(prog, tool);
        try {
            // Preconditions: bytes are present, the block is executable, and there
            // is no instruction nor function at the address yet.
            MemoryBlock block = prog.getMemory().getBlock(funcAddr);
            assertNotNull("block should exist", block);
            assertTrue("block must be executable for create-function", block.isExecute());
            assertNull("no instruction should exist before the call",
                prog.getListing().getInstructionAt(funcAddr));
            assertNull("no function should exist before the call",
                prog.getFunctionManager().getFunctionAt(funcAddr));

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("address", FUNC_ADDR);

            JsonNode result = parseJsonContent(callMcpTool("create-function", args));
            assertTrue("create-function should report success", result.get("success").asBoolean());

            // Validate actual program state: the address was disassembled and a
            // function now exists there.
            assertNotNull("instruction should exist after disassembly",
                prog.getListing().getInstructionAt(funcAddr));
            Function created = prog.getFunctionManager().getFunctionAt(funcAddr);
            assertNotNull("function should have been created at the address", created);
        } finally {
            serverManager.programClosed(prog, tool);
            prog.release(this);
        }
    }
}
