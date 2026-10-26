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

import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

import reva.RevaIntegrationTestBase;

/**
 * Regression tests for parameter reporting on thunk functions.
 *
 * <p>Ghidra 12.2's {@code FunctionDB.getParameter(int)} no longer delegates to the thunked
 * function, while {@code getParameterCount()} still does. Looping
 * {@code getParameter(i)} up to {@code getParameterCount()} on a thunk therefore returns null
 * and NPEs. Tools must use {@code getParameters()}, which still delegates on every version.
 */
public class ThunkFunctionParametersIntegrationTest extends RevaIntegrationTestBase {

    private static final String TARGET_ADDR = "0x01000100";
    private static final String THUNK_ADDR = "0x01000200";

    private String programPath;

    @Before
    public void setUpThunk() throws Exception {
        programPath = program.getDomainFile().getPathname();
        FunctionManager functionManager = program.getFunctionManager();
        Address targetAddr = program.getAddressFactory().getAddress(TARGET_ADDR);
        Address thunkAddr = program.getAddressFactory().getAddress(THUNK_ADDR);

        int txId = program.startTransaction("Create thunk");
        try {
            Function target = functionManager.createFunction("real_target", targetAddr,
                new AddressSet(targetAddr, targetAddr.add(15)), SourceType.USER_DEFINED);
            target.replaceParameters(List.of(
                    new ParameterImpl("a", IntegerDataType.dataType, program),
                    new ParameterImpl("b", IntegerDataType.dataType, program)),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
                SourceType.USER_DEFINED);

            Function thunk = functionManager.createFunction(null, thunkAddr,
                new AddressSet(thunkAddr, thunkAddr.add(5)), SourceType.DEFAULT);
            thunk.setThunkedFunction(target);
        } finally {
            program.endTransaction(txId, true);
        }

        Function thunk = functionManager.getFunctionAt(thunkAddr);
        assertTrue("fixture: thunk must be a thunk", thunk.isThunk());
        assertEquals("fixture: thunk must expose the target's parameters via getParameters()",
            2, thunk.getParameters().length);

        env.open(program);
    }

    @Test
    public void testGetFunctionsReportsThunkParameters() throws Exception {
        JsonNode result = parseJsonContent(callMcpTool("get-functions", Map.of(
            "programPath", programPath,
            "filterDefaultNames", false,
            "verbose", true)));

        JsonNode thunkInfo = null;
        for (JsonNode fn : result.get("functions")) {
            if (THUNK_ADDR.equals(fn.get("address").asText())) {
                thunkInfo = fn;
            }
        }
        assertNotNull("thunk should be listed: " + result, thunkInfo);
        assertTrue(thunkInfo.get("isThunk").asBoolean());

        JsonNode params = thunkInfo.get("parameters");
        assertEquals(2, params.size());
        assertEquals("a", params.get(0).get("name").asText());
        assertEquals("b", params.get(1).get("name").asText());
        assertEquals("int", params.get(0).get("dataType").asText());
    }

    @Test
    public void testGetDecompilationReportsThunkParameters() throws Exception {
        JsonNode result = parseJsonContent(callMcpTool("get-decompilation", Map.of(
            "programPath", programPath,
            "functionNameOrAddress", THUNK_ADDR,
            "signatureOnly", true)));

        JsonNode params = result.get("parameters");
        assertEquals(2, params.size());
        assertEquals("a", params.get(0).get("name").asText());
        assertEquals("b", params.get(1).get("name").asText());
        assertEquals("2", result.get("metadata").get("parameterCount").asText());
    }
}
