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

import org.junit.Test;

import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import reva.RevaHeadlessIntegrationTestBase;
import reva.tools.functions.FunctionToolProvider.CallingConventionSplit;

/**
 * Tests for {@code set-function-prototype}'s signature handling:
 * <ul>
 *   <li>parse failures for undefined types teach the tools that define types</li>
 *   <li>calling-convention keywords are split off the signature and applied afterwards</li>
 *   <li>a convention the program cannot take on produces a self-explanatory error</li>
 *   <li>type names resolve against the Win32 and C library type archives</li>
 * </ul>
 */
public class FunctionToolProviderPrototypeTest extends RevaHeadlessIntegrationTestBase {

    // -------- behaviour 1: undefined types teach the fix --------

    @Test
    public void undefinedTypeHintNamesTheFixTools() {
        String text = FunctionToolProvider.parseSignatureError("Can't resolve datatype: ImportEntry");

        assertTrue(text, text.contains("Undefined type 'ImportEntry'"));
        assertTrue(text, text.contains("parse-c-structure"));
        assertTrue(text, text.contains("apply-data-type"));
        assertTrue(text, text.contains("basic type"));
    }

    @Test
    public void undefinedReturnTypeHintNamesTheFixTools() {
        String text = FunctionToolProvider.parseSignatureError("Can't resolve return type: FILE *");

        assertTrue(text, text.contains("Undefined type 'FILE *'"));
        assertTrue(text, text.contains("parse-c-structure"));
        assertTrue(text, text.contains("apply-data-type"));
    }

    @Test
    public void otherParseFailuresKeepMessageAndPointAtCustomTypes() {
        String text = FunctionToolProvider.parseSignatureError("Can't parse function arguments");

        assertTrue(text, text.contains("Can't parse function arguments"));
        assertTrue(text, text.contains(
            "(define custom types first with parse-c-structure or apply-data-type)"));
        assertFalse(text, text.contains("Undefined type"));
    }

    @Test
    public void realUndefinedTypeParseFailureGetsTeachingText() throws Exception {
        FunctionSignatureParser parser = FunctionToolProvider.newSignatureParser(program);

        try {
            parser.parse(null, "int read_entry(ImportEntry *entry)");
            fail("expected a ParseException for the undefined type");
        }
        catch (ParseException e) {
            String text = FunctionToolProvider.parseSignatureError(e.getMessage());
            assertTrue(text, text.contains("Undefined type 'ImportEntry *'"));
            assertTrue(text, text.contains("parse-c-structure"));
        }
    }

    // -------- behaviour 2: conventions are stripped and reported --------

    @Test
    public void callingConventionIsStrippedAndReported() {
        String[][] cases = {
            { "void __fastcall handler(int a)", "void handler(int a)", "__fastcall" },
            { "int __stdcall handler(int a)", "int handler(int a)", "__stdcall" },
            { "char *__cdecl handler(void)", "char * handler(void)", "__cdecl" },
            { "__thiscall handler(int a)", "handler(int a)", "__thiscall" },
        };

        for (String[] testCase : cases) {
            CallingConventionSplit split =
                FunctionToolProvider.splitCallingConvention(testCase[0]);
            assertEquals(testCase[1], split.signature());
            assertEquals(testCase[2], split.callingConvention());
        }
    }

    @Test
    public void absentCallingConventionIsLeftAlone() {
        CallingConventionSplit split =
            FunctionToolProvider.splitCallingConvention("void handler(int a)");

        assertEquals("void handler(int a)", split.signature());
        assertNull(split.callingConvention());
    }

    @Test
    public void unknownConventionKeywordIsNotStripped() {
        CallingConventionSplit split =
            FunctionToolProvider.splitCallingConvention("void __vectorcall handler(int a)");

        assertEquals("void __vectorcall handler(int a)", split.signature());
        assertNull(split.callingConvention());
    }

    @Test
    public void firstCallingConventionWins() {
        CallingConventionSplit split =
            FunctionToolProvider.splitCallingConvention("void __cdecl __fastcall handler(void)");

        assertEquals("void __fastcall handler(void)", split.signature());
        assertEquals("__cdecl", split.callingConvention());
    }

    @Test
    public void supportedConventionIsAppliedToTheFunction() throws Exception {
        Function function = createFunction("cc_supported");
        int txId = program.startTransaction("Apply calling convention");
        try {
            assertNull(FunctionToolProvider.applyCallingConvention(function, "__fastcall"));
            assertEquals("__fastcall", function.getCallingConventionName());
        }
        finally {
            program.endTransaction(txId, false);
        }
    }

    // -------- behaviour 3: unusable conventions explain themselves --------

    @Test
    public void unusableCallingConventionNamesWhatHappened() throws Exception {
        Function function = createFunction("cc_unsupported");
        int txId = program.startTransaction("Apply unsupported calling convention");
        try {
            String error = FunctionToolProvider.applyCallingConvention(function, "__bogus");

            assertNotNull(error);
            assertTrue(error, error.contains("__bogus"));
            assertTrue(error, error.contains("not part of the signature string"));
            assertTrue(error, error.contains("Unknown calling convention name"));
            assertTrue(error, error.contains("left unchanged"));
        }
        finally {
            program.endTransaction(txId, false);
        }
    }

    // -------- type archives --------

    @Test
    public void parserResolvesClibTypes() throws Exception {
        FunctionSignatureParser parser = FunctionToolProvider.newSignatureParser(program);

        FunctionDefinitionDataType def = parser.parse(null, "int read_stream(FILE *stream)");

        assertEquals("int", def.getReturnType().getName());
        ParameterDefinition[] args = def.getArguments();
        assertEquals(1, args.length);
        assertEquals("FILE *", args[0].getDataType().getName());
    }

    @Test
    public void parserResolvesWin32Types() throws Exception {
        FunctionSignatureParser parser = FunctionToolProvider.newSignatureParser(program);

        FunctionDefinitionDataType def = parser.parse(null, "int close_handle(HANDLE h)");

        ParameterDefinition[] args = def.getArguments();
        assertEquals(1, args.length);
        assertEquals("HANDLE", args[0].getDataType().getName());
    }

    private Function createFunction(String name) throws Exception {
        Address entry =
            program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000010);
        int txId = program.startTransaction("Create calling-convention test function");
        try {
            return program.getFunctionManager()
                    .createFunction(name, entry, new AddressSet(entry, entry), SourceType.USER_DEFINED);
        }
        finally {
            program.endTransaction(txId, true);
        }
    }

    // -------- transaction lifetime on the early error returns --------

    /**
     * Mock program whose only real collaborators are the address, symbol and
     * data-type services of this test's program (so signature parsing and
     * address resolution behave normally); its function manager is a mock so
     * both "no function and creation disabled" and "createFunction returned
     * null" can be reached.
     */
    private ghidra.program.model.listing.Program prototypeMockProgram() throws Exception {
        ghidra.program.model.listing.Program mockProgram =
            org.mockito.Mockito.mock(ghidra.program.model.listing.Program.class);
        ghidra.framework.model.DomainFile df =
            org.mockito.Mockito.mock(ghidra.framework.model.DomainFile.class);
        org.mockito.Mockito.when(df.getPathname()).thenReturn("/proto-target");
        org.mockito.Mockito.when(df.isVersioned()).thenReturn(false);
        org.mockito.Mockito.when(mockProgram.getDomainFile()).thenReturn(df);
        org.mockito.Mockito.when(mockProgram.isClosed()).thenReturn(false);
        org.mockito.Mockito.when(mockProgram.getAddressFactory())
            .thenReturn(program.getAddressFactory());
        org.mockito.Mockito.when(mockProgram.getSymbolTable())
            .thenReturn(program.getSymbolTable());
        org.mockito.Mockito.when(mockProgram.getDataTypeManager())
            .thenReturn(program.getDataTypeManager());
        org.mockito.Mockito.when(mockProgram.getCompilerSpec())
            .thenReturn(program.getCompilerSpec());
        org.mockito.Mockito.when(mockProgram.getDefaultPointerSize()).thenReturn(4);

        ghidra.program.model.listing.FunctionManager functions =
            org.mockito.Mockito.mock(ghidra.program.model.listing.FunctionManager.class);
        org.mockito.Mockito.when(functions.getFunctionAt(org.mockito.ArgumentMatchers.any(Address.class)))
            .thenReturn(null);
        org.mockito.Mockito.when(functions.createFunction(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.any(Address.class),
                org.mockito.ArgumentMatchers.any(ghidra.program.model.address.AddressSetView.class),
                org.mockito.ArgumentMatchers.any(SourceType.class)))
            .thenReturn(null);
        org.mockito.Mockito.when(mockProgram.getFunctionManager()).thenReturn(functions);

        org.mockito.Mockito.when(mockProgram.startTransaction(org.mockito.ArgumentMatchers.anyString()))
            .thenReturn(42);
        return mockProgram;
    }

    private io.modelcontextprotocol.spec.McpSchema.CallToolResult callSetFunctionPrototype(
            java.util.Map<String, Object> args) {
        io.modelcontextprotocol.server.McpSyncServer server =
            org.mockito.Mockito.mock(io.modelcontextprotocol.server.McpSyncServer.class);
        FunctionToolProvider provider = new FunctionToolProvider(server);
        provider.registerTools();
        org.mockito.ArgumentCaptor<io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification>
            cap = org.mockito.ArgumentCaptor.forClass(
                io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification.class);
        org.mockito.Mockito.verify(server, org.mockito.Mockito.atLeastOnce()).addTool(cap.capture());
        for (var spec : cap.getAllValues()) {
            if (spec.tool().name().equals("set-function-prototype")) {
                return spec.callHandler().apply(null,
                    new io.modelcontextprotocol.spec.McpSchema.CallToolRequest(
                        "set-function-prototype", args));
            }
        }
        throw new AssertionError("set-function-prototype not registered");
    }

    @Test
    public void creationDisabledEndsTheTransactionBeforeReturning() throws Exception {
        ghidra.program.model.listing.Program mockProgram = prototypeMockProgram();
        reva.plugin.RevaProgramManager.registerProgram(mockProgram);
        try {
            io.modelcontextprotocol.spec.McpSchema.CallToolResult result =
                callSetFunctionPrototype(java.util.Map.of(
                    "programPath", "/proto-target",
                    "location", "0x01000010",
                    "signature", "int no_such(void)",
                    "createIfNotExists", false));

            String text = ((io.modelcontextprotocol.spec.McpSchema.TextContent)
                result.content().get(0)).text();
            assertTrue(text, text.contains("createIfNotExists is false"));
            org.mockito.Mockito.verify(mockProgram).endTransaction(42, false);
        }
        finally {
            reva.plugin.RevaProgramManager.unregisterProgram(mockProgram);
        }
    }

    @Test
    public void failedFunctionCreationEndsTheTransactionBeforeReturning() throws Exception {
        ghidra.program.model.listing.Program mockProgram = prototypeMockProgram();
        reva.plugin.RevaProgramManager.registerProgram(mockProgram);
        try {
            // createIfNotExists defaults to true; the stubbed createFunction
            // returns null, the other early return.
            io.modelcontextprotocol.spec.McpSchema.CallToolResult result =
                callSetFunctionPrototype(java.util.Map.of(
                    "programPath", "/proto-target",
                    "location", "0x01000010",
                    "signature", "int new_function(void)"));

            String text = ((io.modelcontextprotocol.spec.McpSchema.TextContent)
                result.content().get(0)).text();
            assertTrue(text, text.contains("Failed to create function"));
            org.mockito.Mockito.verify(mockProgram).endTransaction(42, false);
        }
        finally {
            reva.plugin.RevaProgramManager.unregisterProgram(mockProgram);
        }
    }
}
