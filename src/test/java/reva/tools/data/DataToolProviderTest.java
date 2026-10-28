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
package reva.tools.data;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.plugin.RevaProgramManager;
import reva.tools.DatabaseAvailability;

/**
 * Busy-program behaviour of create-label: the write waits for an in-flight
 * operation, then reports the machine-detectable busy result if the program is
 * still held.
 */
public class DataToolProviderTest {

	private static final String PROGRAM_PATH = "/target.exe";
	private static final String BUSY_SCRIPT = "run-script: reva_x.py";

	private Program program;
	private TransactionInfo openTransaction;

	/**
	 * Provider with a bounded write wait, so tests do not sit through the 30 s
	 * default. The production default is exercised by DatabaseAvailabilityTest.
	 */
	private static class ShortWaitDataProvider extends DataToolProvider {
		private final long deadlineMs;

		ShortWaitDataProvider(McpSyncServer server, long deadlineMs) {
			super(server);
			this.deadlineMs = deadlineMs;
		}

		@Override
		protected DatabaseAvailability.WaitOutcome awaitModifiable(Program target) {
			return DatabaseAvailability.awaitModifiable(target,
				DatabaseAvailability::isAutoAnalysisRunning, deadlineMs, 10);
		}
	}

	@Before
	public void setUp() {
		program = mock(Program.class);
		DomainFile domainFile = mock(DomainFile.class);
		when(domainFile.getPathname()).thenReturn(PROGRAM_PATH);
		when(program.getDomainFile()).thenReturn(domainFile);

		Address address = mock(Address.class);
		SymbolTable symbolTable = mock(SymbolTable.class);
		AddressFactory addressFactory = mock(AddressFactory.class);
		AddressSpace defaultSpace = mock(AddressSpace.class);
		when(program.getSymbolTable()).thenReturn(symbolTable);
		when(symbolTable.getLabelOrFunctionSymbols(anyString(), any())).thenReturn(List.of());
		when(program.getAddressFactory()).thenReturn(addressFactory);
		when(addressFactory.getDefaultAddressSpace()).thenReturn(defaultSpace);
		when(defaultSpace.getAddress(anyLong())).thenReturn(address);

		openTransaction = mock(TransactionInfo.class);
		when(openTransaction.getDescription()).thenReturn(BUSY_SCRIPT);

		RevaProgramManager.registerProgram(program);
	}

	@After
	public void tearDown() {
		RevaProgramManager.unregisterProgram(program);
	}

	private CallToolResult call(String toolName, Map<String, Object> args) {
		McpSyncServer server = mock(McpSyncServer.class);
		new ShortWaitDataProvider(server, 150).registerTools();

		ArgumentCaptor<SyncToolSpecification> specs =
			ArgumentCaptor.forClass(SyncToolSpecification.class);
		verify(server, atLeastOnce()).addTool(specs.capture());
		for (SyncToolSpecification spec : specs.getAllValues()) {
			if (spec.tool().name().equals(toolName)) {
				return spec.callHandler().apply(null, new CallToolRequest(toolName, args));
			}
		}
		throw new AssertionError("tool was not registered: " + toolName);
	}

	private static String text(CallToolResult result) {
		assertTrue("expected an error result", result.isError());
		assertEquals(1, result.content().size());
		return ((TextContent) result.content().get(0)).text();
	}

	@Test
	public void createLabelOnAStillBusyProgramReturnsTheBusyResult() {
		when(program.getCurrentTransactionInfo()).thenReturn(openTransaction);

		CallToolResult result = call("create-label", Map.of(
			"programPath", PROGRAM_PATH, "addressOrSymbol", "0x1000", "labelName", "entry"));

		String text = text(result);
		assertTrue(text, text.contains("\"busy\":true"));
		assertTrue(text, text.contains(BUSY_SCRIPT));
		assertTrue(text, text.contains("Wait for the in-flight operation to finish"));
		verify(program, never()).startTransaction(anyString());
	}
}
