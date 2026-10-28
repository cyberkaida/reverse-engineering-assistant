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
package reva.tools;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.ConcurrentModificationException;
import java.util.Map;

import org.junit.Test;

import ghidra.framework.model.DomainObjectLockedException;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

/**
 * Unit tests for the shared busy path in {@link AbstractToolProvider}: the
 * machine-detectable busy result and the wait-then-open-transaction helper.
 */
public class AbstractToolProviderBusyTest {

	private static class Provider extends AbstractToolProvider {
		Provider() {
			super(mock(McpSyncServer.class));
		}

		@Override
		public void registerTools() {
		}
	}

	private final Provider provider = new Provider();

	private static String text(CallToolResult result) {
		assertTrue("expected an error result", result.isError());
		assertEquals(1, result.content().size());
		return ((TextContent) result.content().get(0)).text();
	}

	@Test
	public void busyResultIsMachineReadableJsonNamingTheBlocker() {
		CallToolResult result =
			provider.createBusyResult("a transaction is open (run-script: reva_x.py)");

		String text = text(result);
		assertTrue(text, text.contains("\"busy\":true"));
		assertTrue(text, text.contains("Program is busy: a transaction is open "
			+ "(run-script: reva_x.py). Wait for the in-flight operation to finish, "
			+ "then call this tool again."));
	}

	@Test
	public void busyPayloadCarriesTheSameMessageForJobResults() {
		Map<String, Object> payload = provider.createBusyPayload("auto-analysis is running");

		assertEquals(Boolean.TRUE, payload.get("busy"));
		assertEquals("Program is busy: auto-analysis is running. Wait for the "
			+ "in-flight operation to finish, then call this tool again.",
			payload.get("error"));
	}

	@Test
	public void beginTransactionOpensTheTransactionWhenTheProgramIsFree() {
		Program program = mock(Program.class);
		when(program.getCurrentTransactionInfo()).thenReturn(null);
		when(program.startTransaction("Set Bookmark")).thenReturn(3);

		AbstractToolProvider.TransactionStart start =
			provider.beginTransaction(program, "Set Bookmark");

		assertTrue(start.started());
		assertEquals(3, start.id());
	}

	@Test
	public void beginTransactionReportsTheSaveLockAsBusy() {
		Program program = mock(Program.class);
		when(program.getCurrentTransactionInfo()).thenReturn(null);
		when(program.startTransaction(anyString()))
			.thenThrow(new DomainObjectLockedException("a save"));

		AbstractToolProvider.TransactionStart start =
			provider.beginTransaction(program, "Set Bookmark");

		assertFalse("the save lock the wait cannot see must not surface as a tool failure",
			start.started());
		assertEquals("a save operation holds the program lock", start.reason());
	}

	@Test
	public void beginTransactionReportsAConcurrentWriterAsBusy() {
		Program program = mock(Program.class);
		when(program.getCurrentTransactionInfo()).thenReturn(null);
		when(program.startTransaction(anyString()))
			.thenThrow(new ConcurrentModificationException("busy"));

		AbstractToolProvider.TransactionStart start =
			provider.beginTransaction(program, "Set Bookmark");

		assertFalse(start.started());
		assertEquals("another writer opened a transaction concurrently", start.reason());
	}
}
