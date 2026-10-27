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

import java.util.function.Predicate;

import org.junit.Before;
import org.junit.Test;

import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.listing.Program;
import reva.tools.DatabaseAvailability.WaitOutcome;

public class DatabaseAvailabilityTest {

	private static final Predicate<Program> NO_ANALYSIS = p -> false;

	private Program program;
	private TransactionInfo openTx;

	@Before
	public void setUp() {
		program = mock(Program.class);
		openTx = mock(TransactionInfo.class);
		when(openTx.getDescription()).thenReturn("run-script: reva_x.py");
	}

	@Test
	public void checkIsModifiableWithNoTransactionAndNoAnalysis() {
		when(program.getCurrentTransactionInfo()).thenReturn(null);
		WaitOutcome outcome = DatabaseAvailability.check(program, NO_ANALYSIS);
		assertTrue(outcome.modifiable());
		assertNull(outcome.reason());
	}

	@Test
	public void checkIsBusyWhenATransactionIsOpen() {
		when(program.getCurrentTransactionInfo()).thenReturn(openTx);
		WaitOutcome outcome = DatabaseAvailability.check(program, NO_ANALYSIS);
		assertFalse(outcome.modifiable());
		assertTrue(outcome.reason().contains("run-script: reva_x.py"));
	}

	@Test
	public void checkIsBusyWhenAutoAnalysisIsRunning() {
		when(program.getCurrentTransactionInfo()).thenReturn(null);
		WaitOutcome outcome = DatabaseAvailability.check(program, p -> true);
		assertFalse(outcome.modifiable());
		assertEquals("auto-analysis is running", outcome.reason());
	}

	@Test
	public void awaitReturnsImmediatelyWhenModifiable() {
		when(program.getCurrentTransactionInfo()).thenReturn(null);
		long start = System.currentTimeMillis();
		WaitOutcome outcome =
			DatabaseAvailability.awaitModifiable(program, NO_ANALYSIS, 2000, 10);
		assertTrue(outcome.modifiable());
		assertTrue("returned instantly", System.currentTimeMillis() - start < 1000);
	}

	@Test
	public void awaitSucceedsWhenTheWriterClears() {
		when(program.getCurrentTransactionInfo()).thenReturn(openTx, openTx, null);
		WaitOutcome outcome =
			DatabaseAvailability.awaitModifiable(program, NO_ANALYSIS, 5000, 10);
		assertTrue(outcome.modifiable());
	}

	@Test
	public void awaitTimesOutWithTheBlockingReason() {
		when(program.getCurrentTransactionInfo()).thenReturn(openTx);
		long start = System.currentTimeMillis();
		WaitOutcome outcome =
			DatabaseAvailability.awaitModifiable(program, NO_ANALYSIS, 100, 10);
		assertFalse(outcome.modifiable());
		assertTrue(outcome.reason().contains("run-script: reva_x.py"));
		assertTrue("bounded by the deadline", System.currentTimeMillis() - start < 2000);
	}

	@Test
	public void awaitKeepsWaitingThroughAnalysisThenSucceeds() {
		when(program.getCurrentTransactionInfo()).thenReturn(null);
		WaitOutcome outcome = DatabaseAvailability.awaitModifiable(
			program, new Predicate<>() {
				private int calls;

				@Override
				public boolean test(Program p) {
					return ++calls <= 2;
				}
			}, 5000, 10);
		assertTrue(outcome.modifiable());
	}
}