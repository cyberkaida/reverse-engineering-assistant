package reva.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;
import org.mockito.Mockito;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.listing.Program;
import reva.util.ProgramPersistenceUtil.PersistAction;
import reva.util.ProgramPersistenceUtil.PersistMode;
import reva.util.ProgramPersistenceUtil.PersistResult;

public class ProgramPersistenceUtilTest {

    private DomainFile file(boolean canCheckin, boolean canAdd, boolean readOnly) {
        DomainFile f = Mockito.mock(DomainFile.class);
        when(f.canCheckin()).thenReturn(canCheckin);
        when(f.canAddToRepository()).thenReturn(canAdd);
        when(f.isReadOnly()).thenReturn(readOnly);
        return f;
    }

    @Test public void autoChecksInVersionedCheckedOutFile() {
        assertEquals(PersistAction.CHECKIN,
            ProgramPersistenceUtil.selectAction(file(true, false, false), PersistMode.AUTO));
    }
    @Test public void autoAddsToVcWhenRepoAvailableButUnversioned() {
        assertEquals(PersistAction.ADD_TO_VC,
            ProgramPersistenceUtil.selectAction(file(false, true, false), PersistMode.AUTO));
    }
    @Test public void autoSavesPlainProjectFile() {
        assertEquals(PersistAction.SAVE,
            ProgramPersistenceUtil.selectAction(file(false, false, false), PersistMode.AUTO));
    }
    @Test public void autoChecksInCheckedOutFileWithOnlyInMemoryChanges() {
        // canCheckin() requires modifiedSinceCheckout(), which only counts SAVED
        // changes — a checked-out file whose modifications are still in memory
        // reports canCheckin()=false until persist()'s save. The plan must still
        // be CHECKIN, since persist() saves before the checkin step.
        DomainFile f = file(false, false, false);
        when(f.isVersioned()).thenReturn(true);
        when(f.isCheckedOut()).thenReturn(true);
        when(f.isChanged()).thenReturn(true);
        assertEquals(PersistAction.CHECKIN,
            ProgramPersistenceUtil.selectAction(f, PersistMode.AUTO));
    }
    @Test public void autoSavesCheckedOutFileWithNoChangesAtAll() {
        DomainFile f = file(false, false, false);
        when(f.isVersioned()).thenReturn(true);
        when(f.isCheckedOut()).thenReturn(true);
        when(f.isChanged()).thenReturn(false);
        assertEquals(PersistAction.SAVE,
            ProgramPersistenceUtil.selectAction(f, PersistMode.AUTO));
    }
    @Test public void saveModeNeverChecksInEvenIfVersioned() {
        assertEquals(PersistAction.SAVE,
            ProgramPersistenceUtil.selectAction(file(true, false, false), PersistMode.SAVE));
    }
    @Test public void noneModeSkips() {
        assertEquals(PersistAction.SKIP,
            ProgramPersistenceUtil.selectAction(file(true, false, false), PersistMode.NONE));
    }
    @Test public void readOnlyFileSkips() {
        assertEquals(PersistAction.SKIP,
            ProgramPersistenceUtil.selectAction(file(false, false, true), PersistMode.AUTO));
    }

    private static TransactionInfo transaction(String description) {
        TransactionInfo tx = Mockito.mock(TransactionInfo.class);
        when(tx.getDescription()).thenReturn(description);
        return tx;
    }

    /** A Program whose open transaction is whatever the reference currently holds. */
    private static Program programWithTransaction(AtomicReference<TransactionInfo> tx) {
        Program program = Mockito.mock(Program.class);
        when(program.getCurrentTransactionInfo()).thenAnswer(invocation -> tx.get());
        return program;
    }

    @Test public void awaitNoTransactionReturnsImmediatelyWhenClear() {
        Program program = Mockito.mock(Program.class); // getCurrentTransactionInfo() -> null
        long startNanos = System.nanoTime();
        assertTrue(ProgramPersistenceUtil.awaitNoTransaction(program, 2000, 20));
        long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000;
        assertTrue("must not wait when no transaction is open (waited " + elapsedMs + " ms)",
            elapsedMs < 500);
    }

    @Test public void awaitNoTransactionWaitsForAnEndingTransaction() throws Exception {
        AtomicReference<TransactionInfo> tx = new AtomicReference<>(transaction("t"));
        Program program = programWithTransaction(tx);
        Thread ender = new Thread(() -> {
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            tx.set(null);
        });
        ender.start();
        long startNanos = System.nanoTime();
        try {
            assertTrue(ProgramPersistenceUtil.awaitNoTransaction(program, 2000, 20));
        } finally {
            ender.join();
        }
        long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000;
        assertTrue("must poll until the transaction ends (waited " + elapsedMs + " ms)",
            elapsedMs >= 150);
    }

    @Test public void awaitNoTransactionTimesOutOnANeverEndedTransaction() {
        Program program = programWithTransaction(new AtomicReference<>(transaction("t")));
        long startNanos = System.nanoTime();
        assertFalse(ProgramPersistenceUtil.awaitNoTransaction(program, 200, 20));
        long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000;
        assertTrue("must wait out the timeout (waited " + elapsedMs + " ms)", elapsedMs >= 150);
        assertNotNull("the transaction is still open", program.getCurrentTransactionInfo());
    }

    @Test public void persistRefusesWhileATransactionStaysOpen() {
        Program program = programWithTransaction(new AtomicReference<>(transaction("run-script")));
        PersistResult r = ProgramPersistenceUtil.refuseIfTransactionOpen(program, 200, 20);
        assertNotNull("an open transaction must produce a refusal result", r);
        assertEquals(PersistAction.SKIP, r.action);
        assertFalse(r.saved);
        assertTrue("error must say the transaction is still open: " + r.error,
            r.error.contains("transaction is still open"));
        assertTrue("error must name the open transaction: " + r.error,
            r.error.contains("run-script"));
    }
}
