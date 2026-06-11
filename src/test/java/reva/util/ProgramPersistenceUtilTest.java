package reva.util;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.mockito.Mockito;

import ghidra.framework.model.DomainFile;
import reva.util.ProgramPersistenceUtil.PersistAction;
import reva.util.ProgramPersistenceUtil.PersistMode;

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
}
