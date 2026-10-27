package reva.util;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import reva.RevaHeadlessIntegrationTestBase;

public class TypeArchivesTest extends RevaHeadlessIntegrationTestBase {

    private static boolean resolves(DataTypeManager[] dtms, String name) {
        for (DataTypeManager dtm : dtms) {
            List<DataType> found = new ArrayList<>();
            dtm.findDataTypes(name, found);
            if (!found.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    @Test
    public void windowsProgramSeesWin32AndClibTypes() {
        DataTypeManager[] dtms = TypeArchives.forProgram(program);
        assertTrue("HANDLE should resolve", resolves(dtms, "HANDLE"));
        assertTrue("DWORD should resolve", resolves(dtms, "DWORD"));
        assertTrue("size_t should resolve", resolves(dtms, "size_t"));
    }

    @Test
    public void archivesAreCachedPerJvm() {
        assertSame(TypeArchives.forProgram(program)[0], TypeArchives.forProgram(program)[0]);
    }
}
