package reva.util;

import static org.junit.Assert.*;
import org.junit.Test;
import ghidra.feature.vt.api.correlator.program.ExactMatchBytesProgramCorrelatorFactory;
import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;

public class VersionTrackingUtilTest {
    @Test
    public void testVtClassesAreOnClasspath() {
        VTProgramCorrelatorFactory f = new ExactMatchBytesProgramCorrelatorFactory();
        assertNotNull("VT factory should instantiate", f);
        assertEquals("Exact Function Bytes Match", f.getName());
    }

    @Test
    public void testDefaultCorrelatorSequenceOrderAndContent() {
        var seq = VersionTrackingUtil.defaultCorrelatorSequence();
        assertEquals(6, seq.size());
        assertEquals("Exact Symbol Name Match", seq.get(0).getName());
        assertEquals("Exact Function Bytes Match", seq.get(1).getName());
        assertEquals("Exact Function Instructions Match", seq.get(2).getName());
        assertEquals("Exact Function Mnemonics Match", seq.get(3).getName());
        assertEquals("Duplicate Function Instructions Match", seq.get(4).getName());
        assertEquals("Function Reference Match", seq.get(5).getName());
    }
}
