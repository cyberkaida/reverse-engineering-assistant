package reva.util;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.List;

import org.junit.Test;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import reva.tools.ProgramValidationException;

public class ProgramLookupUtilTest {

    private static Program program(String path, boolean closed) {
        Program p = mock(Program.class);
        DomainFile df = mock(DomainFile.class);
        when(df.getPathname()).thenReturn(path);
        when(p.getDomainFile()).thenReturn(df);
        when(p.isClosed()).thenReturn(closed);
        return p;
    }

    @Test
    public void soleOpenProgramIsResolved() throws Exception {
        Program only = program("/a.exe", false);
        assertSame(only, ProgramLookupUtil.resolveSoleOpenProgram(List.of(only)));
    }

    @Test
    public void closedProgramsAreIgnored() throws Exception {
        Program only = program("/a.exe", false);
        Program closed = program("/b.exe", true);
        assertSame(only, ProgramLookupUtil.resolveSoleOpenProgram(List.of(closed, only)));
    }

    @Test
    public void severalOpenProgramsAreListed() {
        try {
            ProgramLookupUtil.resolveSoleOpenProgram(
                List.of(program("/a.exe", false), program("/b.exe", false)));
            fail("expected ProgramValidationException");
        } catch (ProgramValidationException e) {
            assertEquals("programPath is required when several programs are open:\n  - /a.exe\n  - /b.exe",
                e.getMessage());
        }
    }

    @Test
    public void noOpenProgramSaysSo() {
        try {
            ProgramLookupUtil.resolveSoleOpenProgram(List.of());
            fail("expected ProgramValidationException");
        } catch (ProgramValidationException e) {
            assertEquals("No program is open. Import one with import-file.", e.getMessage());
        }
    }

    @Test
    public void nullPathResolvesToTheSoleRegisteredProgram() throws Exception {
        Program only = program("/only.exe", false);
        reva.plugin.RevaProgramManager.registerProgram(only);
        try {
            assertSame(only, ProgramLookupUtil.getValidatedProgram(null));
            assertSame(only, ProgramLookupUtil.getValidatedProgram("  "));
        } finally {
            reva.plugin.RevaProgramManager.unregisterProgram(only);
        }
    }

    @Test
    public void nullPathWithTwoKnownProgramsListsThem() {
        Program a = program("/a.exe", false);
        Program b = program("/b.exe", false);
        reva.plugin.RevaProgramManager.registerProgram(a);
        reva.plugin.RevaProgramManager.registerProgram(b);
        try {
            ProgramLookupUtil.getValidatedProgram(null);
            fail("expected ProgramValidationException");
        } catch (ProgramValidationException e) {
            assertTrue(e.getMessage(), e.getMessage().startsWith("programPath is required when several programs are open:"));
            assertTrue(e.getMessage().contains("  - /a.exe"));
            assertTrue(e.getMessage().contains("  - /b.exe"));
        } finally {
            reva.plugin.RevaProgramManager.unregisterProgram(a);
            reva.plugin.RevaProgramManager.unregisterProgram(b);
        }
    }

    @Test
    public void nullPathWithNothingKnownSaysNoProgramIsOpen() {
        try {
            ProgramLookupUtil.getValidatedProgram(null);
            fail("expected ProgramValidationException");
        } catch (ProgramValidationException e) {
            assertEquals("No program is open. Import one with import-file.", e.getMessage());
        }
    }

    private static final String SHA = "f3a15d33527c22b9cb25c3c9d503fdbd595511e42160a18573db245c8995fdf5";
    private static final String SHA_PATH = "/" + SHA;
    private static final String OTHER_SHA_PATH =
        "/f805f22f668bd0414497ddc061e021c5b80b80c9702053d72fc809f19307073b";
    private static final List<String> AVAILABLE =
        List.of("/samples/other.exe", OTHER_SHA_PATH, SHA_PATH);

    @Test
    public void ellipsisedShaWithDirectoryAndExtensionRanksTheShaFirst() {
        List<String> ranked = ProgramLookupUtil.rankBySimilarity(
            "/work/ghidra-home/f3a15d...fdf5.bin", AVAILABLE);
        assertEquals(SHA_PATH, ranked.get(0));
        assertEquals(3, ranked.size());
    }

    @Test
    public void unicodeEllipsisWorksToo() {
        assertEquals(SHA_PATH, ProgramLookupUtil.rankBySimilarity("f3a15d\u2026fdf5", AVAILABLE).get(0));
    }

    @Test
    public void missedEllipsisStillRanksByItsPrefix() {
        assertEquals(SHA_PATH, ProgramLookupUtil.rankBySimilarity("/f3a15d...zzzz", AVAILABLE).get(0));
    }

    @Test
    public void hexPrefixRanksTheShaFirst() {
        assertEquals(SHA_PATH, ProgramLookupUtil.rankBySimilarity("f3a15d33", AVAILABLE).get(0));
    }

    @Test
    public void longerCommonPrefixWins() {
        List<String> ranked = ProgramLookupUtil.rankBySimilarity("/f3a1", List.of("/f3b", "/f3a15d", "/f3a2"));
        assertEquals(List.of("/f3a15d", "/f3a2", "/f3b"), ranked);
    }

    @Test
    public void caseIsIgnored() {
        assertEquals(SHA_PATH, ProgramLookupUtil.rankBySimilarity("/F3A15D33...FDF5", AVAILABLE).get(0));
    }

    @Test
    public void exactFileNameRanksFirst() {
        assertEquals(SHA_PATH, ProgramLookupUtil.rankBySimilarity(SHA, AVAILABLE).get(0));
    }

    @Test
    public void exactDecoyRanksTheDecoyFirst() {
        assertEquals("/samples/other.exe", ProgramLookupUtil.rankBySimilarity("/samples/other.exe", AVAILABLE).get(0));
        assertEquals("/samples/other.exe", ProgramLookupUtil.rankBySimilarity("OTHER.EXE", AVAILABLE).get(0));
    }

    @Test
    public void fileNameWithoutExtensionMatches() {
        assertEquals("/samples/other.exe", ProgramLookupUtil.rankBySimilarity("other", AVAILABLE).get(0));
    }

    @Test
    public void nearTypoRanksByEditDistance() {
        List<String> ranked = ProgramLookupUtil.rankBySimilarity("/Hatchery.exe",
            List.of("/zzz.exe", "/Hatchry.exe"));
        assertEquals("/Hatchry.exe", ranked.get(0));
    }

    @Test
    public void unrelatedRequestStillListsEveryPathDeterministically() {
        List<String> ranked = ProgramLookupUtil.rankBySimilarity("/run Analysis", AVAILABLE);
        assertEquals(3, ranked.size());
        assertTrue(ranked.containsAll(AVAILABLE));
        assertEquals(ranked, ProgramLookupUtil.rankBySimilarity("/run Analysis", AVAILABLE));
    }

    @Test
    public void slashOnlyRequestListsEveryPath() {
        assertEquals(3, ProgramLookupUtil.rankBySimilarity("/", AVAILABLE).size());
    }

    @Test
    public void tiesBreakAlphabetically() {
        assertEquals(List.of("/a", "/b"), ProgramLookupUtil.rankBySimilarity("/zzzzzz", List.of("/b", "/a")));
    }

    @Test
    public void errorMessageListsTheThreeClosestThenEverything() {
        String msg = ProgramLookupUtil.buildErrorMessageWithSuggestions("f3a15d33",
            List.of("/d", "/c", SHA_PATH, "/b", "/a"));
        assertTrue(msg, msg.startsWith("Program not found: f3a15d33\n\nDid you mean (closest first)?\n  - " + SHA_PATH + "\n  - "));
        assertEquals(3, msg.split("\n\nAll programs")[0].split("\n  - ").length - 1);
        String all = msg.split("\n\nAll programs \\(5\\):\n")[1];
        assertEquals(5, all.split("\n").length);
        assertTrue(all.startsWith("  - " + SHA_PATH + "\n"));
    }

    @Test
    public void errorMessageWithThreeOrFewerHasNoFullListing() {
        String msg = ProgramLookupUtil.buildErrorMessageWithSuggestions("/run Analysis", AVAILABLE);
        assertTrue(msg, msg.startsWith("Program not found: /run Analysis\n\nDid you mean (closest first)?\n  - "));
        assertFalse(msg, msg.contains("All programs"));
        for (String p : AVAILABLE) {
            assertTrue(msg, msg.contains("\n  - " + p));
        }
    }

    @Test
    public void errorMessageWithNoProgramsSaysSo() {
        String msg = ProgramLookupUtil.buildErrorMessageWithSuggestions("/x", List.of());
        assertEquals("Program not found: /x\n\nNo programs are currently available. "
            + "Please open a program in Ghidra or check your project.", msg);
    }
}
