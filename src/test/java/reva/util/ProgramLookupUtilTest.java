package reva.util;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.List;

import org.junit.Test;
import org.mockito.MockedStatic;

import ghidra.app.services.ProgramManager;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
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

    @Test
    public void blankSnapshotConfigLeavesBaselinePathsOrdinary() throws Exception {
        Program snapshot = program("/baselines/baseline-target.exe", false);
        reva.plugin.RevaProgramManager.registerProgram(snapshot);
        try {
            assertSame("default-off ReVa treats a user folder as ordinary",
                snapshot, ProgramLookupUtil.getValidatedProgram(
                    "/baselines/baseline-target.exe"));
            assertSame(snapshot, reva.plugin.RevaProgramManager.getProgramByPath(
                "/baselines/baseline-target.exe"));
            assertSame(snapshot, ProgramLookupUtil.resolveSoleOpenProgram(List.of(snapshot)));
        } finally {
            reva.plugin.RevaProgramManager.unregisterProgram(snapshot);
        }
    }

    @Test
    public void configuredSnapshotFolderIsNotAddressable() throws Exception {
        useSnapshotFolder("snapshots");
        Program snapshot = program("/snapshots/snapshot-target.exe", false);
        Program baseline = program("/baselines/baseline-target.exe", false);
        reva.plugin.RevaProgramManager.registerProgram(snapshot);
        reva.plugin.RevaProgramManager.registerProgram(baseline);
        try {
            try {
                ProgramLookupUtil.getValidatedProgram("/snapshots/snapshot-target.exe");
                fail("expected ProgramValidationException");
            } catch (ProgramValidationException e) {
                assertTrue(e.getMessage(),
                    e.getMessage().contains("configured analysis snapshots are not addressable"));
            }
            assertNull("the manager refuses the configured path even when it is registered",
                reva.plugin.RevaProgramManager.getProgramByPath(
                    "/snapshots/snapshot-target.exe"));
            assertSame("an unrelated folder stays ordinary",
                baseline, ProgramLookupUtil.getValidatedProgram(
                    "/baselines/baseline-target.exe"));
            assertSame("a configured snapshot is never the sole program",
                baseline, ProgramLookupUtil.resolveSoleOpenProgram(List.of(snapshot, baseline)));
            try {
                ProgramLookupUtil.resolveSoleOpenProgram(List.of(snapshot));
                fail("a configured snapshot is never the sole program");
            } catch (ProgramValidationException e) {
                assertEquals("No program is open. Import one with import-file.",
                    e.getMessage());
            }
        } finally {
            reva.plugin.RevaProgramManager.unregisterProgram(snapshot);
            reva.plugin.RevaProgramManager.unregisterProgram(baseline);
            clearSnapshotConfig();
        }
    }

    @Test
    public void configuredSnapshotAliasesAreNotResolved() throws Exception {
        useSnapshotFolder("snapshots");
        try {
            Program snapshot = program("/snapshots/snapshot-target.exe", false);
            when(snapshot.getName()).thenReturn("snapshot-target.exe");
            when(snapshot.getExecutablePath()).thenReturn("/tmp/snapshot-target.exe");

            DomainFolder root = mock(DomainFolder.class);
            when(root.getFile(anyString())).thenReturn(null);
            ProjectData data = mock(ProjectData.class);
            when(data.getRootFolder()).thenReturn(root);
            when(data.getFolder(anyString())).thenReturn(null);
            ProgramManager programManager = mock(ProgramManager.class);
            when(programManager.getAllOpenPrograms())
                .thenReturn(new Program[] { snapshot });
            PluginTool tool = mock(PluginTool.class);
            when(tool.getService(ProgramManager.class)).thenReturn(programManager);
            ToolManager toolManager = mock(ToolManager.class);
            when(toolManager.getRunningTools()).thenReturn(new PluginTool[] { tool });
            Project project = mock(Project.class);
            when(project.getProjectData()).thenReturn(data);
            when(project.getToolManager()).thenReturn(toolManager);

            try (MockedStatic<AppInfo> appInfo = mockStatic(AppInfo.class)) {
                appInfo.when(AppInfo::getActiveProject).thenReturn(project);

                assertNull("a program name must not alias a configured snapshot",
                    reva.plugin.RevaProgramManager.getProgramByPath(
                        "snapshot-target.exe"));
                assertNull("an executable path must not alias a configured snapshot",
                    reva.plugin.RevaProgramManager.getProgramByPath(
                        "/tmp/snapshot-target.exe"));
            }
        } finally {
            clearSnapshotConfig();
        }
    }

    private static void useSnapshotFolder(String folder) {
        reva.plugin.ConfigManager config = mock(reva.plugin.ConfigManager.class);
        when(config.getSnapshotFolder()).thenReturn(folder);
        RevaInternalServiceRegistry.registerService(reva.plugin.ConfigManager.class, config);
    }

    private static void clearSnapshotConfig() {
        RevaInternalServiceRegistry.unregisterService(reva.plugin.ConfigManager.class);
    }

    @Test
    public void normalExplicitPathStillResolves() throws Exception {
        Program target = program("/target.exe", false);
        reva.plugin.RevaProgramManager.registerProgram(target);
        try {
            assertSame(target, ProgramLookupUtil.getValidatedProgram("/target.exe"));
        } finally {
            reva.plugin.RevaProgramManager.unregisterProgram(target);
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
