package reva.tools.project;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.plugins.importer.batch.BatchGroup;
import ghidra.plugins.importer.batch.BatchGroup.BatchLoadConfig;
import ghidra.plugins.importer.batch.BatchGroupLoadSpec;
import ghidra.plugins.importer.batch.BatchInfo;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

public class ProjectToolProviderTest {

    private static DomainFile versionedUnchanged(boolean checkedOut, boolean modified) {
        DomainFile df = mock(DomainFile.class);
        when(df.canAddToRepository()).thenReturn(false);
        when(df.canCheckin()).thenReturn(false);
        when(df.isVersioned()).thenReturn(true);
        when(df.isChanged()).thenReturn(false);
        when(df.isCheckedOut()).thenReturn(checkedOut);
        when(df.modifiedSinceCheckout()).thenReturn(modified);
        return df;
    }

    private ProjectToolProvider provider() {
        return new ProjectToolProvider(mock(McpSyncServer.class), true);
    }

    @Test
    public void checkinWithNoChangesIsSuccess() {
        CallToolResult r = provider().checkinPreValidation(versionedUnchanged(true, false), "/a.exe");
        assertNotNull(r);
        assertFalse(r.isError());
        String text = ((TextContent) r.content().get(0)).text();
        assertTrue(text, text.contains("\"success\":true"));
        assertTrue(text, text.contains("\"action\":\"no_changes\""));
        assertTrue(text, text.contains("\"programPath\":\"/a.exe\""));
        assertTrue(text, text.contains("\"message\":\"Program has no changes since checkout\""));
    }

    @Test
    public void checkinOfUncheckedOutFileStillErrors() {
        CallToolResult r = provider().checkinPreValidation(versionedUnchanged(false, false), "/a.exe");
        assertNotNull(r);
        assertTrue(r.isError());
    }

    @Test
    public void checkinWithChangesProceeds() {
        DomainFile df = mock(DomainFile.class);
        when(df.canCheckin()).thenReturn(true);
        assertNull(provider().checkinPreValidation(df, "/a.exe"));
    }

    @Test
    public void handBuiltRequiredListsDoNotRequireProgramPath() {
        McpSyncServer server = mock(McpSyncServer.class);
        new ProjectToolProvider(server, true).registerTools();
        org.mockito.ArgumentCaptor<io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification> cap =
            org.mockito.ArgumentCaptor.forClass(io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification.class);
        verify(server, atLeastOnce()).addTool(cap.capture());
        boolean sawCheckin = false;
        for (var spec : cap.getAllValues()) {
            var tool = spec.tool();
            assertFalse(tool.name() + " must not require programPath",
                required(tool).contains("programPath"));
            if (tool.name().equals("checkin-program")) {
                sawCheckin = true;
                assertTrue(required(tool).contains("message"));
                String desc = String.valueOf(((java.util.Map<?, ?>) ((java.util.Map<?, ?>) schema(tool).get("properties")).get("programPath")).get("description"));
                assertTrue(desc, desc.contains("Optional when exactly one program is open."));
            }
        }
        assertTrue(sawCheckin);
    }

    private static java.util.Map<?, ?> schema(io.modelcontextprotocol.spec.McpSchema.Tool tool) {
        return new com.fasterxml.jackson.databind.ObjectMapper().convertValue(tool.inputSchema(), java.util.Map.class);
    }

    private static java.util.List<?> required(io.modelcontextprotocol.spec.McpSchema.Tool tool) {
        Object r = schema(tool).get("required");
        return r == null ? java.util.List.of() : (java.util.List<?>) r;
    }

    private CallToolResult callAnalysisStatus(java.util.Map<String, Object> args) {
        McpSyncServer server = mock(McpSyncServer.class);
        new ProjectToolProvider(server, true).registerTools();
        org.mockito.ArgumentCaptor<io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification> cap =
            org.mockito.ArgumentCaptor.forClass(io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification.class);
        verify(server, atLeastOnce()).addTool(cap.capture());
        for (var spec : cap.getAllValues()) {
            if (spec.tool().name().equals("analysis-status")) {
                return spec.callHandler().apply(null,
                    new io.modelcontextprotocol.spec.McpSchema.CallToolRequest("analysis-status", args));
            }
        }
        throw new AssertionError("analysis-status not registered");
    }

    @Test
    public void analysisStatusWithNeitherArgumentUsesTheSoleKnownProgram() {
        reva.util.RevaInternalServiceRegistry.registerService(reva.services.AnalysisJobManager.class,
            mock(reva.services.AnalysisJobManager.class));
        ghidra.program.model.listing.Program p = mock(ghidra.program.model.listing.Program.class);
        DomainFile df = mock(DomainFile.class);
        when(df.getPathname()).thenReturn("/only.exe");
        when(p.getDomainFile()).thenReturn(df);
        reva.plugin.RevaProgramManager.registerProgram(p);
        try {
            CallToolResult r = callAnalysisStatus(java.util.Map.of());
            assertTrue(r.isError());
            String text = ((TextContent) r.content().get(0)).text();
            assertEquals("No analysis job found for programPath: /only.exe", text);
        } finally {
            reva.plugin.RevaProgramManager.unregisterProgram(p);
            reva.util.RevaInternalServiceRegistry.unregisterService(reva.services.AnalysisJobManager.class);
        }
    }

    @Test
    public void analysisStatusWithBothArgumentsSaysAtMostOne() {
        reva.util.RevaInternalServiceRegistry.registerService(reva.services.AnalysisJobManager.class,
            mock(reva.services.AnalysisJobManager.class));
        try {
            CallToolResult r = callAnalysisStatus(java.util.Map.of("jobId", "j1", "programPath", "/a.exe"));
            assertTrue(r.isError());
            assertEquals("Provide at most one of jobId or programPath, not both",
                ((TextContent) r.content().get(0)).text());
        } finally {
            reva.util.RevaInternalServiceRegistry.unregisterService(reva.services.AnalysisJobManager.class);
        }
    }

    @Test
    public void analysisStatusWithNeitherArgumentAndNoProgramSaysSo() {
        reva.util.RevaInternalServiceRegistry.registerService(reva.services.AnalysisJobManager.class,
            mock(reva.services.AnalysisJobManager.class));
        try {
            CallToolResult r = callAnalysisStatus(java.util.Map.of());
            assertTrue(r.isError());
            assertEquals("No program is open. Import one with import-file.",
                ((TextContent) r.content().get(0)).text());
        } finally {
            reva.util.RevaInternalServiceRegistry.unregisterService(reva.services.AnalysisJobManager.class);
        }
    }

    // --- import-file idempotence ---

    /** Lowercase SHA-256 of the ASCII bytes "abc", as Ghidra records it in Program Info. */
    private static final String ABC_SHA256 =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    private static ByteProvider providerOf(String content) throws Exception {
        ByteProvider provider = mock(ByteProvider.class);
        when(provider.getInputStream(0)).thenReturn(
            new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
        return provider;
    }

    private static DomainFolder folderOf(String name, DomainFile[] files, DomainFolder[] folders) {
        return folderOf(name, name.isEmpty() ? "/" : "/" + name, files, folders);
    }

    private static DomainFolder folderOf(String name, String pathname, DomainFile[] files,
            DomainFolder[] folders) {
        DomainFolder folder = mock(DomainFolder.class);
        when(folder.getName()).thenReturn(name);
        when(folder.getPathname()).thenReturn(pathname);
        when(folder.getFiles()).thenReturn(files);
        when(folder.getFolders()).thenReturn(folders);
        return folder;
    }

    private static Project projectWithRoot(DomainFolder root) {
        ProjectData data = mock(ProjectData.class);
        when(data.getRootFolder()).thenReturn(root);
        Project project = mock(Project.class);
        when(project.getProjectData()).thenReturn(data);
        return project;
    }

    private static DomainFile programFile(String name, Program stored) throws Exception {
        DomainFile file = mock(DomainFile.class);
        when(file.getName()).thenReturn(name);
        when(file.getContentType()).thenReturn("Program");
        when(file.getPathname()).thenReturn("/" + name);
        when(file.getReadOnlyDomainObject(any(), eq(DomainFile.DEFAULT_VERSION), any()))
            .thenReturn(stored);
        return file;
    }

    @Test
    public void sourceSha256MatchesTheHashGhidraRecordsForAnImportedProgram() throws Exception {
        // Same computation as AbstractProgramLoader.setProgramProperties, so equal bytes compare equal.
        assertEquals(ABC_SHA256, ProjectToolProvider.executableSha256(providerOf("abc")));
    }

    @Test
    public void importReusesTheProgramWithTheSameNameAndSha256() throws Exception {
        Program stored = mock(Program.class);
        when(stored.getExecutableSHA256()).thenReturn(ABC_SHA256);
        DomainFile existing = programFile("sample.exe", stored);
        Project project = projectWithRoot(
            folderOf("", new DomainFile[] { existing }, new DomainFolder[0]));

        DomainFile reused = provider().findAlreadyImportedProgram(project, providerOf("abc"),
            TaskMonitor.DUMMY, "sample.exe");

        assertSame("the existing program is reused instead of importing a duplicate", existing, reused);
        verify(existing).getReadOnlyDomainObject(any(), eq(DomainFile.DEFAULT_VERSION),
            eq(TaskMonitor.DUMMY));
        verify(stored).release(any());
    }

    @Test
    public void sameNameWithDifferentBytesIsImportedNormally() throws Exception {
        Program stored = mock(Program.class);
        when(stored.getExecutableSHA256()).thenReturn(ABC_SHA256);
        DomainFile existing = programFile("sample.exe", stored);
        Project project = projectWithRoot(
            folderOf("", new DomainFile[] { existing }, new DomainFolder[0]));

        DomainFile reused = provider().findAlreadyImportedProgram(project, providerOf("abc def"),
            TaskMonitor.DUMMY, "sample.exe");

        assertNull("a same-named program with different bytes is a different program", reused);
        verify(stored).getExecutableSHA256();
        verify(stored).release(any());
    }

    @Test
    public void sameBytesUnderAnotherNameIsImportedNormally() throws Exception {
        Program stored = mock(Program.class);
        when(stored.getExecutableSHA256()).thenReturn(ABC_SHA256);
        DomainFile other = programFile("other.exe", stored);
        Project project = projectWithRoot(
            folderOf("", new DomainFile[] { other }, new DomainFolder[0]));
        ByteProvider source = providerOf("abc");

        DomainFile reused = provider().findAlreadyImportedProgram(project, source,
            TaskMonitor.DUMMY, "sample.exe");

        assertNull(reused);
        verify(other, never()).getReadOnlyDomainObject(any(), anyInt(), any());
        verify(source, never()).getInputStream(anyLong());
    }

    @Test
    public void anyCandidateFileNameThatMatchesIsReused() throws Exception {
        // The handler passes both the source's preferred name and the sanitized name the
        // loader would save under (they differ for names with characters Ghidra rewrites).
        Program stored = mock(Program.class);
        when(stored.getExecutableSHA256()).thenReturn(ABC_SHA256);
        DomainFile existing = programFile("sanitized.exe", stored);
        Project project = projectWithRoot(
            folderOf("", new DomainFile[] { existing }, new DomainFolder[0]));

        DomainFile reused = provider().findAlreadyImportedProgram(project, providerOf("abc"),
            TaskMonitor.DUMMY, "preferred.exe", "sanitized.exe");

        assertSame(existing, reused);
    }

    @Test
    public void nonProgramFilesWithTheSameNameAreIgnored() throws Exception {
        DomainFile data = mock(DomainFile.class);
        when(data.getName()).thenReturn("sample.exe");
        when(data.getContentType()).thenReturn("Data");
        Project project = projectWithRoot(
            folderOf("", new DomainFile[] { data }, new DomainFolder[0]));

        assertNull(provider().findAlreadyImportedProgram(project, providerOf("abc"),
            TaskMonitor.DUMMY, "sample.exe"));
        verify(data, never()).getReadOnlyDomainObject(any(), anyInt(), any());
    }

    @Test
    public void blankConfigReusesAProgramInASnapshotNamedFolder() throws Exception {
        Program stored = mock(Program.class);
        when(stored.getExecutableSHA256()).thenReturn(ABC_SHA256);
        DomainFile snapshot = programFile("sample.exe", stored);
        DomainFolder snapshots = folderOf("snapshots", new DomainFile[] { snapshot },
            new DomainFolder[0]);
        Project project = projectWithRoot(
            folderOf("", new DomainFile[0], new DomainFolder[] { snapshots }));

        DomainFile reused = provider().findAlreadyImportedProgram(project, providerOf("abc"),
            TaskMonitor.DUMMY, "sample.exe");

        assertSame("default-off ReVa leaves every project folder ordinary", snapshot, reused);
    }

    @Test
    public void configuredSnapshotsNeverStandInForTheImportedTarget() throws Exception {
        useSnapshotFolder("snapshots");
        try {
            Program stored = mock(Program.class);
            when(stored.getExecutableSHA256()).thenReturn(ABC_SHA256);
            DomainFile target = programFile("sample.exe", stored);
            DomainFile snapshot = programFile("snapshot-sample.exe", mock(Program.class));
            DomainFolder snapshots = folderOf("snapshots", new DomainFile[] { snapshot },
                new DomainFolder[0]);
            Project project = projectWithRoot(
                folderOf("", new DomainFile[] { target },
                    new DomainFolder[] { snapshots }));

            DomainFile reused = provider().findAlreadyImportedProgram(project,
                providerOf("abc"), TaskMonitor.DUMMY, "sample.exe", "snapshot-sample.exe");

            assertSame("the analyzed target is reused, never the configured snapshot",
                target, reused);
            verify(snapshot, never()).getReadOnlyDomainObject(any(), anyInt(), any());
        } finally {
            clearSnapshotConfig();
        }
    }

    @Test
    public void configuredSnapshotsOnlyLeaveTheImportToProceed() throws Exception {
        useSnapshotFolder("snapshots");
        try {
            Program stored = mock(Program.class);
            when(stored.getExecutableSHA256()).thenReturn(ABC_SHA256);
            DomainFile snapshot = programFile("sample.exe", stored);
            DomainFolder snapshots = folderOf("snapshots", new DomainFile[] { snapshot },
                new DomainFolder[0]);
            Project project = projectWithRoot(
                folderOf("", new DomainFile[0], new DomainFolder[] { snapshots }));

            assertNull("a configured snapshot never stands in for the target",
                provider().findAlreadyImportedProgram(project, providerOf("abc"),
                    TaskMonitor.DUMMY, "sample.exe"));
            verify(snapshot, never()).getReadOnlyDomainObject(any(), anyInt(), any());
        } finally {
            clearSnapshotConfig();
        }
    }

    @Test
    public void configuredSnapshotFolderLeavesOtherFoldersOrdinary() throws Exception {
        useSnapshotFolder("snapshots");
        try {
            Program stored = mock(Program.class);
            when(stored.getExecutableSHA256()).thenReturn(ABC_SHA256);
            DomainFile baseline = programFile("baseline-sample.exe", stored);
            DomainFolder baselines = folderOf("baselines", new DomainFile[] { baseline },
                new DomainFolder[0]);
            Project project = projectWithRoot(
                folderOf("", new DomainFile[0], new DomainFolder[] { baselines }));

            DomainFile reused = provider().findAlreadyImportedProgram(project,
                providerOf("abc"), TaskMonitor.DUMMY, "baseline-sample.exe");

            assertSame("only the configured folder is policy", baseline, reused);
        } finally {
            clearSnapshotConfig();
        }
    }

    private static void useSnapshotFolder(String folder) {
        reva.plugin.ConfigManager config = mock(reva.plugin.ConfigManager.class);
        when(config.getSnapshotFolder()).thenReturn(folder);
        reva.util.RevaInternalServiceRegistry.registerService(
            reva.plugin.ConfigManager.class, config);
    }

    private static void clearSnapshotConfig() {
        reva.util.RevaInternalServiceRegistry.unregisterService(
            reva.plugin.ConfigManager.class);
    }

    @Test
    public void anUnopenableCandidateFallsBackToANormalImport() throws Exception {
        DomainFile broken = mock(DomainFile.class);
        when(broken.getName()).thenReturn("sample.exe");
        when(broken.getContentType()).thenReturn("Program");
        when(broken.getReadOnlyDomainObject(any(), eq(DomainFile.DEFAULT_VERSION), any()))
            .thenThrow(new IOException("cannot open"));
        Project project = projectWithRoot(
            folderOf("", new DomainFile[] { broken }, new DomainFolder[0]));

        assertNull("an unreadable candidate never blocks the import",
            provider().findAlreadyImportedProgram(project, providerOf("abc"),
                TaskMonitor.DUMMY, "sample.exe"));
    }

    /** Calls the real import-file handler and returns its tool result. */
    private CallToolResult callImportFile(Map<String, Object> args) {
        McpSyncServer server = mock(McpSyncServer.class);
        new ProjectToolProvider(server, true).registerTools();
        ArgumentCaptor<io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification> cap =
            ArgumentCaptor.forClass(io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification.class);
        verify(server, atLeastOnce()).addTool(cap.capture());
        for (var spec : cap.getAllValues()) {
            if (spec.tool().name().equals("import-file")) {
                return spec.callHandler().apply(null,
                    new io.modelcontextprotocol.spec.McpSchema.CallToolRequest("import-file", args));
            }
        }
        throw new AssertionError("import-file not registered");
    }

    @Test
    public void importFileReusesAnIdenticalProgramWithoutRunningTheLoader() throws Exception {
        // The project already holds /sample.exe, whose executable hash equals the source bytes.
        Program stored = mock(Program.class);
        when(stored.getExecutableSHA256()).thenReturn(ABC_SHA256);
        DomainFile existing = programFile("sample.exe", stored);
        Project project = projectWithRoot(
            folderOf("", new DomainFile[] { existing }, new DomainFolder[0]));

        // The source exists on disk (the handler checks that) but its bytes come from a provider
        // mock, so no real loader or file format is involved.
        File source = File.createTempFile("reva-import", ".bin");
        source.deleteOnExit();
        ByteProvider bytes = providerOf("abc");

        FSRL sourceFsrl = mock(FSRL.class);
        when(sourceFsrl.toPrettyFullpathString()).thenReturn(source.getAbsolutePath());
        FileSystemService fsService = mock(FileSystemService.class);
        when(fsService.getLocalFSRL(any(File.class))).thenReturn(sourceFsrl);
        when(fsService.getByteProvider(any(FSRL.class), anyBoolean(), any())).thenReturn(bytes);

        // One discovered source whose program would be saved as /sample.exe.
        LoadSpec loadSpec = mock(LoadSpec.class);
        BatchLoadConfig config = mock(BatchLoadConfig.class);
        when(config.getFSRL()).thenReturn(sourceFsrl);
        when(config.getPreferredFileName()).thenReturn("sample.exe");
        when(config.getLoadSpec(any())).thenReturn(loadSpec);
        BatchGroup group = mock(BatchGroup.class);
        when(group.isEnabled()).thenReturn(true);
        when(group.getSelectedBatchGroupLoadSpec()).thenReturn(mock(BatchGroupLoadSpec.class));
        when(group.getBatchLoadConfig()).thenReturn(List.of(config));

        try (MockedStatic<AppInfo> appInfo = mockStatic(AppInfo.class);
                MockedStatic<FileSystemService> fsServiceStatics =
                    mockStatic(FileSystemService.class);
                MockedConstruction<BatchInfo> batchInfo = mockConstruction(BatchInfo.class,
                    (mock, context) -> {
                        when(mock.addFile(any(), any())).thenReturn(true);
                        when(mock.getTotalCount()).thenReturn(1);
                        when(mock.getGroups()).thenReturn(List.of(group));
                    })) {
            appInfo.when(AppInfo::getActiveProject).thenReturn(project);
            fsServiceStatics.when(FileSystemService::getInstance).thenReturn(fsService);

            CallToolResult result = callImportFile(Map.of("path", source.getAbsolutePath()));

            assertFalse(result.isError());
            String text = ((TextContent) result.content().get(0)).text();
            assertTrue(text, text.contains("\"programPath\":\"/sample.exe\""));
            assertTrue(text, text.contains("\"alreadyImported\":true"));
            assertTrue(text, text.contains(
                "\"note\":\"program already in the project; reusing it instead of creating a duplicate\""));
            assertTrue(text, text.contains("\"filesImported\":0"));
            assertTrue(text, text.contains("\"alreadyImportedPrograms\":[\"/sample.exe\"]"));
            assertFalse("a reused program must not be recommended for re-analysis",
                text.contains("analysisRecommended"));
            // The reused source never reaches the loader; it is not even obtained.
            verify(loadSpec, never()).getLoader();
        }
    }

    @Test
    public void aReusedProgramEntrySaysItWasAlreadyImported() {
        Map<String, Object> entry = provider().importedProgramEntry("/sample.exe", false, true);

        assertEquals("/sample.exe", entry.get("programPath"));
        assertEquals(Boolean.TRUE, entry.get("alreadyImported"));
        assertEquals("program already in the project; reusing it instead of creating a duplicate",
            entry.get("note"));
        assertFalse("reuse must not nudge a redundant re-analysis",
            entry.containsKey("analysisRecommended"));
        String nextSteps = (String) entry.get("nextSteps");
        assertTrue(nextSteps, nextSteps.contains("Already in the project"));
        assertTrue(nextSteps, nextSteps.contains("only if it has not been analyzed yet"));
    }

    @Test
    public void aFreshUnanalyzedProgramEntryRecommendsAnalysis() {
        Map<String, Object> entry = provider().importedProgramEntry("/sample.exe", false, false);

        assertEquals(Boolean.TRUE, entry.get("analysisRecommended"));
        String nextSteps = (String) entry.get("nextSteps");
        assertTrue(nextSteps, nextSteps.startsWith("Call analyze-program"));
        assertTrue(nextSteps, nextSteps.contains("/sample.exe"));
        assertFalse(entry.containsKey("alreadyImported"));
    }

    @Test
    public void aFreshlyImportedProgramEntryCarriesNoAlreadyImportedFlag() {
        Map<String, Object> entry = provider().importedProgramEntry("/sample.exe", true, false);

        assertEquals("/sample.exe", entry.get("programPath"));
        assertEquals(Boolean.TRUE, entry.get("analyzed"));
        assertFalse(entry.containsKey("alreadyImported"));
        assertFalse(entry.containsKey("note"));
    }

    /** Calls the real handler of a registered tool and returns its result. */
    private CallToolResult callTool(String toolName, Map<String, Object> args) {
        McpSyncServer server = mock(McpSyncServer.class);
        new ProjectToolProvider(server, true).registerTools();
        ArgumentCaptor<io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification> cap =
            ArgumentCaptor.forClass(io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification.class);
        verify(server, atLeastOnce()).addTool(cap.capture());
        for (var spec : cap.getAllValues()) {
            if (spec.tool().name().equals(toolName)) {
                return spec.callHandler().apply(null,
                    new io.modelcontextprotocol.spec.McpSchema.CallToolRequest(toolName, args));
            }
        }
        throw new AssertionError(toolName + " not registered");
    }

    @Test
    public void blankConfigListsTheBaselinesFolderNormally() {
        DomainFile target = listingFile("target.exe", "/target.exe");
        DomainFile snapshot = listingFile("baseline-target.exe",
            "/baselines/baseline-target.exe");
        DomainFolder baselines = folderOf("baselines", new DomainFile[] { snapshot },
            new DomainFolder[0]);
        DomainFolder root = folderOf("", new DomainFile[] { target },
            new DomainFolder[] { baselines });
        Project project = projectWithRoot(root);

        try (MockedStatic<AppInfo> appInfo = mockStatic(AppInfo.class)) {
            appInfo.when(AppInfo::getActiveProject).thenReturn(project);

            String recursive = text(callTool("list-project-files",
                Map.of("folderPath", "/", "recursive", true)));
            assertTrue(recursive, recursive.contains("\"/target.exe\""));
            assertTrue("default-off ReVa lists user folders as ordinary",
                recursive.contains("\"/baselines/baseline-target.exe\""));
            assertFalse("no folder is reserved while snapshots are disabled",
                recursive.contains("/snapshots"));

            String flat = text(callTool("list-project-files",
                Map.of("folderPath", "/", "recursive", false)));
            assertTrue(flat, flat.contains("\"/target.exe\""));
            assertTrue("the baselines folder is an ordinary folder", flat.contains("baselines"));
        }
    }

    @Test
    public void configuredSnapshotsAreHiddenFromListings() {
        useSnapshotFolder("snapshots");
        try {
            DomainFile target = listingFile("target.exe", "/target.exe");
            DomainFile snapshot = listingFile("snapshot-target.exe",
                "/snapshots/snapshot-target.exe");
            DomainFile baseline = listingFile("baseline-target.exe",
                "/baselines/baseline-target.exe");
            DomainFolder snapshots = folderOf("snapshots", new DomainFile[] { snapshot },
                new DomainFolder[0]);
            DomainFolder baselines = folderOf("baselines", new DomainFile[] { baseline },
                new DomainFolder[0]);
            DomainFolder root = folderOf("", new DomainFile[] { target },
                new DomainFolder[] { snapshots, baselines });
            Project project = projectWithRoot(root);

            try (MockedStatic<AppInfo> appInfo = mockStatic(AppInfo.class)) {
                appInfo.when(AppInfo::getActiveProject).thenReturn(project);

                String recursive = text(callTool("list-project-files",
                    Map.of("folderPath", "/", "recursive", true)));
                assertTrue(recursive, recursive.contains("\"/target.exe\""));
                assertTrue(recursive,
                    recursive.contains("\"/baselines/baseline-target.exe\""));
                assertFalse("configured snapshots never leak into a recursive listing",
                    recursive.contains("/snapshots"));

                String flat = text(callTool("list-project-files",
                    Map.of("folderPath", "/", "recursive", false)));
                assertTrue(flat, flat.contains("\"/target.exe\""));
                assertTrue("only the configured folder is hidden", flat.contains("baselines"));
                assertFalse("the configured folder itself is not listed",
                    flat.contains("snapshots"));
            }
        } finally {
            clearSnapshotConfig();
        }
    }

    @Test
    public void configuredSnapshotsOnlyHideTheRootFolderFromListings() {
        useSnapshotFolder("snapshots");
        try {
            DomainFile target = listingFile("target.exe", "/target.exe");
            DomainFile rootSnapshot = listingFile("snapshot-target.exe",
                "/snapshots/snapshot-target.exe");
            DomainFile nestedSnapshot = listingFile("archived-target.exe",
                "/archive/snapshots/archived-target.exe");
            DomainFolder rootSnapshots = folderOf("snapshots", "/snapshots",
                new DomainFile[] { rootSnapshot }, new DomainFolder[0]);
            DomainFolder nestedSnapshots = folderOf("snapshots", "/archive/snapshots",
                new DomainFile[] { nestedSnapshot }, new DomainFolder[0]);
            DomainFolder archive = folderOf("archive", "/archive", new DomainFile[0],
                new DomainFolder[] { nestedSnapshots });
            DomainFolder root = folderOf("", "/", new DomainFile[] { target },
                new DomainFolder[] { rootSnapshots, archive });
            ProjectData data = mock(ProjectData.class);
            when(data.getRootFolder()).thenReturn(root);
            when(data.getFolder("/archive")).thenReturn(archive);
            Project project = mock(Project.class);
            when(project.getProjectData()).thenReturn(data);

            try (MockedStatic<AppInfo> appInfo = mockStatic(AppInfo.class)) {
                appInfo.when(AppInfo::getActiveProject).thenReturn(project);

                String recursive = text(callTool("list-project-files",
                    Map.of("folderPath", "/", "recursive", true)));
                assertTrue(recursive, recursive.contains("\"/target.exe\""));
                assertTrue("a nested same-name folder stays ordinary", recursive.contains(
                    "\"/archive/snapshots/archived-target.exe\""));
                assertFalse("only the configured root folder is hidden",
                    recursive.contains("/snapshots/snapshot-target.exe"));

                String rootFlat = text(callTool("list-project-files",
                    Map.of("folderPath", "/", "recursive", false)));
                assertTrue(rootFlat, rootFlat.contains("\"folderPath\":\"archive\""));
                assertFalse(rootFlat, rootFlat.contains("\"folderPath\":\"snapshots\""));

                String archiveFlat = text(callTool("list-project-files",
                    Map.of("folderPath", "/archive", "recursive", false)));
                assertTrue("a nested same-name folder is listed at its real depth",
                    archiveFlat.contains("\"folderPath\":\"snapshots\""));
            }
        } finally {
            clearSnapshotConfig();
        }
    }

    @Test
    public void configuredSnapshotsOnlySkipTheRootFolderForImportDedupe() throws Exception {
        useSnapshotFolder("snapshots");
        try {
            Program stored = mock(Program.class);
            when(stored.getExecutableSHA256()).thenReturn(ABC_SHA256);
            DomainFile rootSnapshot = programFile("root-sample.exe", stored);
            DomainFile nestedSnapshot = programFile("archived-sample.exe", stored);
            DomainFolder rootSnapshots = folderOf("snapshots", "/snapshots",
                new DomainFile[] { rootSnapshot }, new DomainFolder[0]);
            DomainFolder nestedSnapshots = folderOf("snapshots", "/archive/snapshots",
                new DomainFile[] { nestedSnapshot }, new DomainFolder[0]);
            DomainFolder archive = folderOf("archive", "/archive", new DomainFile[0],
                new DomainFolder[] { nestedSnapshots });
            DomainFolder root = folderOf("", "/", new DomainFile[0],
                new DomainFolder[] { rootSnapshots, archive });
            Project project = projectWithRoot(root);

            assertNull("a configured root snapshot never stands in for the target",
                provider().findAlreadyImportedProgram(project, providerOf("abc"),
                    TaskMonitor.DUMMY, "root-sample.exe"));
            DomainFile reused = provider().findAlreadyImportedProgram(project,
                providerOf("abc"), TaskMonitor.DUMMY, "archived-sample.exe");
            assertSame("a nested same-name folder stays an ordinary import candidate",
                nestedSnapshot, reused);
        } finally {
            clearSnapshotConfig();
        }
    }

    @Test
    public void configuredSnapshotFolderIsRefusedWhileOtherFoldersStayAddressable() {
        useSnapshotFolder("snapshots");
        try {
            DomainFolder snapshots = folderOf("snapshots", new DomainFile[0],
                new DomainFolder[0]);
            DomainFolder baselines = folderOf("baselines", new DomainFile[0],
                new DomainFolder[0]);
            DomainFolder root = folderOf("", new DomainFile[0],
                new DomainFolder[] { snapshots, baselines });
            ProjectData data = mock(ProjectData.class);
            when(data.getRootFolder()).thenReturn(root);
            when(data.getFolder("/baselines")).thenReturn(baselines);
            Project project = mock(Project.class);
            when(project.getProjectData()).thenReturn(data);

            try (MockedStatic<AppInfo> appInfo = mockStatic(AppInfo.class)) {
                appInfo.when(AppInfo::getActiveProject).thenReturn(project);

                CallToolResult refused = callTool("list-project-files",
                    Map.of("folderPath", "/snapshots"));
                assertTrue("an explicit configured snapshot listing must be an error",
                    refused.isError());
                assertTrue(text(refused), text(refused).contains(
                    "configured analysis snapshots are not addressable"));

                CallToolResult ordinary = callTool("list-project-files",
                    Map.of("folderPath", "/baselines"));
                assertFalse("only the configured folder is refused", ordinary.isError());
            }
        } finally {
            clearSnapshotConfig();
        }
    }

    private static DomainFile listingFile(String name, String pathname) {
        DomainFile file = mock(DomainFile.class);
        when(file.getName()).thenReturn(name);
        when(file.getPathname()).thenReturn(pathname);
        when(file.getContentType()).thenReturn("Program");
        when(file.getLastModifiedTime()).thenReturn(0L);
        when(file.isReadOnly()).thenReturn(false);
        when(file.isVersioned()).thenReturn(false);
        when(file.isCheckedOut()).thenReturn(false);
        return file;
    }

    private static String text(CallToolResult result) {
        return ((TextContent) result.content().get(0)).text();
    }
}
