package reva.services;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.mockito.MockedStatic;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ProjectData;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.task.TaskMonitor;
import reva.plugin.ConfigManager;
import reva.util.ProgramPersistenceUtil.PersistMode;
import reva.util.RevaInternalServiceRegistry;

public class AnalysisJobRunnerTest {

    /** Registers the configuration the analysis hook consults. */
    private static void useSnapshotConfig(String folder, String prefix) {
        ConfigManager config = mock(ConfigManager.class);
        when(config.getSnapshotFolder()).thenReturn(folder);
        when(config.getSnapshotPrefix()).thenReturn(prefix);
        RevaInternalServiceRegistry.registerService(ConfigManager.class, config);
    }

    private static void clearSnapshotConfig() {
        RevaInternalServiceRegistry.unregisterService(ConfigManager.class);
    }

    /** Runs one analysis job to completion against mocks and returns it. */
    private AnalysisJob run(PersistMode persistMode, Program program) {
        return run(persistMode, program, false);
    }

    /** Runs one analysis job; {@code cancelDuringAnalysis} cancels the analysis monitor. */
    private AnalysisJob run(PersistMode persistMode, Program program, boolean cancelDuringAnalysis) {
        AutoAnalysisManager aam = mock(AutoAnalysisManager.class);
        when(aam.getTimedTasks()).thenReturn(new String[0]);
        when(program.getOptions(Program.ANALYSIS_PROPERTIES)).thenReturn(mock(Options.class));
        when(program.startTransaction(anyString())).thenReturn(1);
        if (cancelDuringAnalysis) {
            doAnswer(invocation -> {
                ((TaskMonitor) invocation.getArgument(0)).cancel();
                return null;
            }).when(aam).startAnalysis(any(TaskMonitor.class));
        }

        try (MockedStatic<AutoAnalysisManager> aamStatic = mockStatic(AutoAnalysisManager.class);
                MockedStatic<GhidraProgramUtilities> gpu =
                    mockStatic(GhidraProgramUtilities.class)) {
            aamStatic.when(() -> AutoAnalysisManager.getAnalysisManager(program)).thenReturn(aam);
            gpu.when(() -> GhidraProgramUtilities.isAnalyzed(program)).thenReturn(true);

            AnalysisJobManager mgr = new AnalysisJobManager();
            AnalysisJob job = mgr.create("/target.exe");
            new AnalysisJobRunner(mgr, job, new AnalyzeRequest(
                program, List.of(), List.of(), false, -1, persistMode)).run();
            return job;
        }
    }

    /** Wires the program's domain file to a project root whose /snapshots folder is empty. */
    private static DomainFile stubSnapshotCopyTarget(Program program) throws Exception {
        DomainFolder snapshots = mock(DomainFolder.class);
        when(snapshots.getFiles()).thenReturn(new DomainFile[0]);
        DomainFolder root = mock(DomainFolder.class);
        when(root.getFolder("snapshots")).thenReturn(snapshots);
        ProjectData projectData = mock(ProjectData.class);
        when(projectData.getRootFolder()).thenReturn(root);
        DomainFolder parent = mock(DomainFolder.class);
        when(parent.getProjectData()).thenReturn(projectData);
        DomainFile file = mock(DomainFile.class);
        when(file.getParent()).thenReturn(parent);
        DomainFile copy = mock(DomainFile.class);
        when(copy.getName()).thenReturn("target.exe");
        DomainFile renamed = mock(DomainFile.class);
        when(copy.setName("snapshot-target.exe")).thenReturn(renamed);
        when(renamed.getPathname()).thenReturn("/snapshots/snapshot-target.exe");
        when(file.copyTo(eq(snapshots), eq(TaskMonitor.DUMMY))).thenReturn(copy);
        when(program.getDomainFile()).thenReturn(file);
        when(program.getName()).thenReturn("target.exe");
        return file;
    }

    private static boolean logSays(AnalysisJob job, String text) {
        for (JobLog.LogEntry entry : job.logSince(0, 100).entries) {
            if (entry.message.contains(text)) {
                return true;
            }
        }
        return false;
    }

    @Test
    public void busyProgramFailsTheJobWithoutStartingAnalysis() {
        Program program = mock(Program.class);
        ghidra.framework.model.TransactionInfo open =
            mock(ghidra.framework.model.TransactionInfo.class);
        when(open.getDescription()).thenReturn("run-script: annotate.py");
        when(program.getCurrentTransactionInfo()).thenReturn(open);

        AnalysisJobManager mgr = new AnalysisJobManager();
        AnalysisJob job = mgr.create("/target.exe");
        new AnalysisJobRunner(mgr, job, new AnalyzeRequest(
            program, List.of(), List.of(), false, -1, PersistMode.NONE)).run();

        assertEquals(JobStatus.FAILED, job.getStatus());
        assertNotNull(job.getError());
        assertTrue(job.getError(), job.getError().contains("Program is busy"));
        assertTrue(job.getError(), job.getError().contains("retry when run-script"));
        assertTrue(logSays(job, "Program is busy"));
        verify(program, never()).startTransaction(anyString());
    }

    @Test
    public void blankFolderDisablesSnapshotCreation() throws Exception {
        useSnapshotConfig("", "snapshot-");
        try {
            Program program = mock(Program.class);
            when(program.isChanged()).thenReturn(false);
            DomainFile file = stubSnapshotCopyTarget(program);

            AnalysisJob job = run(PersistMode.AUTO, program);

            assertEquals(JobStatus.COMPLETED, job.getStatus());
            verify(file, never()).copyTo(any(), any());
            assertFalse("default-off analysis must not mention snapshots",
                logSays(job, "Analysis snapshot"));
            assertFalse(job.getResult().containsKey("snapshot"));
        } finally {
            clearSnapshotConfig();
        }
    }

    @Test
    public void missingConfigManagerDisablesSnapshotCreation() throws Exception {
        clearSnapshotConfig();
        Program program = mock(Program.class);
        when(program.isChanged()).thenReturn(false);
        DomainFile file = stubSnapshotCopyTarget(program);

        AnalysisJob job = run(PersistMode.AUTO, program);

        assertEquals(JobStatus.COMPLETED, job.getStatus());
        verify(file, never()).copyTo(any(), any());
        assertFalse(logSays(job, "Analysis snapshot"));
    }

    @Test
    public void dirtyProgramGetsNoConfiguredSnapshot() throws Exception {
        useSnapshotConfig("snapshots", "snapshot-");
        try {
            Program program = mock(Program.class);
            when(program.isChanged()).thenReturn(true); // the persist step saved nothing
            DomainFile file = stubSnapshotCopyTarget(program);

            AnalysisJob job = run(PersistMode.NONE, program);

            assertEquals(JobStatus.COMPLETED, job.getStatus());
            Map<String, Object> result = job.getResult();
            assertNotNull(result);
            assertEquals(Boolean.TRUE, result.get("success"));
            assertEquals("skipped", result.get("persisted"));
            assertFalse("an unsaved program must not get a possibly stale snapshot",
                result.containsKey("snapshot"));
            verify(file, never()).copyTo(any(), any());
            assertTrue(logSays(job, "Analysis snapshot skipped: program has unsaved changes"));
        } finally {
            clearSnapshotConfig();
        }
    }

    @Test
    public void savedProgramGetsOneConfiguredSnapshotWithoutAPath() throws Exception {
        useSnapshotConfig("snapshots", "snapshot-");
        try {
            Program program = mock(Program.class);
            when(program.isChanged()).thenReturn(false);
            DomainFile file = stubSnapshotCopyTarget(program);

            AnalysisJob job = run(PersistMode.AUTO, program);

            assertFalse("the snapshot path must never reach the model",
                job.getResult().containsKey("snapshot"));
            assertFalse(job.getResult().containsKey("baseline"));
            verify(file).copyTo(any(), eq(TaskMonitor.DUMMY));
            assertTrue(logSays(job, "Analysis snapshot created"));
            assertFalse("even the job log stays path-free", logSays(job, "/snapshots"));
            assertFalse("generic production log text only", logSays(job, "baseline"));
        } finally {
            clearSnapshotConfig();
        }
    }

    @Test
    public void cancelledAnalysisCreatesNoSnapshot() throws Exception {
        useSnapshotConfig("snapshots", "snapshot-");
        try {
            Program program = mock(Program.class);
            when(program.isChanged()).thenReturn(false);
            DomainFile file = stubSnapshotCopyTarget(program);

            AnalysisJob job = run(PersistMode.AUTO, program, true);

            assertEquals(JobStatus.CANCELLED, job.getStatus());
            verify(file, never()).copyTo(any(), any());
            assertFalse(logSays(job, "Analysis snapshot created"));
            assertFalse(logSays(job, "Analysis snapshot skipped"));
        } finally {
            clearSnapshotConfig();
        }
    }
}
