package reva.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Test;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class ProjectSnapshotsTest {

    private final TaskMonitor monitor = mock(TaskMonitor.class);

    /** A program in the project root, whose file lives in {@code root}. */
    private Program programIn(DomainFolder root, String name) {
        ProjectData projectData = mock(ProjectData.class);
        when(projectData.getRootFolder()).thenReturn(root);

        DomainFolder parent = mock(DomainFolder.class);
        when(parent.getProjectData()).thenReturn(projectData);

        DomainFile file = mock(DomainFile.class);
        when(file.getParent()).thenReturn(parent);

        Program program = mock(Program.class);
        when(program.getName()).thenReturn(name);
        when(program.getDomainFile()).thenReturn(file);
        return program;
    }

    @Test
    public void blankFolderDisablesSnapshotCreation() throws Exception {
        DomainFolder root = mock(DomainFolder.class);
        Program program = programIn(root, "8422abcd");

        assertNull(ProjectSnapshots.createIfConfigured(program, "", "snapshot-", monitor));
        assertNull(ProjectSnapshots.createIfConfigured(program, null, "snapshot-", monitor));
        verify(program.getDomainFile(), never()).copyTo(any(), any());
    }

    @Test
    public void configuredFolderCreatesOneSnapshot() throws Exception {
        DomainFolder root = mock(DomainFolder.class);
        DomainFolder snapshots = mock(DomainFolder.class);
        when(root.getFolder("snapshots")).thenReturn(null, snapshots);
        when(root.createFolder("snapshots")).thenReturn(snapshots);

        Program program = programIn(root, "8422abcd");
        DomainFile file = program.getDomainFile();
        DomainFile copy = mock(DomainFile.class);
        when(copy.getName()).thenReturn("8422abcd");
        DomainFile renamed = mock(DomainFile.class);
        when(copy.setName("snapshot-8422abcd")).thenReturn(renamed);
        when(renamed.getName()).thenReturn("snapshot-8422abcd");
        when(renamed.getPathname()).thenReturn("/snapshots/snapshot-8422abcd");
        when(snapshots.getFiles()).thenReturn(new DomainFile[0],
            new DomainFile[] { renamed });
        when(file.copyTo(snapshots, monitor)).thenReturn(copy);

        assertEquals("/snapshots/snapshot-8422abcd",
            ProjectSnapshots.createIfConfigured(program, "snapshots", "snapshot-", monitor));
        assertNull("a second analysis must not duplicate the snapshot",
            ProjectSnapshots.createIfConfigured(program, "snapshots", "snapshot-", monitor));

        verify(root).createFolder("snapshots");
        verify(file).copyTo(snapshots, monitor);
        verify(copy).setName("snapshot-8422abcd");
    }

    @Test
    public void nestedOrSlashWrappedFolderCreatesNothing() throws Exception {
        DomainFolder root = mock(DomainFolder.class);
        Program program = programIn(root, "8422abcd");

        for (String folder : new String[] {
                "archive/snapshots", "snapshots/", "/snapshots/", "archive\\snapshots",
                ".", "..", " " }) {
            assertNull(folder + " must not create a snapshot",
                ProjectSnapshots.createIfConfigured(program, folder, "snapshot-", monitor));
        }

        verify(program.getDomainFile(), never()).copyTo(any(), any());
        verify(root, never()).getFolder(any());
        verify(root, never()).createFolder(any());
    }

    @Test
    public void nestedConfigurationMatchesNothing() {
        assertFalse(ProjectSnapshots.isSnapshotFolder("snapshots", "archive/snapshots"));
        assertFalse(ProjectSnapshots.isSnapshotPath("/archive/snapshots/x", "archive/snapshots"));
        assertFalse(ProjectSnapshots.isSnapshotPath("/snapshots/x", "archive/snapshots"));
    }

    @Test
    public void existingSnapshotIsNotRecreated() throws Exception {
        DomainFolder root = mock(DomainFolder.class);
        DomainFolder snapshots = mock(DomainFolder.class);
        when(root.getFolder("snapshots")).thenReturn(snapshots);
        DomainFile existing = mock(DomainFile.class);
        when(existing.getName()).thenReturn("snapshot-8422abcd");
        when(snapshots.getFiles()).thenReturn(new DomainFile[] { existing });

        Program program = programIn(root, "8422abcd");

        assertNull(ProjectSnapshots.createIfConfigured(program, "snapshots", "snapshot-", monitor));
        verify(program.getDomainFile(), never()).copyTo(any(), any());
    }

    @Test
    public void noDomainFileReturnsNull() {
        Program program = mock(Program.class);
        when(program.getDomainFile()).thenReturn(null);

        assertNull(ProjectSnapshots.createIfConfigured(program, "snapshots", "snapshot-", monitor));
    }

    @Test
    public void copyFailureReturnsNull() throws Exception {
        DomainFolder root = mock(DomainFolder.class);
        DomainFolder snapshots = mock(DomainFolder.class);
        when(root.getFolder("snapshots")).thenReturn(snapshots);
        when(snapshots.getFiles()).thenReturn(new DomainFile[0]);

        Program program = programIn(root, "8422abcd");
        when(program.getDomainFile().copyTo(snapshots, monitor))
            .thenThrow(new RuntimeException("project is read-only"));

        assertNull(ProjectSnapshots.createIfConfigured(program, "snapshots", "snapshot-", monitor));
    }

    @Test
    public void pathPredicateComparesOnlyTheSuppliedFolder() {
        assertTrue(ProjectSnapshots.isSnapshotPath("/snapshots/snapshot-x", "snapshots"));
        assertTrue(ProjectSnapshots.isSnapshotPath("/snapshots", "snapshots"));
        assertFalse(ProjectSnapshots.isSnapshotPath("/baselines/baseline-x", "snapshots"));
        assertFalse(ProjectSnapshots.isSnapshotPath("/snapshots-x/file", "snapshots"));
        assertFalse("slash-wrapped configuration is invalid",
            ProjectSnapshots.isSnapshotPath("/snapshots/snapshot-x", "/snapshots/"));
        assertFalse("a blank configuration filters nothing",
            ProjectSnapshots.isSnapshotPath("/snapshots/snapshot-x", ""));
        assertFalse(ProjectSnapshots.isSnapshotPath("/snapshots/snapshot-x", null));
    }

    @Test
    public void folderPredicateComparesOnlyTheSuppliedFolder() {
        assertTrue(ProjectSnapshots.isSnapshotFolder("snapshots", "snapshots"));
        assertFalse("configured leaf names never match a nested configuration",
            ProjectSnapshots.isSnapshotFolder("snapshots", "archive/snapshots"));
        assertFalse(ProjectSnapshots.isSnapshotFolder("baselines", "snapshots"));
        assertFalse("slash-wrapped configuration is invalid",
            ProjectSnapshots.isSnapshotFolder("snapshots", "/snapshots/"));
        assertFalse("a blank configuration filters nothing",
            ProjectSnapshots.isSnapshotFolder("snapshots", " "));
        assertFalse(ProjectSnapshots.isSnapshotFolder("snapshots", null));
    }
}
