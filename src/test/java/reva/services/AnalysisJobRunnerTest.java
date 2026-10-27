package reva.services;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.Test;

import ghidra.program.model.listing.Program;
import reva.util.ProgramPersistenceUtil.PersistMode;

public class AnalysisJobRunnerTest {

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
}
