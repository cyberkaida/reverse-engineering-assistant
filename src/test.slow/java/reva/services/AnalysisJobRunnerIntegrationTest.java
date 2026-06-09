/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.services;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Test;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.task.TaskMonitor;
import reva.RevaIntegrationTestBase;
import reva.services.JobLog;
import reva.services.JobStatus;
import reva.util.ProgramPersistenceUtil.PersistMode;

/**
 * Integration test for the background analysis runner ({@link AnalysisJobManager#submit}
 * + {@link AnalysisJobRunner}). Drives a real auto-analysis off the worker thread on a
 * saveable, project-backed program and verifies persist-on-finish.
 *
 * <p>The base class's shared {@code program} is a temporary (non-saveable) ProgramBuilder
 * program — {@code isChanged()} is always false on it ({@code changed && !temporary}). To
 * exercise the persist path against a real saveable file, this test copies that program into
 * the project root via {@code DomainFolder.createFile} and re-opens the resulting
 * {@link DomainFile} to obtain a project-backed, change-tracking, saveable instance.
 *
 * <p>Auto-analysis of this tiny zero-filled test block produces no functions/strings and so
 * nets no DB-dirtying change on its own. To prove the durability guarantee ("analyze now
 * SAVES"), the test clears the {@code temporary} flag (TestEnv programs default to temporary,
 * which pins {@code isChanged()} to false), deliberately dirties the project-backed program
 * (adds a label) before submitting with {@code PersistMode.SAVE}, then asserts the runner
 * actually persisted it: {@code persisted="save"}, {@code saved=true}, and
 * {@code isChanged()==false} after the job completes.
 */
public class AnalysisJobRunnerIntegrationTest extends RevaIntegrationTestBase {

    private AnalysisJobManager mgr;

    @After
    public void tearDownManager() {
        if (mgr != null) {
            mgr.dispose();
        }
    }

    @Test
    public void backgroundRunCompletesPersistsAndLogs() throws Exception {
        // Copy the shared (temporary) program into the project and re-open it so we have a
        // saveable, change-tracking instance for the persist assertion.
        DomainFolder root = env.getProject().getProjectData().getRootFolder();
        String fileName = "reva-analysis-job-" + System.nanoTime();
        DomainFile file = root.createFile(fileName, program, TaskMonitor.DUMMY);

        Program saveable = (Program) file.getDomainObject(this, false, false, TaskMonitor.DUMMY);
        try {
            // TestEnv-created programs default to temporary, which forces isChanged() to false
            // (isChanged() == changed && !temporary). Clear it so change-tracking is live and
            // the save path is exercised exactly as in headless/CLI mode.
            saveable.setTemporary(false);

            String programPath = saveable.getDomainFile().getPathname();
            assertTrue("Project-backed program should be saveable",
                saveable.getDomainFile().canSave());

            GhidraProgramUtilities.resetAnalysisFlags(saveable);
            assertFalse("Program should start un-analyzed after reset",
                GhidraProgramUtilities.isAnalyzed(saveable));

            // Deliberately dirty the program so the persist step has something real to save.
            // (Analysis of this tiny zero-filled block nets no DB change on its own.)
            int tx = saveable.startTransaction("Dirty for persist");
            try {
                saveable.getSymbolTable().createLabel(
                    saveable.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000),
                    "reva_test_marker", SourceType.USER_DEFINED);
                saveable.endTransaction(tx, true);
            } catch (Exception e) {
                saveable.endTransaction(tx, false);
                throw e;
            }
            saveable.flushEvents();
            assertTrue("Program should be dirty before submit", saveable.isChanged());

            mgr = new AnalysisJobManager();

            // Use SAVE mode so the persist path is the deterministic local save (this test
            // project happens to support add-to-version-control, which AUTO would prefer).
            AnalysisJob job = mgr.create(programPath);
            mgr.submit(job, new AnalyzeRequest(
                saveable, List.of(), List.of(),
                true /* forceFullAnalysis */, 120 /* timeoutSeconds */, PersistMode.SAVE));

            // Bounded wait for terminal status.
            long deadline = System.currentTimeMillis() + 180_000L;
            while (!job.getStatus().isTerminal()) {
                if (System.currentTimeMillis() > deadline) {
                    fail("Analysis job did not reach a terminal status within 180s; status="
                        + job.getStatus());
                }
                Thread.sleep(250L);
            }

            assertEquals("Job should complete successfully", JobStatus.COMPLETED, job.getStatus());
            assertTrue("Program should be marked analyzed in Ghidra metadata",
                GhidraProgramUtilities.isAnalyzed(saveable));

            JobLog.LogPage page = job.logSince(0, 1000);
            assertFalse("Job log should have captured entries", page.entries.isEmpty());

            Map<String, Object> result = job.getResult();
            assertNotNull("Result map should be populated", result);
            assertEquals(Boolean.TRUE, result.get("success"));
            assertEquals(Boolean.TRUE, result.get("wasFullAnalysis"));
            assertEquals(Boolean.FALSE, result.get("cancelled"));

            // The durability guarantee: the runner actually saved the dirty program.
            assertEquals("Project-backed non-versioned program should take the SAVE path",
                "save", result.get("persisted"));
            assertEquals("Persist should report a successful save", Boolean.TRUE, result.get("saved"));
            assertFalse("Saving should clear the dirty flag", saveable.isChanged());
        } finally {
            saveable.release(this);
            try {
                file.delete();
            } catch (Exception ignore) {
                // best-effort cleanup of the temporary project file
            }
        }
    }
}
