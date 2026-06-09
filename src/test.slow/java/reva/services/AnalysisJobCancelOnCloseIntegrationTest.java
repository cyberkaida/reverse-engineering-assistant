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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import reva.RevaIntegrationTestBase;
import reva.plugin.RevaProgramManager;
import reva.util.RevaInternalServiceRegistry;

/**
 * Integration regression for lifecycle hygiene: closing a program through the server's
 * {@code programClosed} hook must request cancellation of any non-terminal analysis job for
 * that program.
 *
 * <p>Opens a saveable, project-backed program, registers an active (created-but-not-submitted)
 * job for its exact {@code programPath}, closes the program through the same
 * {@code serverManager.programClosed(program, tool)} path the GUI plugin uses, and asserts the
 * job became cancel-requested. The job has no attached runner/monitor, so it stays non-terminal;
 * the observable signal is {@code isCancelRequested()}.
 */
public class AnalysisJobCancelOnCloseIntegrationTest extends RevaIntegrationTestBase {

    @Test
    public void closingProgramCancelsActiveJob() throws Exception {
        DomainFolder root = env.getProject().getProjectData().getRootFolder();
        String fileName = "reva-cancel-on-close-" + System.nanoTime();
        DomainFile file = root.createFile(fileName, program, TaskMonitor.DUMMY);
        Program saveable = (Program) file.getDomainObject(this, false, false, TaskMonitor.DUMMY);

        AnalysisJob job = null;
        try {
            RevaProgramManager.registerProgram(saveable);
            assertNotNull("server manager required for this test", serverManager);
            serverManager.programOpened(saveable, tool);

            String programPath = saveable.getDomainFile().getPathname();

            AnalysisJobManager mgr =
                RevaInternalServiceRegistry.getService(AnalysisJobManager.class);
            assertNotNull("AnalysisJobManager service must be registered", mgr);

            job = mgr.create(programPath);
            assertFalse("job should start un-cancelled", job.isCancelRequested());
            assertFalse("job should start non-terminal", job.getStatus().isTerminal());

            // Close the program through the same path the GUI plugin uses.
            serverManager.programClosed(saveable, tool);

            // A job with no runner/monitor stays non-terminal; cancel is the only signal.
            assertTrue("closing the program should request cancel on its active job",
                job.isCancelRequested());
        } finally {
            RevaProgramManager.unregisterProgram(saveable);
            saveable.release(this);
            try {
                file.delete();
            } catch (Exception ignore) {
                // best-effort cleanup of the temporary project file
            }
        }
    }
}
