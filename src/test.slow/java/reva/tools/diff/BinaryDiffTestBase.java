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
package reva.tools.diff;

import java.util.ArrayList;
import java.util.List;

import org.junit.After;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import reva.RevaIntegrationTestBase;
import reva.plugin.RevaProgramManager;

/**
 * Base class for binary-diff integration tests.
 *
 * <p>Adds a helper for creating and registering a SECOND program in the same test
 * environment, since {@link RevaIntegrationTestBase} only provisions one. All
 * additional programs are released and unregistered in {@link #releaseExtraPrograms()}.</p>
 */
public abstract class BinaryDiffTestBase extends RevaIntegrationTestBase {

    private final List<Program> extraPrograms = new ArrayList<>();

    /**
     * Register the base-class program with {@link RevaProgramManager} so
     * {@code programPath} lookups resolve. The base class only calls
     * {@code serverManager.programOpened} which doesn't populate the manager's
     * explicit-registration map; lookups otherwise rely on {@code env.open(program)}
     * which can only "open" one program at a time.
     */
    @Override
    protected void onGhidraStart() {
        super.onGhidraStart();
        if (program != null) {
            RevaProgramManager.registerProgram(program);
        }
    }

    /**
     * Create a second (or third, ...) program, register it with the MCP server,
     * and add it to the auto-release list.
     *
     * @param name short name for the new program; turned into a project file
     * @param languageId Ghidra language string, e.g. {@code "x86:LE:64:default"}
     * @return the newly created Program
     */
    protected Program createAndOpenSecondProgram(String name, String languageId) throws Exception {
        Program extra = createDefaultProgram(name, languageId, this);

        if (extra.getMemory().getBlocks().length == 0) {
            int txId = extra.startTransaction("Add test memory");
            try {
                extra.getMemory().createInitializedBlock("test",
                    extra.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000),
                    0x1000, (byte) 0, TaskMonitor.DUMMY, false);
            } finally {
                extra.endTransaction(txId, true);
            }
        }

        if (serverManager != null) {
            serverManager.programOpened(extra, tool);
        }
        RevaProgramManager.registerProgram(extra);

        extraPrograms.add(extra);
        return extra;
    }

    @After
    public void releaseExtraPrograms() {
        for (Program p : extraPrograms) {
            try {
                RevaProgramManager.unregisterProgram(p);
                if (serverManager != null) {
                    serverManager.programClosed(p, tool);
                }
                p.release(this);
            } catch (Exception e) {
                System.err.println("Failed to release extra program " + p.getName() + ": " + e.getMessage());
            }
        }
        extraPrograms.clear();
        if (program != null) {
            RevaProgramManager.unregisterProgram(program);
        }
    }
}
