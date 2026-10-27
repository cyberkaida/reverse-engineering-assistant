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
package reva.util;

import static org.junit.Assert.*;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.base.project.GhidraProject;
import ghidra.framework.main.AppInfo;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;
import reva.plugin.RevaProgramManager;
import reva.tools.ProgramValidationException;

/**
 * Sole-program resolution against a real headless project: programs saved to
 * the project but not held open by ReVa (after import-file, or after
 * checkin-program released them) still resolve from a missing programPath.
 */
public class ProgramLookupUtilProjectTest extends AbstractGhidraHeadlessIntegrationTest {

    private GhidraProject project;
    private Path projectDir;

    @Before
    public void setUp() throws Exception {
        RevaProgramManager.cleanup();
        // The test directory sits under the repository, whose path may hold a
        // dot-prefixed element (.worktrees) that ProjectLocator rejects.
        projectDir = Files.createTempDirectory("reva-lookup");
        project = GhidraProject.createProject(projectDir.toString(), "LookupProject", true);
        assertSame(project.getProject(), AppInfo.getActiveProject());
    }

    @After
    public void tearDown() {
        RevaProgramManager.cleanup();
        if (project != null) {
            project.close();
        }
        if (projectDir != null) {
            deleteRecursively(projectDir.toFile());
        }
    }

    private static void deleteRecursively(File f) {
        File[] children = f.listFiles();
        if (children != null) {
            for (File c : children) {
                deleteRecursively(c);
            }
        }
        f.delete();
    }

    /** Saves a new program to the project root and releases it, as import-file leaves it. */
    private void saveToProject(String name) throws Exception {
        Language language = getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        ProgramDB p = new ProgramDB(name, language, language.getDefaultCompilerSpec(), this);
        try {
            project.getProjectData().getRootFolder().createFile(name, p, TaskMonitor.DUMMY);
        } finally {
            p.release(this);
        }
    }

    @Test
    public void programSavedToProjectButNotCachedResolvesFromNullPath() throws Exception {
        saveToProject("only.exe");
        assertTrue("nothing is open or cached yet", RevaProgramManager.getAllKnownPrograms().isEmpty());

        Program p = ProgramLookupUtil.getValidatedProgram(null);

        assertNotNull(p);
        assertFalse(p.isClosed());
        assertEquals("/only.exe", p.getDomainFile().getPathname());
        assertTrue("the opened program is cached", RevaProgramManager.isProgramCached(p));
    }

    @Test
    public void nullPathStillResolvesAfterReleaseFromCache() throws Exception {
        saveToProject("only.exe");
        Program first = ProgramLookupUtil.getValidatedProgram(null);
        assertTrue(RevaProgramManager.releaseProgramFromCache(first));
        assertTrue("released, as checkin-program leaves it", RevaProgramManager.getAllKnownPrograms().isEmpty());

        Program again = ProgramLookupUtil.getValidatedProgram(null);

        assertFalse(again.isClosed());
        assertEquals("/only.exe", again.getDomainFile().getPathname());
    }

    @Test
    public void twoProjectProgramsAreListed() throws Exception {
        saveToProject("a.exe");
        saveToProject("b.exe");
        try {
            ProgramLookupUtil.getValidatedProgram(null);
            fail("expected ProgramValidationException");
        } catch (ProgramValidationException e) {
            assertEquals("programPath is required when several programs are open:\n  - /a.exe\n  - /b.exe",
                e.getMessage());
        }
        assertTrue("nothing is opened to build the listing", RevaProgramManager.getAllKnownPrograms().isEmpty());
    }

    @Test
    public void emptyProjectSaysNoProgramIsOpen() {
        try {
            ProgramLookupUtil.getValidatedProgram(null);
            fail("expected ProgramValidationException");
        } catch (ProgramValidationException e) {
            assertEquals("No program is open. Import one with import-file.", e.getMessage());
        }
    }
}
