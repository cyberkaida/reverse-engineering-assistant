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
package reva.tools.scripts;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Unit tests for {@link ScriptDirectoryManager}.
 *
 * Tests the directory model: which dirs are readable (all script source dirs),
 * which are writeable (user-controlled, never system), path containment checks
 * used by write-script / edit-script safety guards, and script name resolution.
 */
public class ScriptDirectoryManagerTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private Path userDir;        // writeable
    private Path systemDir;      // readable only (read-only system scripts dir)
    private Path extraReadDir;   // readable only
    private Path outsideDir;     // not registered at all
    private ScriptDirectoryManager mgr;

    @Before
    public void setUp() throws IOException {
        userDir = tmp.newFolder("user_scripts").toPath();
        systemDir = tmp.newFolder("system_scripts").toPath();
        extraReadDir = tmp.newFolder("plugin_scripts").toPath();
        outsideDir = tmp.newFolder("somewhere_else").toPath();

        mgr = new ScriptDirectoryManager(
            List.of(userDir, systemDir, extraReadDir),  // readable
            List.of(userDir),                            // writeable (user only)
            userDir);                                    // default write target
    }

    @Test
    public void readableDirectoriesAreReturnedAsConstructed() {
        List<Path> readable = mgr.getReadableDirectories();
        assertEquals(3, readable.size());
        assertTrue(readable.contains(userDir));
        assertTrue(readable.contains(systemDir));
        assertTrue(readable.contains(extraReadDir));
    }

    @Test
    public void writeableDirectoriesAreReturnedAsConstructed() {
        List<Path> writeable = mgr.getWriteableDirectories();
        assertEquals(1, writeable.size());
        assertTrue(writeable.contains(userDir));
    }

    @Test
    public void defaultWriteDirectoryIsTheUserDir() {
        assertEquals(userDir, mgr.getDefaultWriteDirectory());
    }

    @Test
    public void pathInsideUserDirIsReadableAndWriteable() {
        Path script = userDir.resolve("MyScript.py");
        assertTrue(mgr.isInsideReadableDirectory(script));
        assertTrue(mgr.isInsideWriteableDirectory(script));
    }

    @Test
    public void pathInsideSystemDirIsReadableButNotWriteable() {
        Path script = systemDir.resolve("ShippedScript.py");
        assertTrue(mgr.isInsideReadableDirectory(script));
        assertFalse(mgr.isInsideWriteableDirectory(script));
    }

    @Test
    public void pathOutsideAllRegisteredDirsIsNeitherReadableNorWriteable() {
        Path script = outsideDir.resolve("Rogue.py");
        assertFalse(mgr.isInsideReadableDirectory(script));
        assertFalse(mgr.isInsideWriteableDirectory(script));
    }

    @Test
    public void siblingPathTrickIsRejected() {
        // /tmp/user_scripts vs /tmp/user_scripts2 — make sure prefix-only
        // matching does not accept the latter as inside the former.
        Path sibling = userDir.getParent().resolve(userDir.getFileName() + "2");
        Path file = sibling.resolve("Rogue.py");
        assertFalse(mgr.isInsideReadableDirectory(file));
        assertFalse(mgr.isInsideWriteableDirectory(file));
    }

    @Test
    public void findScriptByNameLocatesFileInReadableDir() throws IOException {
        Path target = systemDir.resolve("Targeted.py");
        Files.writeString(target, "# test\n");
        Optional<Path> found = mgr.findScriptByName("Targeted.py");
        assertTrue("script should be found", found.isPresent());
        assertEquals(target.toAbsolutePath().normalize(),
            found.get().toAbsolutePath().normalize());
    }

    @Test
    public void findScriptByNameReturnsEmptyWhenAbsent() {
        Optional<Path> found = mgr.findScriptByName("DoesNotExist.py");
        assertFalse(found.isPresent());
    }

    @Test
    public void findScriptByNameUsesFirstMatchAcrossReadableDirs() throws IOException {
        // When the same name exists in multiple readable dirs, the first
        // readable dir (as constructed) wins — matches Ghidra's own behavior.
        Path inUser = userDir.resolve("Shadow.py");
        Path inSystem = systemDir.resolve("Shadow.py");
        Files.writeString(inUser, "user\n");
        Files.writeString(inSystem, "system\n");
        Optional<Path> found = mgr.findScriptByName("Shadow.py");
        assertTrue(found.isPresent());
        assertEquals(inUser.toAbsolutePath().normalize(),
            found.get().toAbsolutePath().normalize());
    }

    @Test
    public void listAllScriptsReturnsPyFilesFromAllReadableDirs() throws IOException {
        Files.writeString(userDir.resolve("A.py"), "# a\n");
        Files.writeString(systemDir.resolve("B.py"), "# b\n");
        Files.writeString(extraReadDir.resolve("C.py"), "# c\n");
        Files.writeString(userDir.resolve("not_a_script.txt"), "junk");

        List<Path> all = mgr.listAllScripts();
        assertEquals(3, all.size());
        assertTrue(all.stream().anyMatch(p -> p.getFileName().toString().equals("A.py")));
        assertTrue(all.stream().anyMatch(p -> p.getFileName().toString().equals("B.py")));
        assertTrue(all.stream().anyMatch(p -> p.getFileName().toString().equals("C.py")));
    }

    @Test
    public void listAllScriptsIgnoresNonPyFiles() throws IOException {
        Files.writeString(userDir.resolve("readme.md"), "# readme\n");
        Files.writeString(userDir.resolve("notes.txt"), "notes\n");
        List<Path> all = mgr.listAllScripts();
        assertTrue("non-.py files should not appear", all.isEmpty());
    }

    @Test
    public void listAllScriptsSkipsDirectoriesThatDoNotExist() throws IOException {
        Path missing = tmp.getRoot().toPath().resolve("nonexistent");
        ScriptDirectoryManager partial = new ScriptDirectoryManager(
            List.of(userDir, missing),
            List.of(userDir),
            userDir);
        Files.writeString(userDir.resolve("Only.py"), "x");
        List<Path> all = partial.listAllScripts();
        assertEquals(1, all.size());
        assertEquals("Only.py", all.get(0).getFileName().toString());
    }

    /**
     * Path-traversal hardening. findScriptByName takes an LLM-supplied string;
     * if we let {@code dir.resolve(name)} traverse, an attacker could read any
     * file by name like {@code "../../../etc/passwd"}. Reject anything that
     * isn't a simple file name (no path separators, no parent refs).
     */
    @Test
    public void findScriptByNameRejectsParentReferenceTraversal() throws IOException {
        // Plant a file *outside* every registered directory so the assertion
        // would actually return it if traversal worked.
        Path secret = outsideDir.resolve("secret.py");
        Files.writeString(secret, "# off-limits");

        // Build a relative '..' chain from userDir → outsideDir
        String traversal = "../" + outsideDir.getFileName() + "/secret.py";
        assertEquals(Optional.empty(), mgr.findScriptByName(traversal));
    }

    @Test
    public void findScriptByNameRejectsForwardSlashSeparator() {
        assertEquals(Optional.empty(), mgr.findScriptByName("subdir/foo.py"));
    }

    @Test
    public void findScriptByNameRejectsBackslashSeparator() {
        // Windows-style separator; even on POSIX this is suspicious and worth
        // refusing — script names are simple file names.
        assertEquals(Optional.empty(), mgr.findScriptByName("subdir\\foo.py"));
    }

    @Test
    public void findScriptByNameRejectsAbsolutePath() throws IOException {
        // Files.isRegularFile on an absolute path bypasses the dir prefix and
        // hands back any file on disk if resolve() honours absolute paths.
        Path absoluteOutside = outsideDir.resolve("absolute.py");
        Files.writeString(absoluteOutside, "# off-limits");
        assertEquals(Optional.empty(),
            mgr.findScriptByName(absoluteOutside.toString()));
    }

    @Test
    public void findScriptByNameStillResolvesPlainName() throws IOException {
        Files.writeString(userDir.resolve("plain.py"), "# fine");
        Optional<Path> hit = mgr.findScriptByName("plain.py");
        assertTrue("Plain file names must still resolve", hit.isPresent());
        assertEquals(userDir.resolve("plain.py"), hit.get());
    }

    /**
     * Symlink-traversal hardening for write/edit paths. {@code
     * isInsideWriteableDirectory} relies on lexical {@code startsWith} after
     * {@code normalize()}, which does not follow symlinks. A directory entry
     * under {@code userDir} that symlinks to an outside path would pass the
     * containment check and then resolve to a file outside the sandbox during
     * the actual write — escaping the allowed dirs.
     */
    @Test
    public void isInsideWriteableRejectsPathThroughSymlinkToOutsideDir() throws IOException {
        // userDir/escape → outsideDir, so userDir/escape/leak.py lexically
        // starts with userDir but the real path lives in outsideDir.
        Path link = userDir.resolve("escape");
        try {
            Files.createSymbolicLink(link, outsideDir);
        } catch (UnsupportedOperationException | java.nio.file.FileSystemException e) {
            org.junit.Assume.assumeNoException(
                "Filesystem doesn't support symlinks; skipping", e);
        }
        Path leak = link.resolve("leak.py");
        assertFalse(
            "Symlinked path escaping userDir must not pass writeable check",
            mgr.isInsideWriteableDirectory(leak));
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorRejectsDefaultWriteDirNotInWriteableList() {
        new ScriptDirectoryManager(
            List.of(userDir),
            List.of(userDir),
            systemDir);  // not in writeable list
    }

    @Test(expected = NullPointerException.class)
    public void constructorRejectsNullReadableList() {
        new ScriptDirectoryManager(null, List.of(userDir), userDir);
    }
}
