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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Resolves and validates script directory paths so the read/write/edit/run
 * tools all agree on which paths are legitimate. Holds:
 * <ul>
 *   <li>Readable directories: every directory the LLM may read scripts from
 *       (user scripts dir + system scripts dirs + bundle dirs).</li>
 *   <li>Writeable directories: subset where new scripts may be written.
 *       System scripts dirs (under the Ghidra install root) are intentionally
 *       excluded so the LLM cannot stomp shipped scripts.</li>
 *   <li>Default write directory: where {@code write-script} drops new files
 *       given a bare {@code scriptName} (defaults to the user scripts dir).</li>
 * </ul>
 */
public class ScriptDirectoryManager {

    private final List<Path> readableDirectories;
    private final List<Path> writeableDirectories;
    private final Path defaultWriteDirectory;

    public ScriptDirectoryManager(
            List<Path> readableDirectories,
            List<Path> writeableDirectories,
            Path defaultWriteDirectory) {
        Objects.requireNonNull(readableDirectories, "readableDirectories");
        Objects.requireNonNull(writeableDirectories, "writeableDirectories");
        Objects.requireNonNull(defaultWriteDirectory, "defaultWriteDirectory");

        List<Path> normalisedReadable = normalise(readableDirectories);
        List<Path> normalisedWriteable = normalise(writeableDirectories);
        Path normalisedDefault = defaultWriteDirectory.toAbsolutePath().normalize();

        if (!normalisedWriteable.contains(normalisedDefault)) {
            throw new IllegalArgumentException(
                "defaultWriteDirectory must be among writeableDirectories: "
                    + defaultWriteDirectory);
        }

        this.readableDirectories = Collections.unmodifiableList(normalisedReadable);
        this.writeableDirectories = Collections.unmodifiableList(normalisedWriteable);
        this.defaultWriteDirectory = normalisedDefault;
    }

    private static List<Path> normalise(List<Path> dirs) {
        List<Path> out = new ArrayList<>(dirs.size());
        for (Path p : dirs) {
            out.add(p.toAbsolutePath().normalize());
        }
        return out;
    }

    public List<Path> getReadableDirectories() {
        return readableDirectories;
    }

    public List<Path> getWriteableDirectories() {
        return writeableDirectories;
    }

    public Path getDefaultWriteDirectory() {
        return defaultWriteDirectory;
    }

    public boolean isInsideReadableDirectory(Path path) {
        return isInsideAny(path, readableDirectories);
    }

    public boolean isInsideWriteableDirectory(Path path) {
        return isInsideAny(path, writeableDirectories);
    }

    private static boolean isInsideAny(Path path, List<Path> dirs) {
        Path lexical = path.toAbsolutePath().normalize();
        Path real = resolveRealPath(lexical);
        for (Path dir : dirs) {
            // Compare against both the lexical and the real form: lexical
            // catches the common case quickly, real catches symlink-traversal
            // (a path under dir/ whose components symlink outside dir/).
            Path dirReal = resolveRealPath(dir);
            if (lexical.startsWith(dir) && real.startsWith(dirReal)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Resolve {@code p} to its real on-disk path, walking symlinks. For paths
     * whose target doesn't exist yet (e.g. a {@code write-script} destination)
     * we recurse into the deepest existing ancestor and re-attach the
     * remaining components — that way a symlinked parent is still detected
     * even if the file itself is about to be created.
     */
    private static Path resolveRealPath(Path p) {
        Path current = p;
        try {
            return current.toRealPath();
        } catch (IOException e) {
            // Walk up until we find an existing ancestor, resolve that, then
            // re-append the suffix.
            Path suffix = current.getFileName();
            Path parent = current.getParent();
            while (parent != null) {
                try {
                    return parent.toRealPath().resolve(suffix);
                } catch (IOException ignored) {
                    suffix = parent.getFileName() == null
                        ? suffix
                        : parent.getFileName().resolve(suffix);
                    parent = parent.getParent();
                }
            }
            return p;
        }
    }

    /**
     * Search readable directories (in order) for a script with the given file
     * name. First match wins, matching Ghidra's own {@code findScriptByName}
     * behavior.
     *
     * <p>Rejects anything that isn't a simple file name: an LLM-supplied
     * {@code name} containing path separators, parent references, or an
     * absolute path could otherwise escape the readable directories via
     * {@code dir.resolve(name)} and reach arbitrary files on disk.
     */
    public Optional<Path> findScriptByName(String name) {
        if (!isSimpleFileName(name)) {
            return Optional.empty();
        }
        for (Path dir : readableDirectories) {
            Path candidate = dir.resolve(name);
            if (Files.isRegularFile(candidate)) {
                return Optional.of(candidate);
            }
        }
        return Optional.empty();
    }

    private static boolean isSimpleFileName(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        if (name.indexOf('/') >= 0 || name.indexOf('\\') >= 0) {
            return false;
        }
        if (name.equals(".") || name.equals("..")) {
            return false;
        }
        // Path.of("..") may parse without a separator; also reject any
        // candidate whose Path representation has more than one component.
        try {
            Path asPath = Path.of(name);
            if (asPath.isAbsolute() || asPath.getNameCount() != 1) {
                return false;
            }
        } catch (java.nio.file.InvalidPathException e) {
            return false;
        }
        return true;
    }

    /**
     * Walk every readable directory and collect all {@code .py} files
     * (non-recursive — scripts directly inside each registered directory).
     */
    public List<Path> listAllScripts() {
        List<Path> out = new ArrayList<>();
        for (Path dir : readableDirectories) {
            if (!Files.isDirectory(dir)) {
                continue;
            }
            try (Stream<Path> entries = Files.list(dir)) {
                entries
                    .filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().endsWith(".py"))
                    .forEach(out::add);
            } catch (IOException e) {
                // skip unreadable dirs silently — same behavior as
                // GhidraScriptUtil when bundle dirs are unavailable
            }
        }
        return out;
    }
}
