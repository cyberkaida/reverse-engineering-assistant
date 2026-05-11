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

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptUtil;

/**
 * Builds a {@link ScriptDirectoryManager} from Ghidra's live script directory
 * registry. Boundary class — depends on {@code GhidraScriptUtil} statics, so
 * not unit-tested directly; the {@code ScriptDirectoryManager} contract is
 * covered by {@link ScriptDirectoryManagerTest} with manually constructed
 * directories.
 */
final class GhidraDirectoryFactory {

    private GhidraDirectoryFactory() {}

    static ScriptDirectoryManager build() {
        ResourceFile userDir = GhidraScriptUtil.getUserScriptDirectory();
        Path userPath = userDir.getFile(false).toPath();

        Set<Path> readable = new LinkedHashSet<>();
        readable.add(userPath);

        List<Path> writeable = new ArrayList<>();
        writeable.add(userPath);

        // System dirs are filesystem-discoverable and don't require the bundle
        // host to be initialized.
        try {
            for (ResourceFile dir : GhidraScriptUtil.getSystemScriptDirectories()) {
                readable.add(dir.getFile(false).toPath());
            }
        } catch (Exception ignored) {
            // best-effort enumeration — user dir suffices for basic operation
        }

        // Bundle / source dirs require GhidraScriptUtil.bundleHost to have been
        // initialized (GUI or PyGhidra launch). In the gradle integrationTest
        // JVM and other minimal contexts, bundleHost is null; fall back to
        // just the user + system dirs without failing the whole tool registration.
        if (GhidraScriptUtil.getBundleHost() != null) {
            try {
                for (ResourceFile dir : GhidraScriptUtil.getScriptSourceDirectories()) {
                    Path p = dir.getFile(false).toPath();
                    readable.add(p);
                    if (!GhidraScriptUtil.isSystemScript(dir) && !writeable.contains(p)) {
                        writeable.add(p);
                    }
                }
            } catch (Exception ignored) {
                // ditto — degrade gracefully
            }
        }

        return new ScriptDirectoryManager(
            new ArrayList<>(readable),
            writeable,
            userPath);
    }
}
