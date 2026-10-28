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

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import reva.plugin.ConfigManager;

/**
 * Files one copy of a program into a caller-configured root project folder
 * after analysis. Snapshot creation is opt-in: an empty, null, path-like, or
 * dot-valued folder name disables it, and nothing in the project is created,
 * hidden, or refused until a single root-level folder name is configured.
 */
public final class ProjectSnapshots {

    private ProjectSnapshots() {}

    /**
     * The configured root-level snapshot folder, or an empty string when
     * snapshots are disabled or no {@link ConfigManager} is registered.
     * This is the only source of snapshot visibility policy: an empty result
     * means no project folder is hidden or refused.
     *
     * @return the normalized configured folder name, or {@code ""}
     */
    public static String configuredFolder() {
        ConfigManager config = RevaInternalServiceRegistry.getService(ConfigManager.class);
        return config == null ? "" : rootFolderName(config.getSnapshotFolder());
    }

    /**
     * Whether a project path points into the configured root-level snapshot
     * folder. An empty, null, path-like, or dot-valued configuration matches
     * nothing.
     *
     * @param projectPath a Ghidra project path such as {@code /snapshots/snapshot-x}
     * @param configuredFolder the configured root-level folder name, e.g. {@code snapshots}
     * @return true when the first path element is the configured folder
     */
    public static boolean isSnapshotPath(String projectPath, String configuredFolder) {
        String folder = rootFolderName(configuredFolder);
        if (folder.isEmpty() || projectPath == null) {
            return false;
        }
        String path = projectPath.trim().replace('\\', '/');
        int start = 0;
        while (start < path.length() && path.charAt(start) == '/') {
            start++;
        }
        int end = path.indexOf('/', start);
        String first = end < 0 ? path.substring(start) : path.substring(start, end);
        return folder.equals(first);
    }

    /**
     * Whether a folder name names the configured root-level snapshot folder.
     * Only an exact single-name match counts; an empty, null, path-like, or
     * dot-valued configuration matches nothing.
     *
     * @param folderName a single project folder name
     * @param configuredFolder the configured root-level folder name, e.g. {@code snapshots}
     * @return true when the name exactly matches the configured folder
     */
    public static boolean isSnapshotFolder(String folderName, String configuredFolder) {
        String folder = rootFolderName(configuredFolder);
        if (folder.isEmpty() || folderName == null) {
            return false;
        }
        return folder.equals(folderName.trim());
    }

    /**
     * Save one copy of {@code program} as
     * {@code <configured root folder>/<configured prefix><program name>} unless
     * a file of that name is already there. A blank, path-like, or dot-valued
     * folder name disables the feature and returns null.
     *
     * <p>The snapshot is bookkeeping, never a tool result: the program's domain
     * file supplies the project, and any failure is logged and swallowed so a
     * snapshot problem can never fail the analysis job.
     *
     * @param program the program whose analysis just succeeded
     * @param folderName the single root-level project folder to create the copy
     *        in; blank, path-like, {@code .}, or {@code ..} disables
     * @param filePrefix the copy's file-name prefix
     * @param monitor monitor for the copy
     * @return the copy's project pathname, or null when disabled, when the
     *         program has no project file, the snapshot already exists, or the
     *         copy failed
     */
    public static String createIfConfigured(Program program, String folderName,
            String filePrefix, TaskMonitor monitor) {
        String configuredFolder = rootFolderName(folderName);
        if (configuredFolder.isEmpty()) {
            return null;
        }
        try {
            DomainFile source = program.getDomainFile();
            if (source == null) {
                return null;
            }
            DomainFolder root = source.getParent().getProjectData().getRootFolder();
            DomainFolder folder = root.getFolder(configuredFolder);
            if (folder == null) {
                folder = root.createFolder(configuredFolder);
            }
            String name = (filePrefix == null ? "" : filePrefix) + program.getName();
            for (DomainFile existing : folder.getFiles()) {
                if (name.equals(existing.getName())) {
                    return null;
                }
            }
            // copyTo keeps the source file's name; rename the copy to the snapshot name.
            DomainFile copy = source.copyTo(folder, monitor);
            if (copy == null) {
                return null;
            }
            if (!name.equals(copy.getName())) {
                copy = copy.setName(name);
            }
            return copy.getPathname();
        } catch (Exception e) {
            Msg.warn(ProjectSnapshots.class,
                "Could not save project snapshot for " + program.getName() + ": "
                    + e.getMessage(), e);
            return null;
        }
    }

    /**
     * Return {@code folder} when it is a usable root-level project folder name,
     * or an empty string when snapshots must stay disabled. Rejects null,
     * blank, any name containing {@code /} or {@code \\}, and the dot names
     * {@code .} and {@code ..}.
     */
    private static String rootFolderName(String folder) {
        if (folder == null) {
            return "";
        }
        String name = folder.trim();
        if (name.isEmpty() || name.contains("/") || name.contains("\\")
                || name.equals(".") || name.equals("..")) {
            return "";
        }
        return name;
    }
}
