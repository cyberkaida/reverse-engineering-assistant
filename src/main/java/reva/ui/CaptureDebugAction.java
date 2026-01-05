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
package reva.ui;

import java.io.File;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.dialogs.InputDialog;

import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

import reva.debug.DebugCaptureService;

/**
 * Menu action for capturing debug information for troubleshooting.
 * Accessible from Tools -> ReVa -> Capture Debug Info
 */
public class CaptureDebugAction extends DockingAction {

    private static final String ACTION_NAME = "Capture Debug Info";
    private static final String MENU_GROUP = "ReVa";

    private final PluginTool tool;

    /**
     * Create a new CaptureDebugAction.
     * @param owner The owner plugin name
     * @param tool The plugin tool for showing dialogs
     */
    public CaptureDebugAction(String owner, PluginTool tool) {
        super(ACTION_NAME, owner);
        this.tool = tool;

        // Set up menu location: Tools -> ReVa -> Capture Debug Info
        setMenuBarData(new MenuData(
            new String[] { "Tools", MENU_GROUP, ACTION_NAME }
        ));

        setEnabled(true);
        setDescription("Capture debug information for troubleshooting ReVa issues");
    }

    @Override
    public void actionPerformed(ActionContext context) {
        // Show input dialog for user message
        InputDialog dialog = new InputDialog(
            "Capture Debug Info",
            "Describe the issue or context (optional):"
        );

        tool.showDialog(dialog);

        if (dialog.isCanceled()) {
            return;
        }

        String userMessage = dialog.getValue();
        if (userMessage == null || userMessage.isBlank()) {
            userMessage = "(No message provided)";
        }

        try {
            DebugCaptureService service = new DebugCaptureService();
            File zipFile = service.captureDebugInfo(userMessage);

            // Show success message with file location
            Msg.showInfo(
                getClass(),
                tool.getToolFrame(),
                "Debug Info Captured",
                "Debug information saved to:\n" + zipFile.getAbsolutePath()
            );

        } catch (Exception e) {
            Msg.showError(
                getClass(),
                tool.getToolFrame(),
                "Capture Failed",
                "Failed to capture debug info: " + e.getMessage(),
                e
            );
        }
    }
}
