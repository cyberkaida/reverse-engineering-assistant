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

import docking.ActionContext;
import docking.action.MenuData;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import resources.Icons;

import reva.plugin.FollowMeService;

/**
 * Per-CodeBrowser toolbar toggle for Follow Me mode. Each instance subscribes to
 * the shared {@link FollowMeService} so that toggling in one tool window keeps
 * other instances in sync.
 */
public class FollowMeAction extends ToggleDockingAction implements FollowMeService.EnabledListener {

    private static final String ACTION_NAME = "ReVa Follow Me";
    private static final String MENU_GROUP = "ReVa";

    private final FollowMeService service;

    public FollowMeAction(String owner, FollowMeService service) {
        super(ACTION_NAME, owner);
        this.service = service;

        setToolBarData(new ToolBarData(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON, MENU_GROUP));
        setMenuBarData(new MenuData(
            new String[] { "Tools", MENU_GROUP, "Follow Me" }, MENU_GROUP));
        setDescription(
            "When enabled, ReVa will navigate the listing to the address of each tool result. " +
            "Useful for live demos. Configure read/write filters under Tool Options → ReVa Server Options.");
        setHelpLocation(new HelpLocation("ReVa", "Follow_Me"));

        setSelected(service.isEnabled());
        service.addEnabledListener(this);
    }

    @Override
    public void actionPerformed(ActionContext context) {
        // ToggleDockingAction flips its selected state before calling actionPerformed.
        service.setEnabled(isSelected());
    }

    @Override
    public void enabledChanged(boolean enabled) {
        // Service was toggled elsewhere (another CodeBrowser, programmatic call) —
        // mirror the change. Always run on the EDT since this updates UI state.
        // Read the live state inside the lambda so rapid toggles can't queue a
        // stale closure that flips the visible state back.
        Swing.runIfSwingOrRunLater(() -> {
            boolean current = service.isEnabled();
            if (isSelected() != current) {
                setSelected(current);
            }
        });
    }

    /** Detach from the service. Call from the owning plugin's cleanup. */
    public void dispose() {
        service.removeEnabledListener(this);
    }
}
