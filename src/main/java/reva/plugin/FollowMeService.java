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
package reva.plugin;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;
import reva.server.McpServerManager;
import reva.util.AddressUtil;

/**
 * Demo-time follow mode. When enabled in the GUI, requests the active CodeBrowser
 * to navigate to the address each ReVa tool just acted on so observers can watch
 * the AI work in real time.
 *
 * <p>The service is GUI-only — it is registered with {@code RevaInternalServiceRegistry}
 * exclusively by the GUI-mode {@link McpServerManager} constructor. In headless and
 * stdio modes the registry returns {@code null}, so {@code AbstractToolProvider}'s
 * {@code followRead}/{@code followWrite} helpers become no-ops automatically.
 *
 * <p>The master {@code enabled} flag is transient: it lives only as long as the
 * Ghidra session and is toggled via the per-tool {@code FollowMeAction}. The
 * read/write sub-options live in {@link ConfigManager} and persist across sessions.
 */
public class FollowMeService {

    /** Whether a tool action read or wrote at the navigated address. */
    public enum Kind {
        READ, WRITE
    }

    /** Listener notified when the master enabled flag changes. */
    public interface EnabledListener {
        void enabledChanged(boolean enabled);
    }

    private final ConfigManager configManager;
    private final McpServerManager serverManager;

    private volatile boolean enabled = false;

    private final Set<EnabledListener> listeners = ConcurrentHashMap.newKeySet();

    // Coalescing — suppress consecutive navigations to the same target. The
    // pair is read+written atomically under coalesceLock so concurrent
    // follow() calls from different Jetty workers cannot both pass the dupe
    // check on identical inputs.
    private final Object coalesceLock = new Object();
    private Program lastProgram;
    private Address lastAddress;

    public FollowMeService(ConfigManager configManager, McpServerManager serverManager) {
        this.configManager = configManager;
        this.serverManager = serverManager;
    }

    /** @return whether follow mode is currently active. */
    public boolean isEnabled() {
        return enabled;
    }

    /** Enable or disable follow mode and notify listeners. */
    public void setEnabled(boolean enabled) {
        if (this.enabled == enabled) {
            return;
        }
        this.enabled = enabled;
        if (!enabled) {
            // Reset coalescing state so re-enabling will navigate again.
            synchronized (coalesceLock) {
                lastProgram = null;
                lastAddress = null;
            }
        }
        Msg.info(this, "ReVa follow mode " + (enabled ? "enabled" : "disabled"));
        for (EnabledListener l : listeners) {
            try {
                l.enabledChanged(enabled);
            } catch (Exception e) {
                Msg.error(this, "Error notifying follow-me listener", e);
            }
        }
    }

    public void addEnabledListener(EnabledListener listener) {
        listeners.add(listener);
    }

    public void removeEnabledListener(EnabledListener listener) {
        listeners.remove(listener);
    }

    /**
     * Navigate the active CodeBrowser to {@code address} when follow mode is enabled
     * and the corresponding kind sub-option is on. Safe to call from any thread —
     * the underlying {@code GoToService} call is dispatched to the Swing EDT.
     *
     * @param program the program containing the address (must be currently open in
     *                the active CodeBrowser for navigation to actually occur)
     * @param address the address to navigate to
     * @param kind whether the calling tool just read or wrote at this address
     */
    public void follow(Program program, Address address, Kind kind) {
        if (!enabled || program == null || address == null || kind == null) {
            return;
        }
        if (kind == Kind.READ && !configManager.isFollowReads()) {
            return;
        }
        if (kind == Kind.WRITE && !configManager.isFollowWrites()) {
            return;
        }
        if (serverManager.isHeadlessMode()) {
            return;
        }

        PluginTool tool = serverManager.getActiveTool();
        if (tool == null) {
            return;
        }
        GoToService goToService = tool.getService(GoToService.class);
        if (goToService == null) {
            return;
        }

        // Coalesce: don't re-navigate to the same target back-to-back. The
        // check-and-set must be atomic so concurrent calls with the same
        // target fire goTo at most once (the first; others see their own
        // values and return).
        synchronized (coalesceLock) {
            if (program.equals(lastProgram) && address.equals(lastAddress)) {
                return;
            }
            lastProgram = program;
            lastAddress = address;
        }

        Swing.runLater(() -> {
            boolean navigated = goToService.goTo(address, program);
            if (!navigated) {
                // Debug-level: would otherwise spam the console during demos
                // where the AI flips between programs that aren't the active one.
                Msg.debug(FollowMeService.class,
                    "follow-me: could not navigate to " + AddressUtil.formatAddress(address) +
                    " in " + program.getName() +
                    " (program may not be active in the CodeBrowser)");
            }
        });
    }
}
