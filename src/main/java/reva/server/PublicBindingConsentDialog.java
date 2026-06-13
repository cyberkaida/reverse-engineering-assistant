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
package reva.server;

import docking.widgets.OptionDialog;

/**
 * Modal consent dialog shown (GUI mode only) when the MCP server is about to bind
 * to a non-localhost interface without API key authentication.
 */
public final class PublicBindingConsentDialog {

    /** The user cancelled — do not start the server. */
    public static final int CANCEL = 0;
    /** Start the server this session only; do not persist the choice. */
    public static final int ALLOW_ONCE = 1;
    /** Persist the allow-public-binding option, then start. */
    public static final int ALLOW_ALWAYS = 2;

    private PublicBindingConsentDialog() {
    }

    /**
     * Prompt the user. Safe to call from any thread (OptionDialog marshals to Swing).
     *
     * @param message the warning text to display
     * @return one of {@link #CANCEL}, {@link #ALLOW_ONCE}, {@link #ALLOW_ALWAYS}
     */
    public static int prompt(String message) {
        int result = OptionDialog.showOptionDialog(
            null,
            "ReVa: Public Network Binding Without Authentication",
            message,
            "Allow Once",
            "Allow Always",
            OptionDialog.WARNING_MESSAGE);
        switch (result) {
            case OptionDialog.OPTION_ONE:
                return ALLOW_ONCE;
            case OptionDialog.OPTION_TWO:
                return ALLOW_ALWAYS;
            default:
                return CANCEL;
        }
    }
}
