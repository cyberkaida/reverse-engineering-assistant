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

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.awt.Component;

import org.junit.Test;
import org.mockito.MockedStatic;

import docking.widgets.OptionDialog;

/**
 * Verifies PublicBindingConsentDialog.prompt() maps OptionDialog return codes to the
 * correct consent constants — guarding against an accidental button-order swap.
 */
public class PublicBindingConsentDialogTest {

    private void assertMapping(int dialogResult, int expected) {
        try (MockedStatic<OptionDialog> od = mockStatic(OptionDialog.class)) {
            od.when(() -> OptionDialog.showOptionDialog(
                    nullable(Component.class), anyString(), anyString(),
                    anyString(), anyString(), anyInt()))
                .thenReturn(dialogResult);
            assertEquals(expected, PublicBindingConsentDialog.prompt("warning"));
        }
    }

    @Test
    public void optionOneMapsToAllowOnce() {
        assertMapping(OptionDialog.OPTION_ONE, PublicBindingConsentDialog.ALLOW_ONCE);
    }

    @Test
    public void optionTwoMapsToAllowAlways() {
        assertMapping(OptionDialog.OPTION_TWO, PublicBindingConsentDialog.ALLOW_ALWAYS);
    }

    @Test
    public void cancelMapsToCancel() {
        assertMapping(OptionDialog.CANCEL_OPTION, PublicBindingConsentDialog.CANCEL);
    }
}
