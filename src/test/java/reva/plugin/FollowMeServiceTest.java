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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.SwingUtilities;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;
import reva.plugin.config.InMemoryBackend;
import reva.server.McpServerManager;

/**
 * Unit tests for FollowMeService gating logic. Confirms that follow() reaches
 * GoToService only when the master toggle, mode, and per-kind config all line up.
 */
public class FollowMeServiceTest {

    @Mock
    private McpServerManager mockServerManager;
    @Mock
    private PluginTool mockTool;
    @Mock
    private GoToService mockGoToService;
    @Mock
    private Program mockProgram;

    private ConfigManager configManager;
    private FollowMeService service;

    private final AddressSpace defaultSpace = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        // Real ConfigManager backed by an in-memory store; defaults: follow reads/writes both true.
        configManager = new ConfigManager(new InMemoryBackend());

        // Default wiring: GUI mode, active CodeBrowser, GoToService available.
        when(mockServerManager.isHeadlessMode()).thenReturn(false);
        when(mockServerManager.getActiveTool()).thenReturn(mockTool);
        when(mockTool.getService(GoToService.class)).thenReturn(mockGoToService);
        when(mockGoToService.goTo(any(Address.class), any(Program.class))).thenReturn(true);

        // Mock AddressFactory access if anything queries it.
        AddressFactory mockFactory = org.mockito.Mockito.mock(AddressFactory.class);
        when(mockProgram.getAddressFactory()).thenReturn(mockFactory);

        service = new FollowMeService(configManager, mockServerManager);
    }

    @After
    public void tearDown() throws Exception {
        // Drain any pending Swing.runLater dispatches so they don't bleed into other tests.
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeAndWait(() -> {
            });
        }
    }

    private void drainEdt() throws InvocationTargetException, InterruptedException {
        SwingUtilities.invokeAndWait(() -> {
        });
    }

    private Address addr(long offset) {
        return defaultSpace.getAddress(offset);
    }

    @Test
    public void disabled_doesNotNavigate() throws Exception {
        // master toggle off (default)
        assertFalse(service.isEnabled());

        service.follow(mockProgram, addr(0x1000), FollowMeService.Kind.READ);
        drainEdt();

        verify(mockGoToService, never()).goTo(any(Address.class), any(Program.class));
    }

    @Test
    public void enabled_read_navigatesWhenFollowReadsTrue() throws Exception {
        service.setEnabled(true);

        service.follow(mockProgram, addr(0x1000), FollowMeService.Kind.READ);
        drainEdt();

        verify(mockGoToService, times(1)).goTo(addr(0x1000), mockProgram);
    }

    @Test
    public void enabled_write_navigatesWhenFollowWritesTrue() throws Exception {
        service.setEnabled(true);

        service.follow(mockProgram, addr(0x2000), FollowMeService.Kind.WRITE);
        drainEdt();

        verify(mockGoToService, times(1)).goTo(addr(0x2000), mockProgram);
    }

    @Test
    public void enabled_butReadsDisabled_doesNotNavigate() throws Exception {
        configManager.setFollowReads(false);
        service.setEnabled(true);

        service.follow(mockProgram, addr(0x3000), FollowMeService.Kind.READ);
        drainEdt();

        verify(mockGoToService, never()).goTo(any(Address.class), any(Program.class));
    }

    @Test
    public void enabled_butWritesDisabled_doesNotNavigate() throws Exception {
        configManager.setFollowWrites(false);
        service.setEnabled(true);

        service.follow(mockProgram, addr(0x4000), FollowMeService.Kind.WRITE);
        drainEdt();

        verify(mockGoToService, never()).goTo(any(Address.class), any(Program.class));
    }

    @Test
    public void enabled_headlessMode_doesNotNavigate() throws Exception {
        when(mockServerManager.isHeadlessMode()).thenReturn(true);
        service.setEnabled(true);

        service.follow(mockProgram, addr(0x5000), FollowMeService.Kind.READ);
        drainEdt();

        verify(mockGoToService, never()).goTo(any(Address.class), any(Program.class));
    }

    @Test
    public void enabled_noActiveTool_doesNotNavigate() throws Exception {
        when(mockServerManager.getActiveTool()).thenReturn(null);
        service.setEnabled(true);

        service.follow(mockProgram, addr(0x6000), FollowMeService.Kind.READ);
        drainEdt();

        verify(mockGoToService, never()).goTo(any(Address.class), any(Program.class));
    }

    @Test
    public void enabled_nullArguments_doesNotNavigate() throws Exception {
        service.setEnabled(true);

        service.follow(null, addr(0x7000), FollowMeService.Kind.READ);
        service.follow(mockProgram, null, FollowMeService.Kind.READ);
        service.follow(mockProgram, addr(0x7000), null);
        drainEdt();

        verify(mockGoToService, never()).goTo(any(Address.class), any(Program.class));
    }

    @Test
    public void coalesce_consecutiveSameAddressIsSkipped() throws Exception {
        service.setEnabled(true);

        service.follow(mockProgram, addr(0x8000), FollowMeService.Kind.READ);
        service.follow(mockProgram, addr(0x8000), FollowMeService.Kind.READ);
        service.follow(mockProgram, addr(0x8000), FollowMeService.Kind.WRITE);
        drainEdt();

        // Only the first call should have navigated.
        verify(mockGoToService, times(1)).goTo(addr(0x8000), mockProgram);
    }

    @Test
    public void coalesce_differentAddressNavigatesAgain() throws Exception {
        service.setEnabled(true);

        service.follow(mockProgram, addr(0x9000), FollowMeService.Kind.READ);
        service.follow(mockProgram, addr(0xa000), FollowMeService.Kind.READ);
        drainEdt();

        verify(mockGoToService, times(1)).goTo(addr(0x9000), mockProgram);
        verify(mockGoToService, times(1)).goTo(addr(0xa000), mockProgram);
    }

    @Test
    public void coalesce_resetsWhenDisabledAndReenabled() throws Exception {
        service.setEnabled(true);

        service.follow(mockProgram, addr(0xb000), FollowMeService.Kind.READ);
        drainEdt();

        // Toggle off then on; the same address should navigate again afterwards.
        service.setEnabled(false);
        service.setEnabled(true);

        service.follow(mockProgram, addr(0xb000), FollowMeService.Kind.READ);
        drainEdt();

        verify(mockGoToService, times(2)).goTo(addr(0xb000), mockProgram);
    }

    @Test
    public void enabledListener_firesOnTransitionsOnly() {
        AtomicInteger transitions = new AtomicInteger();
        service.addEnabledListener(enabled -> transitions.incrementAndGet());

        service.setEnabled(false); // no transition (already false)
        service.setEnabled(true); // transition
        service.setEnabled(true); // no transition
        service.setEnabled(false); // transition

        assertEquals(2, transitions.get());
    }

    @Test
    public void enabledListener_canBeRemoved() {
        AtomicInteger transitions = new AtomicInteger();
        FollowMeService.EnabledListener l = enabled -> transitions.incrementAndGet();
        service.addEnabledListener(l);
        service.removeEnabledListener(l);

        service.setEnabled(true);
        assertEquals(0, transitions.get());
    }

    @Test
    public void isEnabled_reflectsState() {
        assertFalse(service.isEnabled());
        service.setEnabled(true);
        assertTrue(service.isEnabled());
        service.setEnabled(false);
        assertFalse(service.isEnabled());
    }
}
