package reva.tools;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.Map;

import org.junit.Test;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpSyncServer;
import reva.plugin.RevaProgramManager;

public class ProgramFromArgsTest {

    private static class Provider extends AbstractToolProvider {
        Provider() {
            super(mock(McpSyncServer.class));
        }

        @Override
        public void registerTools() {
        }

        Program resolve(Map<String, Object> args) throws ProgramValidationException {
            return getProgramFromArgs(args);
        }
    }

    @Test
    public void mapWithoutProgramPathResolvesToTheSoleKnownProgram() throws Exception {
        Program p = mock(Program.class);
        DomainFile df = mock(DomainFile.class);
        when(df.getPathname()).thenReturn("/only.exe");
        when(p.getDomainFile()).thenReturn(df);
        RevaProgramManager.registerProgram(p);
        try {
            assertSame(p, new Provider().resolve(Map.of()));
        } finally {
            RevaProgramManager.unregisterProgram(p);
        }
    }
}
