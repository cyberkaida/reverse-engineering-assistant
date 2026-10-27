package reva.tools.project;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.Test;

import ghidra.framework.model.DomainFile;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

public class ProjectToolProviderTest {

    private static DomainFile versionedUnchanged(boolean checkedOut, boolean modified) {
        DomainFile df = mock(DomainFile.class);
        when(df.canAddToRepository()).thenReturn(false);
        when(df.canCheckin()).thenReturn(false);
        when(df.isVersioned()).thenReturn(true);
        when(df.isChanged()).thenReturn(false);
        when(df.isCheckedOut()).thenReturn(checkedOut);
        when(df.modifiedSinceCheckout()).thenReturn(modified);
        return df;
    }

    private ProjectToolProvider provider() {
        return new ProjectToolProvider(mock(McpSyncServer.class), true);
    }

    @Test
    public void checkinWithNoChangesIsSuccess() {
        CallToolResult r = provider().checkinPreValidation(versionedUnchanged(true, false), "/a.exe");
        assertNotNull(r);
        assertFalse(r.isError());
        String text = ((TextContent) r.content().get(0)).text();
        assertTrue(text, text.contains("\"success\":true"));
        assertTrue(text, text.contains("\"action\":\"no_changes\""));
        assertTrue(text, text.contains("\"programPath\":\"/a.exe\""));
        assertTrue(text, text.contains("\"message\":\"Program has no changes since checkout\""));
    }

    @Test
    public void checkinOfUncheckedOutFileStillErrors() {
        CallToolResult r = provider().checkinPreValidation(versionedUnchanged(false, false), "/a.exe");
        assertNotNull(r);
        assertTrue(r.isError());
    }

    @Test
    public void checkinWithChangesProceeds() {
        DomainFile df = mock(DomainFile.class);
        when(df.canCheckin()).thenReturn(true);
        assertNull(provider().checkinPreValidation(df, "/a.exe"));
    }

    @Test
    public void handBuiltRequiredListsDoNotRequireProgramPath() {
        McpSyncServer server = mock(McpSyncServer.class);
        new ProjectToolProvider(server, true).registerTools();
        org.mockito.ArgumentCaptor<io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification> cap =
            org.mockito.ArgumentCaptor.forClass(io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification.class);
        verify(server, atLeastOnce()).addTool(cap.capture());
        boolean sawCheckin = false;
        for (var spec : cap.getAllValues()) {
            var tool = spec.tool();
            assertFalse(tool.name() + " must not require programPath",
                required(tool).contains("programPath"));
            if (tool.name().equals("checkin-program")) {
                sawCheckin = true;
                assertTrue(required(tool).contains("message"));
                String desc = String.valueOf(((java.util.Map<?, ?>) ((java.util.Map<?, ?>) schema(tool).get("properties")).get("programPath")).get("description"));
                assertTrue(desc, desc.contains("Optional when exactly one program is open."));
            }
        }
        assertTrue(sawCheckin);
    }

    private static java.util.Map<?, ?> schema(io.modelcontextprotocol.spec.McpSchema.Tool tool) {
        return new com.fasterxml.jackson.databind.ObjectMapper().convertValue(tool.inputSchema(), java.util.Map.class);
    }

    private static java.util.List<?> required(io.modelcontextprotocol.spec.McpSchema.Tool tool) {
        Object r = schema(tool).get("required");
        return r == null ? java.util.List.of() : (java.util.List<?>) r;
    }

    private CallToolResult callAnalysisStatus(java.util.Map<String, Object> args) {
        McpSyncServer server = mock(McpSyncServer.class);
        new ProjectToolProvider(server, true).registerTools();
        org.mockito.ArgumentCaptor<io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification> cap =
            org.mockito.ArgumentCaptor.forClass(io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification.class);
        verify(server, atLeastOnce()).addTool(cap.capture());
        for (var spec : cap.getAllValues()) {
            if (spec.tool().name().equals("analysis-status")) {
                return spec.callHandler().apply(null,
                    new io.modelcontextprotocol.spec.McpSchema.CallToolRequest("analysis-status", args));
            }
        }
        throw new AssertionError("analysis-status not registered");
    }

    @Test
    public void analysisStatusWithNeitherArgumentUsesTheSoleKnownProgram() {
        reva.util.RevaInternalServiceRegistry.registerService(reva.services.AnalysisJobManager.class,
            mock(reva.services.AnalysisJobManager.class));
        ghidra.program.model.listing.Program p = mock(ghidra.program.model.listing.Program.class);
        DomainFile df = mock(DomainFile.class);
        when(df.getPathname()).thenReturn("/only.exe");
        when(p.getDomainFile()).thenReturn(df);
        reva.plugin.RevaProgramManager.registerProgram(p);
        try {
            CallToolResult r = callAnalysisStatus(java.util.Map.of());
            assertTrue(r.isError());
            String text = ((TextContent) r.content().get(0)).text();
            assertEquals("No analysis job found for programPath: /only.exe", text);
        } finally {
            reva.plugin.RevaProgramManager.unregisterProgram(p);
            reva.util.RevaInternalServiceRegistry.unregisterService(reva.services.AnalysisJobManager.class);
        }
    }

    @Test
    public void analysisStatusWithBothArgumentsSaysAtMostOne() {
        reva.util.RevaInternalServiceRegistry.registerService(reva.services.AnalysisJobManager.class,
            mock(reva.services.AnalysisJobManager.class));
        try {
            CallToolResult r = callAnalysisStatus(java.util.Map.of("jobId", "j1", "programPath", "/a.exe"));
            assertTrue(r.isError());
            assertEquals("Provide at most one of jobId or programPath, not both",
                ((TextContent) r.content().get(0)).text());
        } finally {
            reva.util.RevaInternalServiceRegistry.unregisterService(reva.services.AnalysisJobManager.class);
        }
    }

    @Test
    public void analysisStatusWithNeitherArgumentAndNoProgramSaysSo() {
        reva.util.RevaInternalServiceRegistry.registerService(reva.services.AnalysisJobManager.class,
            mock(reva.services.AnalysisJobManager.class));
        try {
            CallToolResult r = callAnalysisStatus(java.util.Map.of());
            assertTrue(r.isError());
            assertEquals("No program is open. Import one with import-file.",
                ((TextContent) r.content().get(0)).text());
        } finally {
            reva.util.RevaInternalServiceRegistry.unregisterService(reva.services.AnalysisJobManager.class);
        }
    }
}
