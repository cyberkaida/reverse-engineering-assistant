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
}
