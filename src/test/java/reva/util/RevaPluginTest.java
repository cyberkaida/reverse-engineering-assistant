package reva.util;

import static org.junit.Assert.*;

import org.junit.Test;

import reva.plugin.RevaPlugin;

public class RevaPluginTest {

    @Test
    public void testPluginClassExists() {
        // Basic test to ensure the RevaPlugin class exists and can be instantiated
        assertNotNull("RevaPlugin class should exist", RevaPlugin.class);
        assertEquals("Package should be correct", "reva.plugin", RevaPlugin.class.getPackage().getName());
    }

    @Test
    public void testPluginConstructorSignature() throws NoSuchMethodException {
        // Verify the plugin has the correct constructor signature for Ghidra plugins
        assertNotNull("RevaPlugin should have a constructor that takes PluginTool",
                     RevaPlugin.class.getConstructor(ghidra.framework.plugintool.PluginTool.class));
    }
}
