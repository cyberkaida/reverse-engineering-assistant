package reva.Actions;

import javax.swing.JComponent;

import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import reva.RevaPlugin;

public class RevaActionTableComponentProvider extends ComponentProvider {
    private RevaActionTable table;

    public RevaActionTableComponentProvider(RevaPlugin plugin) {
        super(plugin.getTool(), "ReVa Action Tracker", "ReVa");
        table = new RevaActionTable(plugin);
    }

    @Override
    public JComponent getComponent() {
        return table;
    }

    public void addAction(RevaAction action) {
        table.addAction(action);
    }
}
