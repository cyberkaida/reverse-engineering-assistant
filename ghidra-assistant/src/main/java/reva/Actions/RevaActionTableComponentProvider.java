package reva.Actions;

import javax.swing.JComponent;

import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;

public class RevaActionTableComponentProvider extends ComponentProvider {
    private RevaActionTable table;

    public RevaActionTableComponentProvider(PluginTool tool) {
        super(tool, "ReVa Action Tracker", "ReVa");
        table = new RevaActionTable();
    }

    @Override
    public JComponent getComponent() {
        return table;
    }

    public void addAction(RevaAction action) {
        table.addAction(action);
    }
}
