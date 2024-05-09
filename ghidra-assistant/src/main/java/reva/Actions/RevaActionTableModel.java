package reva.Actions;
import java.util.ArrayList;
import java.util.List;

import javax.swing.table.AbstractTableModel;

public class RevaActionTableModel extends AbstractTableModel {
    private List<RevaAction> actions;
    private final String[] columnNames = {"Accept", "Reject", "Status", "Action Location", "Action Name", "Description"};

    public RevaActionTableModel() {
        this.actions = new ArrayList<RevaAction>();
    }

    /**
     * Add an action to be monitored by this table
     * @param action
     */
    public void addAction(RevaAction action) {
        actions.add(action);
        fireTableDataChanged();
    }

    public void acceptAction(int row) {
        RevaAction action = actions.get(row);
        action.accept();
        fireTableDataChanged();
    }

    public void rejectAction(int row) {
        RevaAction action = actions.get(row);
        action.reject();
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return actions.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        RevaAction action = actions.get(rowIndex);
        switch (columnIndex) {
            case 0:
                if (action.status == RevaAction.Status.PENDING) {
                    return "✅";
                } else {
                    return "";
                }
            case 1:
                if (action.status == RevaAction.Status.PENDING) {
                    return "❌";
                } else {
                    return "";
                }
            case 2:
                switch (action.status) {
                    case ACCEPTED: return "✅";
                    case REJECTED: return "❌";
                    default: return "❓";
                }
            case 3: return action.location;
            case 4: return action.name;
            case 5: return action.description;
            default: return null;
        }
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }


}
