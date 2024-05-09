package reva.Actions;
import javax.swing.JPanel;

import docking.widgets.table.GTable;
import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.JScrollPane;
import javax.swing.JTable;

public class RevaActionTable extends JPanel {
    private JTable table;
    private RevaActionTableModel tableModel;

    public RevaActionTable() {
        setLayout(new BorderLayout());

        // Create the table model with column names
        tableModel = new RevaActionTableModel();
        // Create the table with the table model
        table = new GTable(tableModel);

        table.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    // Double click
                    int row = table.getSelectedRow();
                    int column = table.getSelectedColumn();
                    if (column == 0) {
                        tableModel.acceptAction(row);
                    } else if (column == 1) {
                        tableModel.rejectAction(row);
                    }
                }
            }
        });
        // Add a scroll pane to the table
        JScrollPane scrollPane = new JScrollPane(table);
        add(scrollPane, BorderLayout.CENTER);
    }

    public void addAction(RevaAction action) {
        tableModel.addAction(action);
    }
}
