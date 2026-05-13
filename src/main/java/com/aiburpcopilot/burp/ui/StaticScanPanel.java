package com.aiburpcopilot.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.IHistoryService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

public class StaticScanPanel extends JPanel {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("HH:mm:ss");

    private final IHistoryService historyService;
    private final JTable table;
    private final StaticScanTableModel tableModel;
    private final JTabbedPane detailTabs;
    private final JTextArea findingArea;
    private final BurpMessageViewer.RequestView requestViewer;
    private final BurpMessageViewer.ResponseView responseViewer;

    private HistoryEntry currentEntry;

    public StaticScanPanel(MontoyaApi api, IHistoryService historyService) {
        this.historyService = historyService;
        setLayout(new BorderLayout());

        tableModel = new StaticScanTableModel();
        table = new JTable(tableModel);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        UiUtil.applyBurpFont(table);

        UiUtil.setScaledColumnWidths(table, 85, 75, 380, 560);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = table.getSelectedRow();
                if (row >= 0) {
                    updateDetail(tableModel.getEntryAt(row));
                } else {
                    clearDetail();
                }
            }
        });

        findingArea = createWrappedTextArea();
        requestViewer = new BurpMessageViewer.RequestView(api);
        responseViewer = new BurpMessageViewer.ResponseView(api);

        JPanel findingPanel = new JPanel(new BorderLayout());
        findingPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        JPanel findingSection = new JPanel(new BorderLayout());
        findingSection.setBorder(BorderFactory.createTitledBorder(null, "\u626b\u63cf\u53d1\u73b0",
                TitledBorder.LEFT, TitledBorder.TOP, UiUtil.burpTableFont().deriveFont(Font.BOLD)));
        findingSection.add(new JScrollPane(findingArea), BorderLayout.CENTER);
        findingPanel.add(findingSection, BorderLayout.CENTER);

        detailTabs = new JTabbedPane();
        UiUtil.applyBurpFont(detailTabs);
        detailTabs.addTab("\u626b\u63cf\u53d1\u73b0", findingPanel);
        detailTabs.addTab("Request", requestViewer);
        detailTabs.addTab("Response", responseViewer);

        JPanel detailPanel = new JPanel(new BorderLayout());
        detailPanel.add(detailTabs, BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), detailPanel);
        splitPane.setResizeWeight(0.4);
        splitPane.setDividerLocation(220);
        add(splitPane, BorderLayout.CENTER);
    }

    public void refresh() {
        String preserveId = currentEntry != null ? currentEntry.getRequestId() : null;
        int selectedTab = detailTabs.getSelectedIndex();
        SwingUtilities.invokeLater(() -> {
            List<HistoryEntry> staticResources = historyService.getAll().stream()
                    .filter(entry -> entry.getEndpointType() == EndpointType.STATIC_RESOURCE)
                    .limit(200)
                    .toList();
            tableModel.setEntries(staticResources);
            restoreSelection(staticResources, preserveId);
            if (selectedTab >= 0 && selectedTab < detailTabs.getTabCount()) {
                detailTabs.setSelectedIndex(selectedTab);
            }
        });
    }

    private JTextArea createWrappedTextArea() {
        JTextArea area = UiUtil.createMessageArea();
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        return area;
    }

    private void restoreSelection(List<HistoryEntry> entries, String preserveId) {
        if (preserveId == null) {
            return;
        }
        for (int i = 0; i < entries.size(); i++) {
            if (preserveId.equals(entries.get(i).getRequestId())) {
                table.setRowSelectionInterval(i, i);
                return;
            }
        }
    }

    private void updateDetail(HistoryEntry entry) {
        currentEntry = entry;
        if (entry == null) {
            clearDetail();
            return;
        }
        findingArea.setText(entry.getAiSummary() != null ? entry.getAiSummary() : "\u672a\u626b\u63cf\u6216\u65e0\u53d1\u73b0");
        requestViewer.setBytes(entry.getRawRequest());
        responseViewer.setBytes(entry.getRawResponse());
        resetCarets();
    }

    private void clearDetail() {
        currentEntry = null;
        findingArea.setText("");
        requestViewer.setBytes(null);
        responseViewer.setBytes(null);
    }

    private void resetCarets() {
        findingArea.setCaretPosition(0);
    }

    private static class StaticScanTableModel extends AbstractTableModel {
        private final String[] columns = {"\u65f6\u95f4", "\u65b9\u6cd5", "URL", "\u53d1\u73b0"};
        private List<HistoryEntry> entries = List.of();

        void setEntries(List<HistoryEntry> entries) {
            this.entries = entries != null ? entries : List.of();
            fireTableDataChanged();
        }

        HistoryEntry getEntryAt(int row) {
            return row >= 0 && row < entries.size() ? entries.get(row) : null;
        }

        @Override public int getColumnCount() { return columns.length; }
        @Override public int getRowCount() { return entries.size(); }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            HistoryEntry entry = entries.get(row);
            return switch (col) {
                case 0 -> DATE_FORMAT.format(new Date(entry.getTimestamp()));
                case 1 -> entry.getMethod();
                case 2 -> entry.getUrl();
                case 3 -> truncate(entry.getAiSummary(), 100);
                default -> "";
            };
        }

        private static String truncate(String value, int maxLen) {
            if (value == null) {
                return "";
            }
            return value.length() > maxLen ? value.substring(0, maxLen - 3) + "..." : value;
        }
    }
}
