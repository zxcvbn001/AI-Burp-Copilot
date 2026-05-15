package com.aiburpcopilot.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.aiburpcopilot.core.context.AnalysisResult;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.RiskLevel;
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

public class EndpointAnalysisPanel extends JPanel {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("HH:mm:ss");

    private final IHistoryService historyService;
    private final JTable table;
    private final EndpointTableModel tableModel;
    private final JTabbedPane detailTabs;
    private final JTextArea summaryArea;
    private final JTextArea attackSurfaceArea;
    private final JTextArea vulnArea;
    private final JTextArea testArea;
    private final BurpMessageViewer.RequestView requestViewer;
    private final BurpMessageViewer.ResponseView responseViewer;

    private HistoryEntry currentEntry;

    public EndpointAnalysisPanel(MontoyaApi api, IHistoryService historyService) {
        this.historyService = historyService;
        setLayout(new BorderLayout());

        tableModel = new EndpointTableModel();
        table = new JTable(tableModel);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        UiUtil.applyBurpFont(table);

        UiUtil.setScaledColumnWidths(table, 85, 75, 360, 100);

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

        summaryArea = createWrappedTextArea();
        attackSurfaceArea = createWrappedTextArea();
        vulnArea = createWrappedTextArea();
        testArea = createWrappedTextArea();
        requestViewer = new BurpMessageViewer.RequestView(api);
        responseViewer = new BurpMessageViewer.ResponseView(api);

        JPanel resultPanel = new JPanel();
        resultPanel.setLayout(new BoxLayout(resultPanel, BoxLayout.Y_AXIS));
        resultPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        resultPanel.add(createSection("\u5206\u6790\u6458\u8981", summaryArea, 120));
        resultPanel.add(Box.createVerticalStrut(3));
        resultPanel.add(createSection("\u653b\u51fb\u9762", attackSurfaceArea, 80));
        resultPanel.add(Box.createVerticalStrut(3));
        resultPanel.add(createSection("\u53ef\u80fd\u5b58\u5728\u7684\u6f0f\u6d1e\uff08\u542b\u5173\u8054\u53c2\u6570\uff09", vulnArea, 80));
        resultPanel.add(Box.createVerticalStrut(3));
        resultPanel.add(createSection("\u63a8\u8350\u6d4b\u8bd5\uff08\u542b\u5173\u8054\u53c2\u6570\uff09", testArea, 80));

        detailTabs = new JTabbedPane();
        UiUtil.applyBurpFont(detailTabs);
        detailTabs.addTab("\u5206\u6790\u7ed3\u679c", new JScrollPane(resultPanel));
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
            List<HistoryEntry> endpoints = historyService.getAll().stream()
                    .filter(entry -> entry.getEndpointType() == EndpointType.ENDPOINT)
                    .limit(200)
                    .toList();
            tableModel.setEntries(endpoints);
            restoreSelection(endpoints, preserveId);
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

    private JPanel createSection(String title, JTextArea textArea, int height) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(null, title, TitledBorder.LEFT, TitledBorder.TOP,
                UiUtil.burpTableFont().deriveFont(Font.BOLD)));
        JScrollPane scroll = new JScrollPane(textArea);
        scroll.setPreferredSize(new Dimension(400, height));
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
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
        summaryArea.setText("端点动作类型: " + (entry.getEndpointActionType() != null ? entry.getEndpointActionType() : "UNKNOWN")
                + "\n\n" + (entry.getAiSummary() != null ? entry.getAiSummary() : "\u6682\u65e0\u5206\u6790\u7ed3\u679c"));
        attackSurfaceArea.setText(formatLines(entry.getAttackSurface(), "\u6682\u65e0\u653b\u51fb\u9762\u5206\u6790"));
        vulnArea.setText(formatVulnerabilities(entry));
        testArea.setText(formatLines(entry.getRecommendedTests(), "\u6682\u65e0\u63a8\u8350\u6d4b\u8bd5"));
        requestViewer.setBytes(entry.getRawRequest());
        responseViewer.setBytes(entry.getRawResponse());
        resetCarets();
    }

    private String formatVulnerabilities(HistoryEntry entry) {
        StringBuilder vulns = new StringBuilder();
        if (entry.getHighValueParamDetails() != null && !entry.getHighValueParamDetails().isEmpty()) {
            vulns.append("\u3010\u9ad8\u4ef7\u503c\u53c2\u6570\u98ce\u9669\u6620\u5c04\u3011\n");
            for (AnalysisResult.HighValueParam param : entry.getHighValueParamDetails()) {
                vulns.append("  - ").append(param.getParamName())
                        .append(" [").append(riskLevelChinese(param.getRiskLevel())).append("]");
                if (param.getReason() != null) {
                    vulns.append(" - ").append(param.getReason());
                }
                vulns.append("\n");
            }
            vulns.append("\n");
        }
        if (entry.getPossibleVulnerabilities() != null && !entry.getPossibleVulnerabilities().isEmpty()) {
            vulns.append("\u3010\u6f5c\u5728\u6f0f\u6d1e\u3011\n");
            for (String vulnerability : entry.getPossibleVulnerabilities()) {
                vulns.append("  - ").append(vulnerability).append("\n");
            }
        }
        return vulns.length() > 0 ? vulns.toString() : "  \u6682\u65e0\u6f0f\u6d1e\u5206\u6790\n";
    }

    private String formatLines(List<String> lines, String emptyText) {
        if (lines == null || lines.isEmpty()) {
            return "  " + emptyText + "\n";
        }
        StringBuilder builder = new StringBuilder();
        for (String line : lines) {
            builder.append("  - ").append(line).append("\n");
        }
        return builder.toString();
    }

    private void clearDetail() {
        currentEntry = null;
        summaryArea.setText("");
        attackSurfaceArea.setText("");
        vulnArea.setText("");
        testArea.setText("");
        requestViewer.setBytes(null);
        responseViewer.setBytes(null);
    }

    private void resetCarets() {
        summaryArea.setCaretPosition(0);
        attackSurfaceArea.setCaretPosition(0);
        vulnArea.setCaretPosition(0);
        testArea.setCaretPosition(0);
    }

    private String riskLevelChinese(RiskLevel level) {
        if (level == null) {
            return "\u672a\u77e5";
        }
        return switch (level) {
            case CRITICAL -> "\u4e25\u91cd";
            case HIGH -> "\u9ad8\u5371";
            case MEDIUM -> "\u4e2d\u5371";
            case LOW -> "\u4f4e\u5371";
            case INFO -> "\u4fe1\u606f";
        };
    }

    private static class EndpointTableModel extends AbstractTableModel {
        private final String[] columns = {"\u65f6\u95f4", "\u65b9\u6cd5", "URL", "\u52a8\u4f5c", "\u5206\u6790\u6458\u8981"};
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
                case 3 -> entry.getEndpointActionType();
                case 4 -> truncate(entry.getAiSummary(), 100);
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
