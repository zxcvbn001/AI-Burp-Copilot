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
    private String displayedEntryId;
    private boolean refreshing;

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
            if (!e.getValueIsAdjusting() && !refreshing) {
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
        resultPanel.add(createSection("分析摘要", summaryArea, 120));
        resultPanel.add(Box.createVerticalStrut(3));
        resultPanel.add(createSection("攻击面", attackSurfaceArea, 80));
        resultPanel.add(Box.createVerticalStrut(3));
        resultPanel.add(createSection("可能存在的漏洞（含关联参数）", vulnArea, 80));
        resultPanel.add(Box.createVerticalStrut(3));
        resultPanel.add(createSection("推荐测试（含关联参数）", testArea, 80));

        detailTabs = new JTabbedPane();
        UiUtil.applyBurpFont(detailTabs);
        detailTabs.addTab("分析结果", new JScrollPane(resultPanel));
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
            refreshing = true;
            try {
                List<HistoryEntry> endpoints = historyService.searchAdvanced(
                        null, null, EndpointType.ENDPOINT, null, null, null, null, 0, 200);
                tableModel.setEntries(endpoints);
                restoreSelection(endpoints, preserveId);
                if (selectedTab >= 0 && selectedTab < detailTabs.getTabCount()) {
                    detailTabs.setSelectedIndex(selectedTab);
                }
            } finally {
                refreshing = false;
            }
            int row = table.getSelectedRow();
            if (row >= 0) {
                updateDetail(tableModel.getEntryAt(row));
            } else {
                clearDetail();
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
        if (entry != null) {
            HistoryEntry fullEntry = historyService.getById(entry.getRequestId());
            if (fullEntry != null) {
                entry = fullEntry;
            }
        }
        currentEntry = entry;
        if (entry == null) {
            clearDetail();
            return;
        }
        String currentId = entry.getRequestId();
        boolean sameEntry = currentId != null && currentId.equals(displayedEntryId);
        UiUtil.setTextPreservingView(summaryArea,
                "端点动作类型: " + (entry.getEndpointActionType() != null ? entry.getEndpointActionType() : "UNKNOWN")
                        + "\n\n" + (entry.getAiSummary() != null ? entry.getAiSummary() : "暂无分析结果"),
                sameEntry);
        UiUtil.setTextPreservingView(attackSurfaceArea,
                formatLines(entry.getAttackSurface(), "暂无攻击面分析"),
                sameEntry);
        UiUtil.setTextPreservingView(vulnArea, formatVulnerabilities(entry), sameEntry);
        UiUtil.setTextPreservingView(testArea,
                formatLines(entry.getRecommendedTests(), "暂无推荐测试"),
                sameEntry);
        requestViewer.setBytes(entry.getRawRequest());
        responseViewer.setBytes(entry.getRawResponse());
        displayedEntryId = currentId;
    }

    private String formatVulnerabilities(HistoryEntry entry) {
        StringBuilder vulns = new StringBuilder();
        if (entry.getHighValueParamDetails() != null && !entry.getHighValueParamDetails().isEmpty()) {
            vulns.append("【高价值参数风险映射】\n");
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
            vulns.append("【潜在漏洞】\n");
            for (String vulnerability : entry.getPossibleVulnerabilities()) {
                vulns.append("  - ").append(vulnerability).append("\n");
            }
        }
        return vulns.length() > 0 ? vulns.toString() : "  暂无漏洞分析\n";
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
        displayedEntryId = null;
        summaryArea.setText("");
        attackSurfaceArea.setText("");
        vulnArea.setText("");
        testArea.setText("");
        requestViewer.setBytes(null);
        responseViewer.setBytes(null);
    }

    private String riskLevelChinese(RiskLevel level) {
        if (level == null) {
            return "未知";
        }
        return switch (level) {
            case CRITICAL -> "严重";
            case HIGH -> "高危";
            case MEDIUM -> "中危";
            case LOW -> "低危";
            case INFO -> "信息";
        };
    }

    private static class EndpointTableModel extends AbstractTableModel {
        private final String[] columns = {"时间", "方法", "URL", "动作", "分析摘要"};
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
