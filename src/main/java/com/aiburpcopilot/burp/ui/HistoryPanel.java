package com.aiburpcopilot.burp.ui;

import com.aiburpcopilot.core.context.AnalysisStatus;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.RiskLevel;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.IHistoryService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.*;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * 历史记录面板。
 * <p>
 * 展示所有历史分析记录，支持搜索和过滤。
 * 双击记录可查看详情。
 */
public class HistoryPanel extends JPanel {

    private final IHistoryService historyService;

    private final JTable table;
    private final HistoryTableModel tableModel;
    private final JTextField searchField;
    private final JComboBox<String> typeFilter;
    private final JComboBox<String> riskFilter;
    private final JComboBox<String> statusFilter;

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("HH:mm:ss");

    public HistoryPanel(IHistoryService historyService) {
        this.historyService = historyService;

        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        // ========== 工具栏 ==========
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));

        toolbar.add(new JLabel("Search:"));
        searchField = new JTextField(20);
        searchField.addActionListener(e -> refresh());
        toolbar.add(searchField);

        toolbar.add(new JLabel("Type:"));
        typeFilter = new JComboBox<>(new String[]{"All", "ENDPOINT", "STATIC_RESOURCE", "UNKNOWN"});
        typeFilter.addActionListener(e -> refresh());
        toolbar.add(typeFilter);

        toolbar.add(new JLabel("Risk:"));
        riskFilter = new JComboBox<>(new String[]{"All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"});
        riskFilter.addActionListener(e -> refresh());
        toolbar.add(riskFilter);

        toolbar.add(new JLabel("Status:"));
        statusFilter = new JComboBox<>(new String[]{"All", "PENDING", "ANALYZING", "COMPLETED", "FAILED", "SKIPPED"});
        statusFilter.addActionListener(e -> refresh());
        toolbar.add(statusFilter);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> clearHistory());
        toolbar.add(clearBtn);

        add(toolbar, BorderLayout.NORTH);

        // ========== 表格 ==========
        tableModel = new HistoryTableModel();
        table = new JTable(tableModel);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        UiUtil.applyBurpFont(table);

        // 列宽设置
        UiUtil.setScaledColumnWidths(table,
                85,   // Time
                75,   // Method
                360,  // URL
                150,  // Type
                95,   // Risk
                125,  // Status
                260); // Summary

        // 双击查看详情
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    showDetailDialog(tableModel.getEntryAt(table.getSelectedRow()));
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        add(scrollPane, BorderLayout.CENTER);

        // 初始加载
        refresh();
    }

    /**
     * 刷新表格数据。
     */
    public void refresh() {
        SwingUtilities.invokeLater(() -> {
            String keyword = searchField.getText().trim();
            EndpointType type = parseTypeFilter();
            RiskLevel risk = parseRiskFilter();
            AnalysisStatus status = parseStatusFilter();

            List<HistoryEntry> results = (keyword.isEmpty() && type == null && risk == null && status == null)
                    ? historyService.getAll()
                    : historyService.search(keyword.isEmpty() ? null : keyword,
                    type, risk, status, 0, 200);

            tableModel.setEntries(results);
        });
    }

    // ---------- Private ----------

    private void clearHistory() {
        int confirm = JOptionPane.showConfirmDialog(this,
                "Clear all history records?", "Confirm",
                JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            historyService.clear();
            refresh();
        }
    }

    private void showDetailDialog(HistoryEntry entry) {
        if (entry == null) return;

        StringBuilder sb = new StringBuilder();
        sb.append("=== History Detail ===\n\n");
        sb.append("Time: ").append(DATE_FORMAT.format(new Date(entry.getTimestamp()))).append("\n");
        sb.append("Method: ").append(entry.getMethod()).append("\n");
        sb.append("URL: ").append(entry.getUrl()).append("\n");
        sb.append("Status: ").append(entry.getStatusCode()).append("\n");
        sb.append("Type: ").append(entry.getEndpointType()).append("\n");
        sb.append("Risk: ").append(entry.getRiskLevel()).append("\n");
        sb.append("Analysis: ").append(entry.getAnalysisStatus()).append("\n\n");

        if (entry.getAttackSurface() != null && !entry.getAttackSurface().isEmpty()) {
            sb.append("--- Attack Surface ---\n");
            entry.getAttackSurface().forEach(s -> sb.append("  - ").append(s).append("\n"));
            sb.append("\n");
        }

        if (entry.getPossibleVulnerabilities() != null && !entry.getPossibleVulnerabilities().isEmpty()) {
            sb.append("--- Possible Vulnerabilities ---\n");
            entry.getPossibleVulnerabilities().forEach(s -> sb.append("  - ").append(s).append("\n"));
            sb.append("\n");
        }

        if (entry.getRecommendedTests() != null && !entry.getRecommendedTests().isEmpty()) {
            sb.append("--- Recommended Tests ---\n");
            entry.getRecommendedTests().forEach(s -> sb.append("  - ").append(s).append("\n"));
            sb.append("\n");
        }

        if (entry.getAiSummary() != null) {
            sb.append("--- AI Summary ---\n").append(entry.getAiSummary()).append("\n");
        }

        JTextArea textArea = new JTextArea(sb.toString());
        textArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(500, 400));

        JOptionPane.showMessageDialog(this, scrollPane,
                "History Detail - " + entry.getPath(), JOptionPane.INFORMATION_MESSAGE);
    }

    private EndpointType parseTypeFilter() {
        String selected = (String) typeFilter.getSelectedItem();
        if (selected == null || "All".equals(selected)) return null;
        return EndpointType.valueOf(selected);
    }

    private RiskLevel parseRiskFilter() {
        String selected = (String) riskFilter.getSelectedItem();
        if (selected == null || "All".equals(selected)) return null;
        return RiskLevel.valueOf(selected);
    }

    private AnalysisStatus parseStatusFilter() {
        String selected = (String) statusFilter.getSelectedItem();
        if (selected == null || "All".equals(selected)) return null;
        return AnalysisStatus.valueOf(selected);
    }

    // ========== Table Model ==========

    private static class HistoryTableModel extends AbstractTableModel {
        private final String[] columns = {"Time", "Method", "URL", "Type", "Risk", "Status", "Summary"};
        private List<HistoryEntry> entries = List.of();

        void setEntries(List<HistoryEntry> entries) {
            this.entries = entries != null ? entries : List.of();
            fireTableDataChanged();
        }

        HistoryEntry getEntryAt(int row) {
            if (row >= 0 && row < entries.size()) {
                return entries.get(row);
            }
            return null;
        }

        @Override
        public int getColumnCount() { return columns.length; }

        @Override
        public int getRowCount() { return entries.size(); }

        @Override
        public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            HistoryEntry e = entries.get(row);
            return switch (col) {
                case 0 -> DATE_FORMAT.format(new Date(e.getTimestamp()));
                case 1 -> e.getMethod();
                case 2 -> e.getUrl();
                case 3 -> e.getEndpointType();
                case 4 -> e.getRiskLevel();
                case 5 -> e.getAnalysisStatus();
                case 6 -> {
                    String summary = e.getAiSummary();
                    yield (summary != null && summary.length() > 80) ? summary.substring(0, 80) + "..." : summary;
                }
                default -> "";
            };
        }
    }
}
