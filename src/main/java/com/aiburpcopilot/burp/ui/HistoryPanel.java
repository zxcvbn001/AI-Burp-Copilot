package com.aiburpcopilot.burp.ui;

import com.aiburpcopilot.core.context.AnalysisStatus;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.RiskLevel;
import com.aiburpcopilot.core.history.HistoryExportService;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.IHistoryService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.*;
import java.awt.*;
import java.io.File;
import java.nio.file.Path;
import java.text.ParseException;
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
    private final JTextField siteField;
    private final JTextField timeFromField;
    private final JTextField timeToField;
    private final JComboBox<String> typeFilter;
    private final JComboBox<String> riskFilter;
    private final JComboBox<String> statusFilter;
    private final HistoryExportService exportService = new HistoryExportService();

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("HH:mm:ss");
    private static final SimpleDateFormat FILTER_DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm");

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

        toolbar.add(new JLabel("Site:"));
        siteField = new JTextField(18);
        siteField.addActionListener(e -> refresh());
        toolbar.add(siteField);

        toolbar.add(new JLabel("From:"));
        timeFromField = new JTextField(14);
        timeFromField.setToolTipText("yyyy-MM-dd HH:mm");
        timeFromField.addActionListener(e -> refresh());
        toolbar.add(timeFromField);

        toolbar.add(new JLabel("To:"));
        timeToField = new JTextField(14);
        timeToField.setToolTipText("yyyy-MM-dd HH:mm");
        timeToField.addActionListener(e -> refresh());
        toolbar.add(timeToField);

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

        JButton clearFilteredBtn = new JButton("Clear Filtered");
        clearFilteredBtn.addActionListener(e -> clearFilteredHistory());
        toolbar.add(clearFilteredBtn);

        JButton exportBtn = new JButton("Export Filtered");
        exportBtn.addActionListener(e -> exportFilteredHistory());
        toolbar.add(exportBtn);

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
            String site = siteField.getText().trim();
            EndpointType type = parseTypeFilter();
            RiskLevel risk = parseRiskFilter();
            AnalysisStatus status = parseStatusFilter();
            Long timeFrom = parseTime(timeFromField.getText().trim(), false);
            Long timeTo = parseTime(timeToField.getText().trim(), true);

            List<HistoryEntry> results = (keyword.isEmpty() && site.isEmpty() && type == null && risk == null && status == null
                    && timeFrom == null && timeTo == null)
                    ? historyService.searchAdvanced(null, null, null, null, null, null, null, 0, 200)
                    : historyService.searchAdvanced(
                    keyword.isEmpty() ? null : keyword,
                    site.isEmpty() ? null : site,
                    type, risk, status,
                    timeFrom, timeTo,
                    0, 200);

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

    private void clearFilteredHistory() {
        String summary = buildFilterSummary();
        int confirm = JOptionPane.showConfirmDialog(this,
                "Clear history records matching current filters?\n\n" + summary,
                "Confirm Filtered Clear",
                JOptionPane.YES_NO_OPTION);
        if (confirm != JOptionPane.YES_OPTION) {
            return;
        }
        int deleted = historyService.clearAdvanced(
                emptyToNull(searchField.getText().trim()),
                emptyToNull(siteField.getText().trim()),
                parseTypeFilter(),
                parseRiskFilter(),
                parseStatusFilter(),
                parseTime(timeFromField.getText().trim(), false),
                parseTime(timeToField.getText().trim(), true));
        refresh();
        JOptionPane.showMessageDialog(this,
                "Deleted " + deleted + " history records.",
                "Filtered Clear",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void exportFilteredHistory() {
        try {
            List<HistoryEntry> entries = historyService.searchAdvanced(
                    emptyToNull(searchField.getText().trim()),
                    emptyToNull(siteField.getText().trim()),
                    parseTypeFilter(),
                    parseRiskFilter(),
                    parseStatusFilter(),
                    parseTime(timeFromField.getText().trim(), false),
                    parseTime(timeToField.getText().trim(), true),
                    0,
                    10_000);
            JFileChooser chooser = new JFileChooser();
            chooser.setSelectedFile(new File("history-export.csv"));
            int result = chooser.showSaveDialog(this);
            if (result != JFileChooser.APPROVE_OPTION) {
                return;
            }
            Path output = chooser.getSelectedFile().toPath();
            exportService.exportCsv(entries, output);
            JOptionPane.showMessageDialog(this,
                    "Exported " + entries.size() + " records to:\n" + output,
                    "Export Success",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "Export failed: " + e.getMessage(),
                    "Export Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void showDetailDialog(HistoryEntry entry) {
        if (entry == null) return;
        HistoryEntry fullEntry = historyService.getById(entry.getRequestId());
        if (fullEntry != null) {
            entry = fullEntry;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("=== History Detail ===\n\n");
        sb.append("Time: ").append(DATE_FORMAT.format(new Date(entry.getTimestamp()))).append("\n");
        sb.append("Method: ").append(entry.getMethod()).append("\n");
        sb.append("URL: ").append(entry.getUrl()).append("\n");
        sb.append("Status: ").append(entry.getStatusCode()).append("\n");
        sb.append("Type: ").append(entry.getEndpointType()).append("\n");
        sb.append("Action: ").append(entry.getEndpointActionType()).append("\n");
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

    private Long parseTime(String text, boolean endOfMinute) {
        if (text == null || text.isBlank()) {
            return null;
        }
        try {
            Date parsed = FILTER_DATE_FORMAT.parse(text);
            long value = parsed.getTime();
            return endOfMinute ? value + 59_999 : value;
        } catch (ParseException e) {
            throw new IllegalArgumentException("Invalid time format, use yyyy-MM-dd HH:mm");
        }
    }

    private String emptyToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private String buildFilterSummary() {
        return "keyword=" + emptyToNull(searchField.getText().trim())
                + "\nsite=" + emptyToNull(siteField.getText().trim())
                + "\nfrom=" + emptyToNull(timeFromField.getText().trim())
                + "\nto=" + emptyToNull(timeToField.getText().trim())
                + "\ntype=" + parseTypeFilter()
                + "\nrisk=" + parseRiskFilter()
                + "\nstatus=" + parseStatusFilter();
    }

    // ========== Table Model ==========

    private static class HistoryTableModel extends AbstractTableModel {
        private final String[] columns = {"Time", "Method", "URL", "Type", "Action", "Risk", "Status", "Summary"};
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
                case 4 -> e.getEndpointActionType();
                case 5 -> e.getRiskLevel();
                case 6 -> e.getAnalysisStatus();
                case 7 -> {
                    String summary = e.getAiSummary();
                    yield (summary != null && summary.length() > 80) ? summary.substring(0, 80) + "..." : summary;
                }
                default -> "";
            };
        }
    }
}
