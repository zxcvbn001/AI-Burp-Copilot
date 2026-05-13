package com.aiburpcopilot.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.core.pipeline.HistoryEventBus;
import com.aiburpcopilot.core.verification.ManualVerificationService;
import com.aiburpcopilot.core.verification.model.InfluenceStatus;
import com.aiburpcopilot.core.verification.model.VerificationResult;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ParameterInfluencePanel extends JPanel {

    private static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("HH:mm:ss");

    private final IHistoryService historyService;
    private final ManualVerificationService manualVerificationService;
    private final JTable table;
    private final InfluenceTableModel tableModel;
    private final JTextArea summaryArea;
    private final BurpMessageViewer.RequestView requestViewer;
    private final BurpMessageViewer.ResponseView responseViewer;
    private final JTextArea diffArea;
    private final JTextArea reasoningArea;
    private final JTabbedPane detailTabs;
    private final JLabel statusLabel;
    private final JButton markInfluentialBtn;
    private final JButton markNoInfluenceBtn;
    private String displayedKey;
    private boolean refreshing;

    public ParameterInfluencePanel(MontoyaApi api,
                                   IHistoryService historyService,
                                   ManualVerificationService manualVerificationService) {
        this.historyService = historyService;
        this.manualVerificationService = manualVerificationService;
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 5));
        JButton refreshBtn = new JButton("\u5237\u65b0");
        refreshBtn.addActionListener(e -> refresh());
        toolbar.add(refreshBtn);

        markInfluentialBtn = new JButton("\u6807\u8bb0\u4e3a\u6709\u5f71\u54cd\u5e76\u9a8c\u8bc1");
        markInfluentialBtn.addActionListener(e -> markSelected(true));
        toolbar.add(markInfluentialBtn);

        markNoInfluenceBtn = new JButton("\u6807\u8bb0\u4e3a\u65e0\u5f71\u54cd");
        markNoInfluenceBtn.addActionListener(e -> markSelected(false));
        toolbar.add(markNoInfluenceBtn);

        statusLabel = new JLabel("\u53c2\u6570\u5f71\u54cd\u7ed3\u679c: 0");
        toolbar.add(Box.createHorizontalStrut(20));
        toolbar.add(statusLabel);
        add(toolbar, BorderLayout.NORTH);

        tableModel = new InfluenceTableModel();
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);
        UiUtil.applyBurpFont(table);
        UiUtil.setScaledColumnWidths(table, 90, 420, 120, 95, 130, 110, 90);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !refreshing) {
                updateDetail();
            }
        });

        summaryArea = UiUtil.createMessageArea();
        requestViewer = new BurpMessageViewer.RequestView(api);
        responseViewer = new BurpMessageViewer.ResponseView(api);
        diffArea = UiUtil.createMessageArea();
        reasoningArea = UiUtil.createMessageArea();

        detailTabs = new JTabbedPane();
        UiUtil.applyBurpFont(detailTabs);
        detailTabs.addTab("\u6982\u8981", UiUtil.searchableTextPanel(summaryArea));
        detailTabs.addTab("Request", requestViewer);
        detailTabs.addTab("Response", responseViewer);
        detailTabs.addTab("Diff", UiUtil.searchableTextPanel(diffArea));
        detailTabs.addTab("Reasoning", UiUtil.searchableTextPanel(reasoningArea));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), detailTabs);
        splitPane.setResizeWeight(0.42);
        add(splitPane, BorderLayout.CENTER);

        refresh();
    }

    public void refresh() {
        SwingUtilities.invokeLater(() -> {
            String selectedKey = selectedKey();
            int selectedTab = detailTabs.getSelectedIndex();
            refreshing = true;
            List<VerificationUiSupport.ResultRow> rows = collectInfluenceRows();
            tableModel.setRows(rows);
            statusLabel.setText("\u53c2\u6570\u5f71\u54cd\u7ed3\u679c: " + rows.size());
            restoreSelection(selectedKey);
            if (selectedTab >= 0 && selectedTab < detailTabs.getTabCount()) {
                detailTabs.setSelectedIndex(selectedTab);
            }
            refreshing = false;
            if (displayedKey == null || selectedKey == null || !selectedKey.equals(selectedKey())) {
                updateDetail();
            }
        });
    }

    private void updateDetail() {
        VerificationUiSupport.ResultRow row = tableModel.getRowAt(table.getSelectedRow());
        if (row == null) {
            displayedKey = null;
            clearDetails();
            return;
        }
        VerificationResult result = row.result();
        String currentKey = influenceGroupKey(row);
        boolean sameRow = currentKey.equals(displayedKey);
        int[] positions = sameRow ? captureCaretPositions() : null;
        summaryArea.setText("\u53c2\u6570: " + nullToDash(result.getParameter())
                + "\n\u653b\u51fb\u7c7b\u578b: " + nullToDash(result.getAttackType())
                + "\n\u5f53\u524d\u7ed3\u8bba: " + influenceConclusion(result)
                + "\n\u662f\u5426\u624b\u52a8\u4fee\u6539: " + (result.isManualInfluenceOverride() ? "\u662f" : "\u5426")
                + "\n\u7f6e\u4fe1\u5ea6: " + String.format("%.2f", result.getConfidence())
                + "\nURL: " + nullToDash(result.getUrl()));
        requestViewer.setBytes(result.getMutatedRequestBytes());
        responseViewer.setBytes(result.getMutatedResponseBytes());
        diffArea.setText(VerificationUiSupport.formatDiffChinese(result.getDiffResult(), result.getResponseTimeMs()));
        reasoningArea.setText(result.getReasoning() != null ? result.getReasoning() : "N/A");
        displayedKey = currentKey;
        if (sameRow) {
            restoreCaretPositions(positions);
        } else {
            resetCarets();
        }
    }

    private void markSelected(boolean influential) {
        VerificationUiSupport.ResultRow row = tableModel.getRowAt(table.getSelectedRow());
        if (row == null) {
            JOptionPane.showMessageDialog(this, "\u8bf7\u5148\u9009\u62e9\u4e00\u6761\u53c2\u6570\u5f71\u54cd\u7ed3\u679c\u3002");
            return;
        }
        String selectedKey = influenceGroupKey(row);
        VerificationResult result = row.result();
        result.setManualInfluenceOverride(true);
        result.setConfidence(influential ? 1.0 : 0.0);
        result.setInfluenceStatus(influential
                ? InfluenceStatus.INFLUENTIAL
                : InfluenceStatus.NOT_INFLUENTIAL);
        result.setReasoning((influential ? "Manual override: influential" : "Manual override: no influence")
                + "\n" + (result.getReasoning() != null ? result.getReasoning() : ""));

        if (!influential || manualVerificationService == null) {
            historyService.update(row.entry());
            HistoryEventBus.getInstance().fireRefreshNeeded();
            refresh();
            restoreSelection(selectedKey);
            return;
        }

        setManualActionRunning(true);
        statusLabel.setText("\u6b63\u5728\u540e\u53f0\u6267\u884c\u6f0f\u6d1e\u9a8c\u8bc1\uff0cBurp UI \u4e0d\u4f1a\u963b\u585e...");
        SwingWorker<List<VerificationResult>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<VerificationResult> doInBackground() {
                return manualVerificationService.runAfterManualInfluence(row.entry(), result);
            }

            @Override
            protected void done() {
                try {
                    List<VerificationResult> newResults = get();
                    if (!newResults.isEmpty()) {
                        if (row.entry().getVerificationResults() == null) {
                            row.entry().setVerificationResults(new ArrayList<>());
                        }
                        row.entry().getVerificationResults().addAll(newResults);
                    }
                    historyService.update(row.entry());
                    HistoryEventBus.getInstance().fireRefreshNeeded();
                    refresh();
                    restoreSelection(selectedKey);
                    statusLabel.setText("\u53c2\u6570\u5f71\u54cd\u7ed3\u679c: " + tableModel.getRowCount()
                            + " | \u624b\u52a8\u9a8c\u8bc1\u5b8c\u6210\uff0c\u65b0\u7ed3\u679c " + newResults.size());
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(ParameterInfluencePanel.this,
                            "\u624b\u52a8\u9a8c\u8bc1\u5931\u8d25: " + ex.getMessage(),
                            "\u9519\u8bef", JOptionPane.ERROR_MESSAGE);
                    statusLabel.setText("\u624b\u52a8\u9a8c\u8bc1\u5931\u8d25");
                } finally {
                    setManualActionRunning(false);
                }
            }
        };
        worker.execute();
    }

    private void setManualActionRunning(boolean running) {
        markInfluentialBtn.setEnabled(!running);
        markNoInfluenceBtn.setEnabled(!running);
        table.setEnabled(!running);
    }

    private void clearDetails() {
        summaryArea.setText("");
        requestViewer.setBytes(null);
        responseViewer.setBytes(null);
        diffArea.setText("");
        reasoningArea.setText("");
    }

    private String selectedKey() {
        VerificationUiSupport.ResultRow row = tableModel.getRowAt(table.getSelectedRow());
        return row != null ? influenceGroupKey(row) : null;
    }

    private void restoreSelection(String key) {
        if (key == null) {
            return;
        }
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            VerificationUiSupport.ResultRow row = tableModel.getRowAt(i);
            if (key.equals(influenceGroupKey(row))) {
                table.setRowSelectionInterval(i, i);
                return;
            }
        }
    }

    private void resetCarets() {
        summaryArea.setCaretPosition(0);
        diffArea.setCaretPosition(0);
        reasoningArea.setCaretPosition(0);
    }

    private int[] captureCaretPositions() {
        return new int[]{summaryArea.getCaretPosition(), diffArea.getCaretPosition(), reasoningArea.getCaretPosition()};
    }

    private void restoreCaretPositions(int[] positions) {
        if (positions == null || positions.length < 3) {
            resetCarets();
            return;
        }
        setCaretSafely(summaryArea, positions[0]);
        setCaretSafely(diffArea, positions[1]);
        setCaretSafely(reasoningArea, positions[2]);
    }

    private void setCaretSafely(JTextArea area, int position) {
        area.setCaretPosition(Math.max(0, Math.min(position, area.getDocument().getLength())));
    }

    private static String nullToDash(Object value) {
        return value != null ? String.valueOf(value) : "-";
    }

    private static String influenceConclusion(VerificationResult result) {
        if (result == null) {
            return "-";
        }
        InfluenceStatus inferredStatus = result.getInfluenceStatus() != null
                ? result.getInfluenceStatus()
                : inferInfluenceStatus(result.getReasoning());
        if (inferredStatus == InfluenceStatus.INFLUENTIAL) {
            return "\u786e\u8ba4\u53c2\u4e0e\u4e1a\u52a1";
        }
        if (inferredStatus == InfluenceStatus.UNCERTAIN) {
            return "\u4e0d\u786e\u5b9a\uff08\u4e0d\u526a\u679d\uff0c\u7ee7\u7eed\u9a8c\u8bc1\uff09";
        }
        if (inferredStatus == InfluenceStatus.NOT_INFLUENTIAL) {
            return "\u672a\u89c2\u5bdf\u5230\u4e1a\u52a1\u5f71\u54cd";
        }
        return result.getConfidence() >= 0.1
                ? "\u786e\u8ba4\u53c2\u4e0e\u4e1a\u52a1"
                : "\u672a\u89c2\u5bdf\u5230\u4e1a\u52a1\u5f71\u54cd";
    }

    private static InfluenceStatus inferInfluenceStatus(String reasoning) {
        if (reasoning == null || reasoning.isBlank()) {
            return null;
        }
        for (InfluenceStatus status : InfluenceStatus.values()) {
            if (reasoning.contains("Influence status=" + status.name())) {
                return status;
            }
        }
        return null;
    }

    private List<VerificationUiSupport.ResultRow> collectInfluenceRows() {
        Map<String, VerificationUiSupport.ResultRow> dedup = new LinkedHashMap<>();
        for (VerificationUiSupport.ResultRow row : VerificationUiSupport.collectRows(historyService)) {
            if (!VerificationUiSupport.isInfluence(row.result())) {
                continue;
            }
            String key = influenceGroupKey(row);
            VerificationUiSupport.ResultRow previous = dedup.get(key);
            if (previous == null || betterInfluence(row.result(), previous.result())) {
                dedup.put(key, row);
            }
        }
        return new ArrayList<>(dedup.values());
    }

    private String influenceGroupKey(VerificationUiSupport.ResultRow row) {
        VerificationResult result = row.result();
        String url = result.getUrl() != null ? result.getUrl() : row.entry().getUrl();
        return nullToDash(row.entry().getMethod())
                + "|" + nullToDash(url)
                + "|" + nullToDash(result.getAttackType())
                + "|" + nullToDash(result.getParameter());
    }

    private boolean betterInfluence(VerificationResult candidate, VerificationResult previous) {
        if (candidate.isManualInfluenceOverride() != previous.isManualInfluenceOverride()) {
            return candidate.isManualInfluenceOverride();
        }
        if (Double.compare(candidate.getConfidence(), previous.getConfidence()) != 0) {
            return candidate.getConfidence() > previous.getConfidence();
        }
        return candidate.getTimestamp() > previous.getTimestamp();
    }

    private static class InfluenceTableModel extends AbstractTableModel {
        private final String[] columns = {"\u65f6\u95f4", "URL", "\u53c2\u6570", "\u7c7b\u578b", "\u4e1a\u52a1\u53c2\u4e0e\u5224\u65ad", "\u7f6e\u4fe1\u5ea6", "\u624b\u52a8"};
        private List<VerificationUiSupport.ResultRow> rows = List.of();

        void setRows(List<VerificationUiSupport.ResultRow> rows) {
            this.rows = rows != null ? rows : List.of();
            fireTableDataChanged();
        }

        VerificationUiSupport.ResultRow getRowAt(int row) {
            return row >= 0 && row < rows.size() ? rows.get(row) : null;
        }

        @Override public int getColumnCount() { return columns.length; }
        @Override public int getRowCount() { return rows.size(); }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            VerificationResult result = rows.get(row).result();
            return switch (col) {
                case 0 -> TIME_FORMAT.format(new Date(result.getTimestamp()));
                case 1 -> result.getUrl() != null ? truncate(result.getUrl(), 90) : "-";
                case 2 -> result.getParameter();
                case 3 -> result.getAttackType();
                case 4 -> influenceConclusion(result);
                case 5 -> String.format("%.2f", result.getConfidence());
                case 6 -> result.isManualInfluenceOverride() ? "\u662f" : "\u5426";
                default -> "";
            };
        }

        private static String truncate(String value, int maxLen) {
            return value != null && value.length() > maxLen ? value.substring(0, maxLen - 3) + "..." : value;
        }
    }
}
