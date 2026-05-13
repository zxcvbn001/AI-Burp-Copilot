package com.aiburpcopilot.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.core.pipeline.HistoryEventBus;
import com.aiburpcopilot.core.verification.model.ReviewStatus;
import com.aiburpcopilot.core.verification.model.VerificationResult;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

public class VerificationPanel extends JPanel {

    private static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("HH:mm:ss");
    private final MontoyaApi api;
    private final IHistoryService historyService;
    private final JTable table;
    private final VerificationTableModel tableModel;
    private final BurpMessageViewer.RequestView requestViewer;
    private final BurpMessageViewer.ResponseView responseViewer;
    private final JTextArea diffArea;
    private final JTextArea reasoningArea;
    private final JTabbedPane detailTabs;
    private final JLabel statusLabel;
    private String displayedKey;
    private boolean refreshing;

    public VerificationPanel(MontoyaApi api, IHistoryService historyService) {
        this.api = api;
        this.historyService = historyService;
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 5));
        JButton refreshBtn = new JButton("\u5237\u65b0");
        refreshBtn.addActionListener(e -> refresh());
        toolbar.add(refreshBtn);

        JButton confirmBtn = new JButton("\u786e\u8ba4\u6709\u6548\u6f0f\u6d1e");
        confirmBtn.addActionListener(e -> setSelectedConfirmed(true));
        toolbar.add(confirmBtn);

        JButton unconfirmBtn = new JButton("\u53d6\u6d88\u786e\u8ba4");
        unconfirmBtn.addActionListener(e -> setSelectedConfirmed(false));
        toolbar.add(unconfirmBtn);

        statusLabel = new JLabel("\u9a8c\u8bc1\u7ed3\u679c: 0");
        toolbar.add(Box.createHorizontalStrut(20));
        toolbar.add(statusLabel);
        add(toolbar, BorderLayout.NORTH);

        tableModel = new VerificationTableModel();
        table = new JTable(tableModel);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);
        UiUtil.applyBurpFont(table);

        TableColumnModel colModel = table.getColumnModel();
        UiUtil.setScaledMinimumColumnWidths(table,
                70,   // Time
                160,  // Attack Type
                100,  // Parameter
                90,   // Phase
                130,  // Strategy
                90,   // Payload
                70,   // Status
                85,   // Risk
                70,   // Evidence
                75,   // Confidence
                65);  // Confirmed
        colModel.getColumn(9).setCellRenderer(new ConfidenceRenderer());

        requestViewer = new BurpMessageViewer.RequestView(api);
        responseViewer = new BurpMessageViewer.ResponseView(api);
        diffArea = UiUtil.createMessageArea();
        reasoningArea = UiUtil.createMessageArea();

        detailTabs = new JTabbedPane();
        UiUtil.applyBurpFont(detailTabs);
        detailTabs.addTab("\u8bf7\u6c42", requestViewer);
        detailTabs.addTab("\u54cd\u5e94", responseViewer);
        detailTabs.addTab("\u5dee\u5f02\u6458\u8981", UiUtil.searchableTextPanel(diffArea));
        detailTabs.addTab("\u5224\u65ad\u4f9d\u636e", UiUtil.searchableTextPanel(reasoningArea));

        JSplitPane splitPane = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table),
                detailTabs);
        splitPane.setResizeWeight(0.35);
        splitPane.setDividerLocation(200);
        add(splitPane, BorderLayout.CENTER);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !refreshing) {
                updateDetail();
            }
        });

        refresh();
    }

    public void refresh() {
        SwingUtilities.invokeLater(() -> {
            String selectedKey = selectedKey();
            int selectedTab = detailTabs.getSelectedIndex();
            refreshing = true;
            List<VerificationUiSupport.ResultRow> rows = VerificationUiSupport.collectRows(historyService)
                    .stream()
                    .filter(row -> VerificationUiSupport.isPayloadVerification(row.result()))
                    .toList();
            tableModel.setRows(rows);
            statusLabel.setText("\u9a8c\u8bc1\u7ed3\u679c: " + rows.size());
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
            requestViewer.setBytes(null);
            responseViewer.setBytes(null);
            diffArea.setText("\u6682\u65e0\u5dee\u5f02\u5206\u6790\u3002\n\u53ef\u80fd\u662f\u8bf7\u6c42\u8d85\u65f6\u3001\u91cd\u653e\u5931\u8d25\uff0c\u6216\u6ca1\u6709\u6355\u83b7\u5230\u54cd\u5e94\u3002");
            reasoningArea.setText("");
            return;
        }

        VerificationResult result = row.result();
        String currentKey = VerificationUiSupport.rowKey(row.entry(), result);
        boolean sameRow = currentKey.equals(displayedKey);
        int[] positions = sameRow ? captureCaretPositions() : null;
        requestViewer.setBytes(result.getMutatedRequestBytes());
        responseViewer.setBytes(result.getMutatedResponseBytes());
        updateDiffTab(result);
        updateReasoningTab(result);
        displayedKey = currentKey;
        if (sameRow) {
            restoreCaretPositions(positions);
        } else {
            diffArea.setCaretPosition(0);
            reasoningArea.setCaretPosition(0);
        }
    }

    private void updateDiffTab(VerificationResult result) {
        if (result.getDiffResult() != null) {
            diffArea.setText(VerificationUiSupport.formatDiffChinese(result.getDiffResult(), result.getResponseTimeMs()));
        } else {
            diffArea.setText("\u6682\u65e0\u5dee\u5f02\u5206\u6790\u3002\n\u53ef\u80fd\u662f\u8bf7\u6c42\u8d85\u65f6\u3001\u91cd\u653e\u5931\u8d25\uff0c\u6216\u6ca1\u6709\u6355\u83b7\u5230\u54cd\u5e94\u3002");
        }
        if (displayedKey == null) {
            diffArea.setCaretPosition(0);
        }
    }

    private void updateReasoningTab(VerificationResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Confidence: ").append(String.format("%.2f", result.getConfidence()));
        if (result.getRiskLevel() != null) {
            sb.append(" (").append(result.getRiskLevel().name()).append(")");
        }
        sb.append(" ===\n\n");
        sb.append(result.getReasoning() != null ? result.getReasoning() : "N/A");
        reasoningArea.setText(sb.toString());
        if (displayedKey == null) {
            reasoningArea.setCaretPosition(0);
        }
    }

    private void setSelectedConfirmed(boolean confirmed) {
        VerificationUiSupport.ResultRow row = tableModel.getRowAt(table.getSelectedRow());
        if (row == null) {
            JOptionPane.showMessageDialog(this, "\u8bf7\u5148\u9009\u62e9\u4e00\u6761\u9a8c\u8bc1\u8bb0\u5f55\u3002");
            return;
        }
        row.result().setConfirmedVulnerability(confirmed);
        row.result().setReviewStatus(confirmed ? ReviewStatus.PENDING : ReviewStatus.NOT_REQUIRED);
        if (!confirmed) {
            row.result().setLlmReview(null);
        }
        historyService.update(row.entry());
        HistoryEventBus.getInstance().fireRefreshNeeded();
        refresh();
    }

    private String selectedKey() {
        VerificationUiSupport.ResultRow row = tableModel.getRowAt(table.getSelectedRow());
        return row != null ? VerificationUiSupport.rowKey(row.entry(), row.result()) : null;
    }

    private void restoreSelection(String key) {
        if (key == null) {
            return;
        }
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            VerificationUiSupport.ResultRow row = tableModel.getRowAt(i);
            if (key.equals(VerificationUiSupport.rowKey(row.entry(), row.result()))) {
                table.setRowSelectionInterval(i, i);
                return;
            }
        }
    }

    private static class VerificationTableModel extends AbstractTableModel {
        private final String[] columns = {
                "Time", "URI", "Attack", "Param", "Phase",
                "Payload", "Len", "Time(ms)", "Sim", "Conf", "Risk"
        };
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
                case 1 -> result.getUrl() != null ? truncate(result.getUrl(), 80) : "-";
                case 2 -> result.getAttackTypeName() != null
                        ? result.getAttackTypeName()
                        : (result.getAttackType() != null ? result.getAttackType().getDisplayName() : "N/A");
                case 3 -> result.getParameter() != null ? result.getParameter() : "-";
                case 4 -> result.getPhase() != null ? result.getPhase()
                        : (result.getStrategyName() != null ? result.getStrategyName() : "N/A");
                case 5 -> result.getPayload() != null ? truncate(result.getPayload(), 30) : "-";
                case 6 -> result.getResponseLength() > 0 ? String.valueOf(result.getResponseLength()) : "-";
                case 7 -> result.getResponseTimeMs() > 0 ? String.valueOf(result.getResponseTimeMs()) : "-";
                case 8 -> result.getDiffResult() != null ? String.format("%.2f", result.getDiffResult().getSimilarity()) : "-";
                case 9 -> String.format("%.2f", result.getConfidence());
                case 10 -> result.getRiskLevel() != null ? result.getRiskLevel().name() : "N/A";
                default -> "";
            };
        }

        private static String truncate(String value, int maxLen) {
            if (value == null) {
                return "-";
            }
            return value.length() <= maxLen ? value : value.substring(0, maxLen - 3) + "...";
        }
    }

    private int[] captureCaretPositions() {
        return new int[]{
                diffArea.getCaretPosition(),
                reasoningArea.getCaretPosition()
        };
    }

    private void restoreCaretPositions(int[] positions) {
        if (positions == null || positions.length < 2) {
            return;
        }
        setCaretSafely(diffArea, positions[0]);
        setCaretSafely(reasoningArea, positions[1]);
    }

    private void setCaretSafely(javax.swing.text.JTextComponent component, int position) {
        component.setCaretPosition(Math.max(0, Math.min(position, component.getDocument().getLength())));
    }

    private static class ConfidenceRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                try {
                    double conf = Double.parseDouble(value.toString());
                    if (conf >= 0.9) {
                        component.setForeground(new Color(0, 150, 0));
                    } else if (conf >= 0.7) {
                        component.setForeground(new Color(200, 120, 0));
                    } else if (conf >= 0.5) {
                        component.setForeground(new Color(200, 80, 0));
                    } else {
                        component.setForeground(Color.GRAY);
                    }
                } catch (NumberFormatException e) {
                    component.setForeground(Color.BLACK);
                }
            }
            return component;
        }
    }
}

