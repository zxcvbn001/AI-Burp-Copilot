package com.aiburpcopilot.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.core.pipeline.HistoryEventBus;
import com.aiburpcopilot.core.verification.ManualVerificationService;
import com.aiburpcopilot.core.verification.model.VerificationResult;
import com.aiburpcopilot.utils.HttpUtil;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class VerificationWorkbenchPanel extends JPanel {

    private static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("HH:mm:ss");

    private final IHistoryService historyService;
    private final ManualVerificationService manualVerificationService;
    private final JTable requestTable;
    private final RequestTableModel requestTableModel;
    private final JComboBox<String> parameterCombo;
    private final JComboBox<AttackType> attackTypeCombo;
    private final JButton runButton;
    private final JLabel statusLabel;
    private final BurpMessageViewer.RequestView requestViewer;
    private final BurpMessageViewer.ResponseView responseViewer;
    private final BurpMessageViewer.RequestView proofRequestViewer;
    private final BurpMessageViewer.ResponseView proofResponseViewer;
    private final JTextArea resultArea;
    private final JTextArea evidenceArea;
    private final JTabbedPane detailTabs;

    private HistoryEntry selectedEntry;
    private VerificationResult selectedResult;

    public VerificationWorkbenchPanel(MontoyaApi api,
                                      IHistoryService historyService,
                                      ManualVerificationService manualVerificationService) {
        this.historyService = historyService;
        this.manualVerificationService = manualVerificationService;
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        requestTableModel = new RequestTableModel();
        requestTable = new JTable(requestTableModel);
        requestTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestTable.setFillsViewportHeight(true);
        UiUtil.applyBurpFont(requestTable);
        UiUtil.setScaledColumnWidths(requestTable, 90, 85, 620, 100);
        requestTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onRequestSelected();
            }
        });

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 5));
        JButton refreshButton = new JButton("\u5237\u65b0\u8bf7\u6c42");
        refreshButton.addActionListener(e -> refresh());
        toolbar.add(refreshButton);

        toolbar.add(new JLabel("\u53c2\u6570:"));
        parameterCombo = new JComboBox<>();
        parameterCombo.setPrototypeDisplayValue("parameter_name_long_value");
        parameterCombo.addActionListener(e -> updateSelectionStatus());
        toolbar.add(parameterCombo);

        toolbar.add(new JLabel("\u6f0f\u6d1e\u7c7b\u578b:"));
        attackTypeCombo = new JComboBox<>(new AttackType[]{AttackType.SQLI, AttackType.XSS, AttackType.IDOR});
        attackTypeCombo.addActionListener(e -> updateSelectionStatus());
        toolbar.add(attackTypeCombo);

        runButton = new JButton("\u6267\u884c\u6700\u5c0f\u5316\u9a8c\u8bc1");
        runButton.addActionListener(e -> runVerification());
        toolbar.add(runButton);

        statusLabel = new JLabel("\u5c31\u7eea");
        toolbar.add(Box.createHorizontalStrut(20));
        toolbar.add(statusLabel);

        requestViewer = new BurpMessageViewer.RequestView(api);
        responseViewer = new BurpMessageViewer.ResponseView(api);
        proofRequestViewer = new BurpMessageViewer.RequestView(api);
        proofResponseViewer = new BurpMessageViewer.ResponseView(api);
        resultArea = UiUtil.createMessageArea();
        evidenceArea = UiUtil.createMessageArea();

        detailTabs = new JTabbedPane();
        UiUtil.applyBurpFont(detailTabs);
        detailTabs.addTab("\u539f\u59cb\u8bf7\u6c42", requestViewer);
        detailTabs.addTab("\u539f\u59cb\u54cd\u5e94", responseViewer);
        detailTabs.addTab("\u9a8c\u8bc1\u8bf7\u6c42", proofRequestViewer);
        detailTabs.addTab("\u9a8c\u8bc1\u54cd\u5e94", proofResponseViewer);
        detailTabs.addTab("\u7ed3\u8bba", UiUtil.searchableTextPanel(resultArea));
        detailTabs.addTab("\u8bc1\u636e", UiUtil.searchableTextPanel(evidenceArea));

        JSplitPane splitPane = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(requestTable),
                detailTabs);
        splitPane.setResizeWeight(0.38);

        add(toolbar, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
        refresh();
    }

    public void refresh() {
        SwingUtilities.invokeLater(() -> {
            String selectedId = selectedEntry != null ? selectedEntry.getRequestId() : null;
            List<HistoryEntry> entries = historyService.getAll().stream()
                    .filter(entry -> entry.getRawRequest() != null && entry.getRawRequest().length > 0)
                    .limit(300)
                    .toList();
            requestTableModel.setEntries(entries);
            restoreSelection(selectedId);
            if (selectedEntry == null && requestTableModel.getRowCount() > 0) {
                requestTable.setRowSelectionInterval(0, 0);
            }
        });
    }

    private void onRequestSelected() {
        selectedEntry = requestTableModel.getEntryAt(requestTable.getSelectedRow());
        selectedResult = null;
        parameterCombo.removeAllItems();
        if (selectedEntry == null) {
            clearDetails();
            return;
        }
        for (String parameter : extractParameterNames(selectedEntry)) {
            parameterCombo.addItem(parameter);
        }
        requestViewer.setBytes(selectedEntry.getRawRequest());
        responseViewer.setBytes(selectedEntry.getRawResponse());
        proofRequestViewer.setBytes(null);
        proofResponseViewer.setBytes(null);
        resultArea.setText(buildRequestSummary(selectedEntry));
        evidenceArea.setText("");
        updateSelectionStatus();
    }

    private void runVerification() {
        if (selectedEntry == null) {
            JOptionPane.showMessageDialog(this, "\u8bf7\u5148\u9009\u62e9\u4e00\u6761\u8bf7\u6c42\u3002");
            return;
        }
        String parameter = (String) parameterCombo.getSelectedItem();
        AttackType attackType = (AttackType) attackTypeCombo.getSelectedItem();
        if (parameter == null || parameter.isBlank() || attackType == null) {
            JOptionPane.showMessageDialog(this, "\u8bf7\u5148\u9009\u62e9\u53c2\u6570\u548c\u6f0f\u6d1e\u7c7b\u578b\u3002");
            return;
        }

        setRunning(true);
        resultArea.setText("\u6b63\u5728\u6267\u884c\u6700\u5c0f\u5316\u9a8c\u8bc1...\n");
        SwingWorker<List<VerificationResult>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<VerificationResult> doInBackground() {
                return manualVerificationService.runManualVerification(selectedEntry, parameter, attackType);
            }

            @Override
            protected void done() {
                try {
                    List<VerificationResult> results = get();
                    handleResults(results);
                } catch (Exception e) {
                    resultArea.setText("\u9a8c\u8bc1\u5931\u8d25: " + e.getMessage());
                    statusLabel.setText("\u9a8c\u8bc1\u5931\u8d25");
                } finally {
                    setRunning(false);
                }
            }
        };
        worker.execute();
    }

    private void handleResults(List<VerificationResult> results) {
        if (selectedEntry.getVerificationResults() == null) {
            selectedEntry.setVerificationResults(new ArrayList<>());
        }
        selectedEntry.getVerificationResults().addAll(results);
        historyService.update(selectedEntry);
        HistoryEventBus.getInstance().fireRefreshNeeded();

        selectedResult = chooseBestResult(results);
        if (selectedResult != null) {
            proofRequestViewer.setBytes(selectedResult.getMutatedRequestBytes());
            proofResponseViewer.setBytes(selectedResult.getMutatedResponseBytes());
            resultArea.setText(formatResult(selectedResult, results.size()));
            evidenceArea.setText(formatEvidence(selectedResult));
            statusLabel.setText("\u5b8c\u6210: confidence=" + String.format("%.2f", selectedResult.getConfidence()));
            detailTabs.setSelectedIndex(4);
        } else {
            resultArea.setText("\u6ca1\u6709\u4ea7\u751f\u9a8c\u8bc1\u7ed3\u679c\u3002");
            statusLabel.setText("\u65e0\u7ed3\u679c");
        }
    }

    private void updateSelectionStatus() {
        if (selectedEntry == null) {
            statusLabel.setText("\u5c31\u7eea");
            return;
        }
        Object parameter = parameterCombo.getSelectedItem();
        Object attackType = attackTypeCombo.getSelectedItem();
        statusLabel.setText("\u5df2\u9009\u62e9: "
                + nullToDash(parameter)
                + " / "
                + nullToDash(attackType));
    }

    private VerificationResult chooseBestResult(List<VerificationResult> results) {
        if (results == null || results.isEmpty()) {
            return null;
        }
        return results.stream()
                .max((left, right) -> Double.compare(left.getConfidence(), right.getConfidence()))
                .orElse(results.get(0));
    }

    private String formatResult(VerificationResult result, int resultCount) {
        StringBuilder builder = new StringBuilder();
        builder.append("\u7ed3\u679c\u6570: ").append(resultCount).append("\n");
        builder.append("\u6f0f\u6d1e\u7c7b\u578b: ").append(nullToDash(result.getAttackType())).append("\n");
        builder.append("\u53c2\u6570: ").append(nullToDash(result.getParameter())).append("\n");
        builder.append("\u9636\u6bb5: ").append(nullToDash(result.getPhase())).append("\n");
        builder.append("Payload: ").append(nullToDash(result.getPayload())).append("\n");
        builder.append("\u7f6e\u4fe1\u5ea6: ").append(String.format("%.2f", result.getConfidence())).append("\n");
        builder.append("\u98ce\u9669\u7b49\u7ea7: ").append(nullToDash(result.getRiskLevel())).append("\n\n");
        builder.append(result.getReasoning() != null ? result.getReasoning() : "N/A");
        return builder.toString();
    }

    private String formatEvidence(VerificationResult result) {
        StringBuilder builder = new StringBuilder();
        builder.append("=== Diff ===\n");
        builder.append(VerificationUiSupport.formatDiffChinese(result.getDiffResult(), result.getResponseTimeMs()));
        builder.append("\n\n=== Exchange ===\n");
        builder.append(result.getExchangeTranscript() != null ? result.getExchangeTranscript() : "\u6682\u65e0\u5b8c\u6574\u8fc7\u7a0b\u8bb0\u5f55");
        return builder.toString();
    }

    private List<String> extractParameterNames(HistoryEntry entry) {
        List<String> names = new ArrayList<>();
        String url = entry.getUrl();
        if (url != null) {
            int queryIndex = url.indexOf('?');
            if (queryIndex >= 0 && queryIndex < url.length() - 1) {
                HttpUtil.parseQueryParams(url.substring(queryIndex + 1))
                        .forEach(parameter -> addUnique(names, parameter.getName()));
            }
        }
        if (entry.getRequestBody() != null) {
            if (HttpUtil.isFormContent(entry.getContentType())) {
                HttpUtil.parseFormBodyParams(entry.getRequestBody())
                        .forEach(parameter -> addUnique(names, parameter.getName()));
            } else if (HttpUtil.isJsonContent(entry.getContentType())) {
                HttpUtil.parseJsonBodyParams(entry.getRequestBody())
                        .forEach(parameter -> addUnique(names, parameter.getName()));
            }
        }
        return names;
    }

    private void addUnique(List<String> names, String name) {
        if (name != null && !name.isBlank() && !names.contains(name)) {
            names.add(name);
        }
    }

    private String buildRequestSummary(HistoryEntry entry) {
        return "\u624b\u52a8\u9a8c\u8bc1\u5de5\u4f5c\u53f0\n\n"
                + "\u65b9\u6cd5: " + nullToDash(entry.getMethod()) + "\n"
                + "URL: " + nullToDash(entry.getUrl()) + "\n"
                + "\u53c2\u6570\u6570: " + parameterCombo.getItemCount() + "\n\n"
                + "\u8bf7\u9009\u62e9\u53c2\u6570\u548c\u6f0f\u6d1e\u7c7b\u578b\uff0c\u7136\u540e\u6267\u884c\u6700\u5c0f\u5316\u9a8c\u8bc1\u3002";
    }

    private void restoreSelection(String requestId) {
        if (requestId == null) {
            return;
        }
        for (int index = 0; index < requestTableModel.getRowCount(); index++) {
            HistoryEntry entry = requestTableModel.getEntryAt(index);
            if (requestId.equals(entry.getRequestId())) {
                requestTable.setRowSelectionInterval(index, index);
                return;
            }
        }
    }

    private void clearDetails() {
        requestViewer.setBytes(null);
        responseViewer.setBytes(null);
        proofRequestViewer.setBytes(null);
        proofResponseViewer.setBytes(null);
        resultArea.setText("");
        evidenceArea.setText("");
        statusLabel.setText("\u5c31\u7eea");
    }

    private void setRunning(boolean running) {
        runButton.setEnabled(!running);
        requestTable.setEnabled(!running);
        parameterCombo.setEnabled(!running);
        attackTypeCombo.setEnabled(!running);
        statusLabel.setText(running ? "\u9a8c\u8bc1\u4e2d..." : "\u5c31\u7eea");
    }

    private static String nullToDash(Object value) {
        return value != null ? String.valueOf(value) : "-";
    }

    private static class RequestTableModel extends AbstractTableModel {
        private final String[] columns = {"\u65f6\u95f4", "\u65b9\u6cd5", "URL", "\u72b6\u6001"};
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
        @Override public String getColumnName(int column) { return columns[column]; }

        @Override
        public Object getValueAt(int row, int column) {
            HistoryEntry entry = entries.get(row);
            return switch (column) {
                case 0 -> TIME_FORMAT.format(new Date(entry.getTimestamp()));
                case 1 -> entry.getMethod();
                case 2 -> entry.getUrl();
                case 3 -> entry.getStatusCode();
                default -> "";
            };
        }
    }
}
