package com.aiburpcopilot.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.core.pipeline.HistoryEventBus;
import com.aiburpcopilot.core.verification.model.Evidence;
import com.aiburpcopilot.core.verification.model.ExchangeRecord;
import com.aiburpcopilot.core.verification.model.FinalVerdicts;
import com.aiburpcopilot.core.verification.model.VerificationResult;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class VerificationPanel extends JPanel {

    private static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("HH:mm:ss");
    private static final String EMPTY_DIFF_TEXT = "暂无差异分析。\n可能是请求超时、重放失败，或没有捕获到响应。";

    private final MontoyaApi api;
    private final IHistoryService historyService;
    private final JTable table;
    private final VerificationTableModel tableModel;
    private final JList<ExchangeItem> exchangeList;
    private final DefaultListModel<ExchangeItem> exchangeListModel;
    private final BurpMessageViewer.RequestView requestViewer;
    private final BurpMessageViewer.ResponseView responseViewer;
    private final BurpMessageViewer.ResponseView baselineViewer;
    private final JTextArea diffArea;
    private final JTextArea reasoningArea;
    private final JLabel statusLabel;
    private final JLabel exchangeHintLabel;
    private final JLabel exchangeTitleLabel;
    private final JTabbedPane detailTabs;
    private String displayedWorkflowKey;
    private String displayedExchangeKey;
    private boolean refreshing;

    public VerificationPanel(MontoyaApi api, IHistoryService historyService) {
        this.api = api;
        this.historyService = historyService;
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 5));
        JButton refreshBtn = new JButton("刷新");
        refreshBtn.addActionListener(e -> refresh());
        toolbar.add(refreshBtn);

        JButton confirmBtn = new JButton("确认有效漏洞");
        confirmBtn.addActionListener(e -> setSelectedConfirmed(true));
        toolbar.add(confirmBtn);

        JButton unconfirmBtn = new JButton("取消确认");
        unconfirmBtn.addActionListener(e -> setSelectedConfirmed(false));
        toolbar.add(unconfirmBtn);

        statusLabel = new JLabel("验证结果: 0");
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
        UiUtil.setScaledMinimumColumnWidths(table, 70, 160, 100, 90, 130, 70, 85, 70, 75, 65);
        colModel.getColumn(8).setCellRenderer(new ConfidenceRenderer());

        exchangeListModel = new DefaultListModel<>();
        exchangeList = new JList<>(exchangeListModel);
        exchangeList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        exchangeList.setCellRenderer(new ExchangeItemRenderer());
        UiUtil.applyBurpLabelFont(exchangeList);

        requestViewer = new BurpMessageViewer.RequestView(api);
        responseViewer = new BurpMessageViewer.ResponseView(api);
        baselineViewer = new BurpMessageViewer.ResponseView(api);
        diffArea = UiUtil.createMessageArea();
        reasoningArea = UiUtil.createMessageArea();
        exchangeHintLabel = new JLabel("未选择交换记录");

        detailTabs = new JTabbedPane();
        UiUtil.applyBurpFont(detailTabs);
        detailTabs.addTab("请求", requestViewer);
        detailTabs.addTab("响应", responseViewer);
        detailTabs.addTab("基线响应", baselineViewer);
        detailTabs.addTab("差异摘要", UiUtil.searchableTextPanel(diffArea));
        detailTabs.addTab("判断依据", UiUtil.searchableTextPanel(reasoningArea));

        JPanel exchangePanel = new JPanel(new BorderLayout(0, 6));
        exchangePanel.setBorder(new EmptyBorder(6, 6, 6, 6));
        exchangeTitleLabel = new JLabel("请求 / 响应执行记录");
        exchangePanel.add(exchangeTitleLabel, BorderLayout.NORTH);
        exchangePanel.add(new JScrollPane(exchangeList), BorderLayout.CENTER);
        exchangePanel.add(exchangeHintLabel, BorderLayout.SOUTH);

        JSplitPane lowerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, exchangePanel, detailTabs);
        lowerSplit.setResizeWeight(0.24);
        lowerSplit.setDividerLocation(260);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), lowerSplit);
        mainSplit.setResizeWeight(0.34);
        mainSplit.setDividerLocation(220);
        add(mainSplit, BorderLayout.CENTER);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !refreshing) {
                updateWorkflowDetail();
            }
        });
        exchangeList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !refreshing) {
                updateExchangeDetail();
            }
        });

        refresh();
    }

    public void refresh() {
        SwingUtilities.invokeLater(() -> {
            String selectedKey = selectedWorkflowKey();
            String selectedExchangeKey = selectedExchangeKey();
            int selectedTab = detailTabs.getSelectedIndex();
            refreshing = true;
            List<VerificationUiSupport.ResultRow> rows = collectWorkflowRows();
            tableModel.setRows(rows);
            statusLabel.setText("验证结果: " + rows.size());
            restoreWorkflowSelection(selectedKey);
            if (selectedTab >= 0 && selectedTab < detailTabs.getTabCount()) {
                detailTabs.setSelectedIndex(selectedTab);
            }
            refreshing = false;
            updateWorkflowDetail();
            restoreExchangeSelection(selectedExchangeKey);
        });
    }

    private void updateWorkflowDetail() {
        VerificationUiSupport.ResultRow row = tableModel.getRowAt(table.getSelectedRow());
        if (row == null) {
            displayedWorkflowKey = null;
            exchangeTitleLabel.setText("请求 / 响应执行记录");
            exchangeListModel.clear();
            clearExchangeDetail(EMPTY_DIFF_TEXT);
            reasoningArea.setText("");
            exchangeHintLabel.setText("未选择交换记录");
            return;
        }

        VerificationResult result = row.result();
        String currentWorkflowKey = VerificationUiSupport.workflowKey(row.entry(), result);
        boolean sameWorkflow = currentWorkflowKey.equals(displayedWorkflowKey);
        displayedWorkflowKey = currentWorkflowKey;
        UiUtil.setTextPreservingView(reasoningArea, buildReasoningText(result), sameWorkflow);

        List<ExchangeItem> items = buildExchangeItems(collectWorkflowResults(displayedWorkflowKey), result);
        exchangeListModel.clear();
        for (ExchangeItem item : items) {
            exchangeListModel.addElement(item);
        }
        long matchedCount = items.stream().filter(ExchangeItem::matched).count();
        exchangeTitleLabel.setText(items.isEmpty()
                ? "请求 / 响应执行记录"
                : "请求 / 响应执行记录（命中 " + matchedCount + " / " + items.size() + "）");
        exchangeHintLabel.setText(items.isEmpty()
                ? "当前结果没有可展示的请求 / 响应"
                : "共 " + items.size() + " 条执行记录，选中后右侧显示详情");
        if (!items.isEmpty()) {
            String preservedExchangeKey = displayedExchangeKey != null ? displayedExchangeKey : selectedExchangeKey();
            if (preservedExchangeKey != null) {
                restoreExchangeSelection(preservedExchangeKey);
            }
            if (exchangeList.getSelectedIndex() < 0) {
                exchangeList.setSelectedIndex(0);
            }
        } else {
            displayedExchangeKey = null;
            clearExchangeDetail(EMPTY_DIFF_TEXT);
        }
    }

    private void updateExchangeDetail() {
        ExchangeItem item = exchangeList.getSelectedValue();
        if (item == null) {
            displayedExchangeKey = null;
            clearExchangeDetail(EMPTY_DIFF_TEXT);
            return;
        }
        boolean sameExchange = item.key().equals(displayedExchangeKey);
        requestViewer.setBytes(item.requestBytes());
        responseViewer.setBytes(item.responseBytes());
        baselineViewer.setBytes(item.baselineResponseBytes());
        UiUtil.setTextPreservingView(diffArea, item.diffText(), sameExchange);
        exchangeHintLabel.setText(item.hint());
        displayedExchangeKey = item.key();
    }

    private void clearExchangeDetail(String diffText) {
        requestViewer.setBytes(null);
        responseViewer.setBytes(null);
        baselineViewer.setBytes(null);
        UiUtil.setTextPreservingView(diffArea, diffText, false);
    }

    private List<VerificationUiSupport.ResultRow> collectWorkflowRows() {
        Map<String, VerificationUiSupport.ResultRow> grouped = new LinkedHashMap<>();
        for (VerificationUiSupport.ResultRow row : VerificationUiSupport.collectRows(historyService)) {
            VerificationResult result = row.result();
            if (VerificationUiSupport.isInfluence(result)) {
                continue;
            }
            String key = VerificationUiSupport.workflowKey(row.entry(), result);
            VerificationUiSupport.ResultRow previous = grouped.get(key);
            if (previous == null || isBetterWorkflowRepresentative(result, previous.result())) {
                grouped.put(key, row);
            }
        }
        return List.copyOf(grouped.values());
    }

    private List<VerificationResult> collectWorkflowResults(String workflowKey) {
        if (workflowKey == null || workflowKey.isBlank()) {
            return List.of();
        }
        List<VerificationResult> results = new ArrayList<>();
        for (VerificationUiSupport.ResultRow row : VerificationUiSupport.collectRows(historyService)) {
            VerificationResult result = row.result();
            if (result == null || VerificationUiSupport.isInfluence(result)) {
                continue;
            }
            if (workflowKey.equals(VerificationUiSupport.workflowKey(row.entry(), result))) {
                results.add(result);
            }
        }
        return results;
    }

    private boolean isBetterWorkflowRepresentative(VerificationResult candidate, VerificationResult current) {
        return VerificationUiSupport.isBetterWorkflowRepresentative(candidate, current);
    }

    private List<ExchangeItem> buildExchangeItems(List<VerificationResult> groupedResults, VerificationResult selectedResult) {
        List<ExchangeItem> items = new ArrayList<>();
        Map<String, ExchangeItem> dedup = new LinkedHashMap<>();
        int index = 1;
        for (VerificationResult result : groupedResults) {
            List<ExchangeRecord> records = result.getExchangeRecords() != null ? result.getExchangeRecords() : List.of();
            for (ExchangeRecord record : records) {
                if (record == null) {
                    continue;
                }
                byte[] request = record.getRequestBytes();
                byte[] response = record.getResponseBytes();
                byte[] baselineResponse = firstNonEmpty(record.getBaselineResponseBytes(), selectedResult.getBaselineResponseBytes());
                if (isEmpty(request) && isEmpty(response) && isEmpty(baselineResponse)) {
                    continue;
                }
                String key = record.getExchangeKey() != null && !record.getExchangeKey().isBlank()
                        ? record.getExchangeKey()
                        : "exchange-" + index;
                ExchangeItem candidate = new ExchangeItem(
                        key,
                        buildExchangeTitle(index, record),
                        buildExchangeHint(index, record),
                        request,
                        response,
                        baselineResponse,
                        buildExchangeDiffText(record, index),
                        record.isMatched());
                ExchangeItem existing = dedup.get(key);
                if (existing == null || (!existing.matched() && candidate.matched())) {
                    dedup.put(key, candidate);
                }
                index++;
            }
        }
        items.addAll(dedup.values());
        if (!items.isEmpty()) {
            return items;
        }

        List<Evidence> evidences = selectedResult.getEvidences() != null ? selectedResult.getEvidences() : List.of();
        int evidenceIndex = 1;
        for (Evidence evidence : evidences) {
            byte[] request = firstNonEmpty(evidence.getMutatedRequest(), evidence.getRequest());
            byte[] response = evidence.getMutatedResponse();
            byte[] baseline = evidence.getOriginalResponse();
            if (isEmpty(request) && isEmpty(response) && isEmpty(baseline)) {
                continue;
            }
            items.add(new ExchangeItem(
                    "evidence-" + evidenceIndex,
                    "Request " + evidenceIndex + " / Response " + evidenceIndex + " | 命中",
                    buildEvidenceHint(evidenceIndex, evidence),
                    request,
                    response,
                    baseline,
                    buildEvidenceDiffText(selectedResult, evidence, evidenceIndex),
                    true));
            evidenceIndex++;
        }
        if (items.isEmpty() && (!isEmpty(selectedResult.getMutatedRequestBytes()) || !isEmpty(selectedResult.getMutatedResponseBytes()))) {
            items.add(new ExchangeItem(
                    "fallback-1",
                    "Request 1 / Response 1 | 未标记命中",
                    "当前结果未拆分到执行级记录，显示步骤级请求 / 响应",
                    firstNonEmpty(selectedResult.getMutatedRequestBytes(), selectedResult.getBaselineRequestBytes()),
                    selectedResult.getMutatedResponseBytes(),
                    selectedResult.getBaselineResponseBytes(),
                    buildFallbackDiffText(selectedResult),
                    false));
        }
        return items;
    }

    private String buildExchangeTitle(int index, ExchangeRecord record) {
        StringBuilder title = new StringBuilder();
        title.append("Request ").append(index).append(" / Response ").append(index);
        title.append(record.isMatched() ? " | 命中" : " | 未命中");
        if (record.getProbeId() != null && !record.getProbeId().isBlank()) {
            title.append(" | ").append(record.getProbeId());
        }
        if (record.getRole() != null) {
            title.append(" | ").append(record.getRole().name());
        }
        return title.toString();
    }

    private String buildExchangeHint(int index, ExchangeRecord record) {
        StringBuilder hint = new StringBuilder();
        hint.append(record.isMatched() ? "命中记录 " : "执行记录 ").append(index);
        if (record.getEvidenceType() != null && !record.getEvidenceType().isBlank()) {
            hint.append(" | ").append(record.getEvidenceType());
        }
        hint.append(" | conf=").append(String.format("%.2f", record.getConfidence()));
        if (record.getDescription() != null && !record.getDescription().isBlank()) {
            hint.append(" | ").append(record.getDescription());
        }
        return hint.toString();
    }

    private String buildExchangeDiffText(ExchangeRecord record, int index) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== 执行记录 ").append(index).append(" ===\n\n");
        sb.append("命中状态: ").append(record.isMatched() ? "命中" : "未命中").append("\n");
        if (record.getProbeId() != null && !record.getProbeId().isBlank()) {
            sb.append("Probe: ").append(record.getProbeId()).append("\n");
        }
        if (record.getRole() != null) {
            sb.append("Role: ").append(record.getRole().name()).append("\n");
        }
        if (record.getPayload() != null && !record.getPayload().isBlank()) {
            sb.append("Payload: ").append(record.getPayload()).append("\n");
        }
        sb.append("Confidence: ").append(String.format("%.2f", record.getConfidence())).append("\n");
        if (record.getEvidenceType() != null && !record.getEvidenceType().isBlank()) {
            sb.append("EvidenceType: ").append(record.getEvidenceType()).append("\n");
        }
        if (record.getDescription() != null && !record.getDescription().isBlank()) {
            sb.append("Description: ").append(record.getDescription()).append("\n");
        }
        if (record.getDiffDescription() != null && !record.getDiffDescription().isBlank()) {
            sb.append("Diff: ").append(record.getDiffDescription()).append("\n");
        } else if (!record.isMatched()) {
            sb.append("Diff: 本次执行未命中本地证据规则。\n");
        }
        if (!isEmpty(record.getBaselineResponseBytes())) {
            sb.append("\n已附带 baseline response，可在右侧对照。\n");
        }
        return sb.toString();
    }

    private String buildEvidenceHint(int index, Evidence evidence) {
        StringBuilder hint = new StringBuilder();
        hint.append("命中记录 ").append(index);
        if (evidence.getEvidenceType() != null && !evidence.getEvidenceType().isBlank()) {
            hint.append(" | ").append(evidence.getEvidenceType());
        }
        hint.append(" | conf=").append(String.format("%.2f", evidence.getConfidence()));
        if (evidence.getDescription() != null && !evidence.getDescription().isBlank()) {
            hint.append(" | ").append(evidence.getDescription());
        }
        return hint.toString();
    }

    private String buildEvidenceDiffText(VerificationResult result, Evidence evidence, int index) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== 交换记录 ").append(index).append(" ===\n\n");
        if (evidence.getEvidenceType() != null) {
            sb.append("证据类型: ").append(evidence.getEvidenceType()).append("\n");
        }
        sb.append("证据置信度: ").append(String.format("%.2f", evidence.getConfidence())).append("\n");
        if (evidence.getDescription() != null && !evidence.getDescription().isBlank()) {
            sb.append("证据说明: ").append(evidence.getDescription()).append("\n");
        }
        if (evidence.getDiffDescription() != null && !evidence.getDiffDescription().isBlank()) {
            sb.append("差异说明: ").append(evidence.getDiffDescription()).append("\n");
        }
        if (!isEmpty(evidence.getOriginalResponse())) {
            sb.append("已携带基线响应，可与当前响应对照。\n");
        }
        if (!isEmpty(evidence.getBaselineRequest())) {
            sb.append("已携带基线请求，可与变异请求对照。\n");
        }
        if (evidence.getBaselineSummary() != null && !evidence.getBaselineSummary().isBlank()) {
            sb.append("基线摘要: ").append(evidence.getBaselineSummary()).append("\n");
        }
        if (result.getDiffResult() != null) {
            sb.append("\n").append(VerificationUiSupport.formatDiffChinese(result.getDiffResult(), result.getResponseTimeMs()));
        }
        return sb.toString();
    }

    private String buildFallbackDiffText(VerificationResult result) {
        if (result.getDiffResult() != null) {
            return VerificationUiSupport.formatDiffChinese(result.getDiffResult(), result.getResponseTimeMs());
        }
        return EMPTY_DIFF_TEXT;
    }

    private String buildReasoningText(VerificationResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Confidence: ").append(String.format("%.2f", result.getConfidence()));
        if (result.getRiskLevel() != null) {
            sb.append(" (").append(result.getRiskLevel().name()).append(")");
        }
        sb.append(" ===\n\n");
        sb.append(result.getReasoning() != null ? result.getReasoning() : "N/A");
        sb.append("\n\n=== Finding Aggregation ===\n");
        sb.append("generated=").append(result.isFindingGenerated()).append("\n");
        sb.append("rawConfidence=").append(String.format("%.4f", result.getFindingConfidenceRaw())).append("\n");
        if (result.getFindingThreshold() > 0) {
            sb.append("threshold=").append(String.format("%.4f", result.getFindingThreshold())).append("\n");
        }
        sb.append("finalDecision=").append(result.getFinalDecision() != null ? result.getFinalDecision() : "-").append("\n");
        sb.append("localMatched=").append(result.isLocalMatched()).append("\n");
        sb.append("llmMatched=").append(result.getLlmMatched() != null ? result.getLlmMatched() : "null").append("\n");
        sb.append("manualOverride=").append(result.getManualConfirmedOverride() != null ? result.getManualConfirmedOverride() : "null").append("\n");
        if (result.getFindingDecisionReason() != null && !result.getFindingDecisionReason().isBlank()) {
            sb.append("decision=").append(result.getFindingDecisionReason()).append("\n");
        }
        if (result.getRejectReason() != null && !result.getRejectReason().isBlank()) {
            sb.append("rejectReason=").append(result.getRejectReason()).append("\n");
        }
        List<ExchangeRecord> records = result.getExchangeRecords();
        if (records != null && !records.isEmpty()) {
            sb.append("\n\n=== Execution Records ===\n");
            for (int i = 0; i < records.size(); i++) {
                ExchangeRecord record = records.get(i);
                sb.append("- Request ").append(i + 1).append(" / Response ").append(i + 1);
                sb.append(record.isMatched() ? " | 命中" : " | 未命中");
                if (record.getProbeId() != null && !record.getProbeId().isBlank()) {
                    sb.append(" | ").append(record.getProbeId());
                }
                if (record.getRole() != null) {
                    sb.append(" | ").append(record.getRole().name());
                }
                sb.append(" | conf=").append(String.format("%.2f", record.getConfidence()));
                if (record.getDescription() != null && !record.getDescription().isBlank()) {
                    sb.append(" | ").append(record.getDescription());
                }
                sb.append("\n");
            }
        }
        return sb.toString();
    }

    private void setSelectedConfirmed(boolean confirmed) {
        VerificationUiSupport.ResultRow row = tableModel.getRowAt(table.getSelectedRow());
        if (row == null) {
            JOptionPane.showMessageDialog(this, "请先选择一条验证记录。");
            return;
        }
        row.result().setManualConfirmedOverride(confirmed);
        if (confirmed) {
            row.result().setFinalDecision(FinalVerdicts.MANUAL_CONFIRMED);
        } else {
            row.result().setFinalDecision(FinalVerdicts.MANUAL_REJECTED);
            row.result().setRejectReason("Manually rejected by analyst.");
        }
        FinalVerdicts.recompute(row.result());
        historyService.update(row.entry());
        HistoryEventBus.getInstance().fireRefreshNeeded();
        refresh();
    }

    private String selectedWorkflowKey() {
        VerificationUiSupport.ResultRow row = tableModel.getRowAt(table.getSelectedRow());
        return row != null ? VerificationUiSupport.workflowKey(row.entry(), row.result()) : null;
    }

    private String selectedExchangeKey() {
        ExchangeItem item = exchangeList.getSelectedValue();
        return item != null ? item.key() : null;
    }

    private void restoreWorkflowSelection(String key) {
        if (key == null) {
            return;
        }
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            VerificationUiSupport.ResultRow row = tableModel.getRowAt(i);
            if (row != null && key.equals(VerificationUiSupport.workflowKey(row.entry(), row.result()))) {
                table.setRowSelectionInterval(i, i);
                return;
            }
        }
    }

    private void restoreExchangeSelection(String key) {
        if (key == null) {
            return;
        }
        for (int i = 0; i < exchangeListModel.size(); i++) {
            ExchangeItem item = exchangeListModel.get(i);
            if (item != null && key.equals(item.key())) {
                exchangeList.setSelectedIndex(i);
                return;
            }
        }
    }

    private static byte[] firstNonEmpty(byte[] first, byte[] second) {
        return !isEmpty(first) ? first : second;
    }

    private static boolean isEmpty(byte[] bytes) {
        return bytes == null || bytes.length == 0;
    }

    private record ExchangeItem(String key,
                                String title,
                                String hint,
                                byte[] requestBytes,
                                byte[] responseBytes,
                                byte[] baselineResponseBytes,
                                String diffText,
                                boolean matched) {
        @Override
        public String toString() {
            return title;
        }
    }

    private static class ExchangeItemRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                      boolean isSelected, boolean cellHasFocus) {
            JLabel label = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            if (value instanceof ExchangeItem item) {
                label.setText(item.title() + "  |  " + item.hint());
            }
            return label;
        }
    }

    private static class VerificationTableModel extends AbstractTableModel {
        private final String[] columns = {
                "Time", "URI", "Attack", "Param", "Phase",
                "Len", "Time(ms)", "Sim", "Conf", "Risk"
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
                case 5 -> result.getResponseLength() > 0 ? String.valueOf(result.getResponseLength()) : "-";
                case 6 -> result.getResponseTimeMs() > 0 ? String.valueOf(result.getResponseTimeMs()) : "-";
                case 7 -> result.getDiffResult() != null ? String.format("%.2f", result.getDiffResult().getSimilarity()) : "-";
                case 8 -> String.format("%.2f", result.getConfidence());
                case 9 -> result.getRiskLevel() != null ? result.getRiskLevel().name() : "N/A";
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
