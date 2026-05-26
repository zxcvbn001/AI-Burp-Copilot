package com.aiburpcopilot.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.scanner.staticresource.StaticScanResult;
import com.aiburpcopilot.utils.PluginLogger;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

public class StaticScanPanel extends JPanel {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("HH:mm:ss");

    private final IHistoryService historyService;
    private final JTable table;
    private final StaticScanTableModel tableModel;
    private final JTabbedPane detailTabs;
    private final JTextArea findingArea;
    private final JTable cloudFindingTable;
    private final CloudFindingTableModel cloudFindingTableModel;
    private final JTable cloudApiTable;
    private final CloudApiTableModel cloudApiTableModel;
    private final JTable cloudAssetTable;
    private final CloudAssetTableModel cloudAssetTableModel;
    private final JTable cloudParamTable;
    private final CloudParamTableModel cloudParamTableModel;
    private final JTable cloudSecretTable;
    private final CloudSecretTableModel cloudSecretTableModel;
    private final JTable findingDetailTable;
    private final CloudFindingTableModel findingDetailTableModel;
    private final JTable analyzedScriptTable;
    private final AnalyzedScriptTableModel analyzedScriptTableModel;
    private final JTable jsTaskTable;
    private final JsTaskTableModel jsTaskTableModel;
    private final JTextArea authSignalArea;
    private final JTextArea discoveryDetailArea;
    private final BurpMessageViewer.RequestView requestViewer;
    private final BurpMessageViewer.ResponseView responseViewer;
    private final MontoyaApi api;
    private final JTabbedPane resultTabs;

    private HistoryEntry currentEntry;
    private String displayedEntryId;
    private String displayedFindingDetailKey;
    private boolean refreshing;

    public StaticScanPanel(MontoyaApi api, IHistoryService historyService) {
        this.api = api;
        this.historyService = historyService;
        setLayout(new BorderLayout());

        tableModel = new StaticScanTableModel(api);
        table = new JTable(tableModel);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        UiUtil.applyBurpFont(table);
        UiUtil.setScaledColumnWidths(table, 85, 420, 130, 560);
        UiUtil.installHistoryDeleteMenu(table, historyService, this::selectedEntry, this::refresh);

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

        findingArea = createWrappedTextArea();
        cloudFindingTableModel = new CloudFindingTableModel();
        cloudFindingTable = createDataTable(cloudFindingTableModel, 110, 110, 240, 80, 75, 85, 220, 520);
        cloudApiTableModel = new CloudApiTableModel();
        cloudApiTable = createDataTable(cloudApiTableModel, 80, 65, 320, 240, 180, 65, 75, 110, 150, 220, 260);
        cloudApiTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !refreshing) {
                updateCloudApiDetail(false);
            }
        });
        cloudAssetTableModel = new CloudAssetTableModel();
        cloudAssetTable = createDataTable(cloudAssetTableModel, 80, 70, 330, 260, 130, 120, 220);
        cloudAssetTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !refreshing) {
                updateGenericDetailSafely("asset", this::buildSelectedAssetDetail, false);
            }
        });
        cloudParamTableModel = new CloudParamTableModel();
        cloudParamTable = createDataTable(cloudParamTableModel, 130, 80, 240, 120, 240);
        cloudParamTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !refreshing) {
                updateGenericDetailSafely("param", this::buildSelectedParamDetail, false);
            }
        });
        cloudSecretTableModel = new CloudSecretTableModel();
        cloudSecretTable = createDataTable(cloudSecretTableModel, 80, 120, 260, 75, 80, 100, 220, 520);
        cloudSecretTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !refreshing) {
                updateGenericDetailSafely("secret", this::buildSelectedSecretDetail, false);
            }
        });
        findingDetailTableModel = new CloudFindingTableModel();
        findingDetailTable = createDataTable(findingDetailTableModel, 110, 280, 85, 75, 95, 240, 560);
        findingDetailTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !refreshing) {
                displayedFindingDetailKey = selectedFindingDetailKey();
                updateGenericDetailSafely("findingDetail",
                        () -> buildSelectedFindingDetail(findingDetailTable, findingDetailTableModel), false);
            }
        });
        analyzedScriptTableModel = new AnalyzedScriptTableModel();
        analyzedScriptTable = createDataTable(analyzedScriptTableModel, 360, 80, 70, 65, 65, 65, 80, 440);
        analyzedScriptTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !refreshing) {
                updateGenericDetailSafely("analyzedScript", this::buildSelectedAnalyzedScriptDetail, false);
            }
        });
        jsTaskTableModel = new JsTaskTableModel();
        jsTaskTable = createDataTable(jsTaskTableModel, 90, 90, 230, 280, 520);
        jsTaskTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !refreshing) {
                updateGenericDetailSafely("task", this::buildSelectedTaskDetail, false);
            }
        });
        authSignalArea = createWrappedTextArea();
        discoveryDetailArea = createWrappedTextArea();
        requestViewer = new BurpMessageViewer.RequestView(api);
        responseViewer = new BurpMessageViewer.ResponseView(api);

        resultTabs = new JTabbedPane();
        UiUtil.applyBurpFont(resultTabs);
        resultTabs.addTab("Endpoints", createEndpointGroupPanel());
        resultTabs.addTab("secret", createSecretGroupPanel());
        resultTabs.addTab("finding", createFindingGroupPanel());

        JSplitPane findingSplit = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                resultTabs,
                titledScroll("选中项详情", discoveryDetailArea));
        findingSplit.setResizeWeight(0.72);
        findingSplit.setDividerLocation(430);

        JPanel findingPanel = new JPanel(new BorderLayout());
        findingPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        findingPanel.add(findingSplit, BorderLayout.CENTER);

        detailTabs = new JTabbedPane();
        UiUtil.applyBurpFont(detailTabs);
        detailTabs.addTab("扫描发现", findingPanel);
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
        int selectedResultTab = resultTabs.getSelectedIndex();
        SwingUtilities.invokeLater(() -> {
            refreshing = true;
            try {
                List<HistoryEntry> staticResources = historyService.searchAdvanced(
                                null, null, EndpointType.STATIC_RESOURCE, null, null, null, null, 0, 200).stream()
                        .filter(Objects::nonNull)
                        .filter(entry -> entry.getAiSummary() != null
                                && !entry.getAiSummary().startsWith("静态文件扫描已跳过"))
                        .toList();
                tableModel.setEntries(staticResources);
                restoreSelection(staticResources, preserveId);
                if (selectedTab >= 0 && selectedTab < detailTabs.getTabCount()) {
                    detailTabs.setSelectedIndex(selectedTab);
                }
                if (selectedResultTab >= 0 && selectedResultTab < resultTabs.getTabCount()) {
                    resultTabs.setSelectedIndex(selectedResultTab);
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

    private void restoreSelection(List<HistoryEntry> entries, String preserveId) {
        if (preserveId == null) {
            return;
        }
        for (int i = 0; i < entries.size(); i++) {
            HistoryEntry entry = entries.get(i);
            if (entry != null && preserveId.equals(entry.getRequestId())) {
                table.setRowSelectionInterval(i, i);
                return;
            }
        }
    }

    private HistoryEntry selectedEntry() {
        int row = table.getSelectedRow();
        if (row < 0) {
            return null;
        }
        return tableModel.getEntryAt(table.convertRowIndexToModel(row));
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
        StaticScanResult details = entry.getStaticScanDetails();
        String selectedApiKey = selectedCloudApiKey();
        String selectedAssetKey = selectedAssetKey();
        String selectedParamKey = selectedParamKey();
        String selectedSecretKey = selectedSecretKey();
        String selectedFindingDetailKey = sameEntry
                ? firstNonBlank(selectedFindingDetailKey(), displayedFindingDetailKey)
                : null;
        String selectedScriptKey = selectedScriptKey();
        String selectedTaskKey = selectedTaskKey();
        boolean previousRefreshing = refreshing;
        refreshing = true;
        try {
            UiUtil.setTextPreservingView(
                    findingArea,
                    buildSummaryText(entry, details),
                    sameEntry);
            cloudFindingTableModel.setFindings(details != null ? details.getCloudFindings() : List.of());
            cloudApiTableModel.setApis(
                    details != null ? details.getCloudApis() : List.of(),
                    details != null ? details.getRecoveredEndpoints() : List.of());
            restoreCloudApiSelection(sameEntry ? selectedApiKey : null);
            cloudAssetTableModel.setAssets(details != null ? details.getCloudAssets() : List.of());
            restoreAssetSelection(sameEntry ? selectedAssetKey : null);
            cloudParamTableModel.setParams(details != null ? details.getCloudParams() : List.of());
            restoreParamSelection(sameEntry ? selectedParamKey : null);
            cloudSecretTableModel.setSecrets(details != null ? details.getCloudSecrets() : List.of());
            restoreSecretSelection(sameEntry ? selectedSecretKey : null);
            findingDetailTableModel.setFindings(allCloudFindings(details));
            boolean restoredFindingDetail = restoreFindingDetailSelection(sameEntry ? selectedFindingDetailKey : null);
            displayedFindingDetailKey = restoredFindingDetail ? selectedFindingDetailKey() : null;
            if (restoredFindingDetail) {
                updateGenericDetailSafely("findingDetail",
                        () -> buildSelectedFindingDetail(findingDetailTable, findingDetailTableModel), true);
            }
            analyzedScriptTableModel.setScripts(details != null ? details.getAnalyzedScripts() : List.of());
            restoreScriptSelection(sameEntry ? selectedScriptKey : null);
            jsTaskTableModel.setTasks(details != null ? details.getJsAstTasks() : List.of());
            restoreTaskSelection(sameEntry ? selectedTaskKey : null);
            UiUtil.setTextPreservingView(authSignalArea, buildAuthSignalText(details), sameEntry);
        } finally {
            refreshing = previousRefreshing;
        }
        if (!sameEntry && discoveryDetailArea.getText().isBlank()) {
            updateGenericDetail("请选择上方表格中的一条记录查看详情。", false);
        }
        requestViewer.setBytes(entry.getRawRequest());
        responseViewer.setBytes(entry.getRawResponse());
        displayedEntryId = currentId;
    }

    private void clearDetail() {
        currentEntry = null;
        displayedEntryId = null;
        displayedFindingDetailKey = null;
        findingArea.setText("");
        cloudFindingTableModel.setFindings(List.of());
        cloudApiTableModel.setApis(List.of(), List.of());
        cloudAssetTableModel.setAssets(List.of());
        cloudParamTableModel.setParams(List.of());
        cloudSecretTableModel.setSecrets(List.of());
        findingDetailTableModel.setFindings(List.of());
        analyzedScriptTableModel.setScripts(List.of());
        jsTaskTableModel.setTasks(List.of());
        authSignalArea.setText("");
        discoveryDetailArea.setText("");
        requestViewer.setBytes(null);
        responseViewer.setBytes(null);
    }

    private JTable createDataTable(AbstractTableModel model, int... widths) {
        JTable dataTable = new JTable(model);
        dataTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        dataTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        UiUtil.applyBurpFont(dataTable);
        UiUtil.setScaledColumnWidths(dataTable, widths);
        return dataTable;
    }

    private JPanel titledScroll(String title, Component component) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(null, title,
                TitledBorder.LEFT, TitledBorder.TOP, UiUtil.burpTableFont().deriveFont(Font.BOLD)));
        panel.add(new JScrollPane(component), BorderLayout.CENTER);
        return panel;
    }

    private JPanel createEndpointGroupPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(titledScroll("API / Endpoint 候选（验证结果见表格，参数和认证信号点开后在详情区查看）", cloudApiTable), BorderLayout.CENTER);
        return panel;
    }

    private void restoreCloudApiSelection(String selectedApiKey) {
        if (cloudApiTableModel.getRowCount() == 0) {
            cloudApiTable.clearSelection();
            return;
        }
        if (selectedApiKey == null) {
            cloudApiTable.clearSelection();
            return;
        }
        int row = selectedApiKey != null ? cloudApiTableModel.indexOfKey(selectedApiKey) : -1;
        if (row < 0) {
            cloudApiTable.clearSelection();
            return;
        }
        cloudApiTable.setRowSelectionInterval(row, row);
    }

    private String selectedCloudApiKey() {
        int row = cloudApiTable.getSelectedRow();
        if (row < 0) {
            return null;
        }
        return cloudApiTableModel.selectedKey(cloudApiTable.convertRowIndexToModel(row));
    }

    private String selectedAssetKey() {
        return selectedModelKey(cloudAssetTable, row -> cloudAssetTableModel.keyAt(row));
    }

    private void restoreAssetSelection(String key) {
        restoreModelKeySelection(cloudAssetTable, key, searchKey -> cloudAssetTableModel.indexOfKey(searchKey));
    }

    private String selectedParamKey() {
        return selectedModelKey(cloudParamTable, row -> cloudParamTableModel.keyAt(row));
    }

    private void restoreParamSelection(String key) {
        restoreModelKeySelection(cloudParamTable, key, searchKey -> cloudParamTableModel.indexOfKey(searchKey));
    }

    private String selectedSecretKey() {
        return selectedModelKey(cloudSecretTable, row -> cloudSecretTableModel.keyAt(row));
    }

    private void restoreSecretSelection(String key) {
        restoreModelKeySelection(cloudSecretTable, key, searchKey -> cloudSecretTableModel.indexOfKey(searchKey));
    }

    private String selectedFindingDetailKey() {
        return selectedModelKey(findingDetailTable, row -> findingDetailTableModel.keyAt(row));
    }

    private boolean restoreFindingDetailSelection(String key) {
        return restoreModelKeySelection(findingDetailTable, key, searchKey -> findingDetailTableModel.indexOfKey(searchKey));
    }

    private String selectedScriptKey() {
        return selectedModelKey(analyzedScriptTable, row -> analyzedScriptTableModel.keyAt(row));
    }

    private void restoreScriptSelection(String key) {
        restoreModelKeySelection(analyzedScriptTable, key, searchKey -> analyzedScriptTableModel.indexOfKey(searchKey));
    }

    private String selectedTaskKey() {
        return selectedModelKey(jsTaskTable, row -> jsTaskTableModel.keyAt(row));
    }

    private void restoreTaskSelection(String key) {
        restoreModelKeySelection(jsTaskTable, key, searchKey -> jsTaskTableModel.indexOfKey(searchKey));
    }

    private String selectedModelKey(JTable sourceTable, java.util.function.IntFunction<String> keyFunction) {
        int row = sourceTable != null ? sourceTable.getSelectedRow() : -1;
        if (row < 0 || keyFunction == null) {
            return null;
        }
        return keyFunction.apply(sourceTable.convertRowIndexToModel(row));
    }

    private boolean restoreModelKeySelection(JTable sourceTable,
                                             String key,
                                             java.util.function.Function<String, Integer> indexFunction) {
        if (sourceTable == null || key == null || key.isBlank() || indexFunction == null) {
            return false;
        }
        int modelRow = indexFunction.apply(key);
        if (modelRow < 0) {
            return false;
        }
        int viewRow = sourceTable.convertRowIndexToView(modelRow);
        if (viewRow >= 0) {
            sourceTable.setRowSelectionInterval(viewRow, viewRow);
            sourceTable.scrollRectToVisible(sourceTable.getCellRect(viewRow, 0, true));
            return true;
        }
        return false;
    }

    private void updateCloudApiDetail(boolean preserveView) {
        updateGenericDetailSafely("api", () -> {
            int row = cloudApiTable.getSelectedRow();
            if (row < 0) {
                return "请选择上方接口候选，查看验证状态与详细结果。";
            }
            int modelRow = cloudApiTable.convertRowIndexToModel(row);
            StaticScanResult.CloudApi api = cloudApiTableModel.getApiAt(modelRow);
            StaticScanResult.RecoveredEndpoint recovered = cloudApiTableModel.getRecoveredAt(modelRow);
            return buildCloudApiDetail(api, recovered);
        }, preserveView);
    }

    private JPanel createSecretGroupPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(titledScroll("Sensitive / Secret（云端已完成 LLM 复核）", cloudSecretTable), BorderLayout.CENTER);
        return panel;
    }

    private JPanel createFindingGroupPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(titledScroll("Finding 详情", findingDetailTable), BorderLayout.CENTER);
        return panel;
    }

    private JPanel createParamAuthPanel() {
        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                titledScroll("参数", cloudParamTable),
                titledScroll("认证信号", authSignalArea));
        split.setResizeWeight(0.72);
        split.setDividerLocation(330);
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    private String buildAuthSignalText(StaticScanResult details) {
        if (details == null || details.getCloudAuthSignals() == null || details.getCloudAuthSignals().isEmpty()) {
            return "";
        }
        return details.getCloudAuthSignals().stream()
                .filter(signal -> signal != null && !signal.isBlank())
                .toList()
                .stream()
                .reduce((left, right) -> left + "\n" + right)
                .orElse("");
    }

    private String buildSummaryText(HistoryEntry entry, StaticScanResult details) {
        String summary = entry != null ? entry.getAiSummary() : null;
        boolean structured = hasStructuredStaticDetails(details);
        StringBuilder text = new StringBuilder();
        if (details == null) {
            text.append(summary != null ? summary : "未扫描或无发现");
            text.append("\n\n[UI] 未读取到结构化静态扫描详情，分组 Tab 将为空。请重新扫描该 JS。");
            return text.toString();
        }
        if (isFailureSummary(summary) && structured) {
            text.append("静态分析已完成，结构化结果已返回。旧的失败摘要已忽略，具体异常请看 Burp Error / 系统日志。");
        } else {
            text.append(summary != null ? summary : "未扫描或无发现");
        }
        if (details == null) {
            text.append("\n\n[UI] 未读取到结构化静态扫描详情，分组 Tab 将为空。请重新扫描该 JS。");
            return text.toString();
        }
        text.append("\n\n[UI] Compact 展示分组")
                .append("\n- Endpoints: ").append(endpointGroupCount(details))
                .append("（apis=").append(apiCount(details))
                .append(", verified=").append(validRecoveredEndpointCount(details)).append("）")
                .append("\n- Secret: ").append(secretCount(details))
                .append("（exposureFindings=").append(exposureGroupCount(details)).append("）")
                .append("\n- Finding: ").append(totalFindingCount(details))
                .append("（scriptFindings=").append(scriptGroupCount(details))
                .append(", assets=").append(assetCount(details)).append("）")
                .append("\n- Params/Auth: params=").append(paramCount(details))
                .append(", auth=").append(authCount(details));
        StaticScanResult.CloudSummary cloudSummary = details.getCloudSummary();
        if (cloudSummary != null) {
            text.append("\n- LLM: enabled=").append(cloudSummary.isLlmEnabled())
                    .append(", secrets reviewed/confirmed/rejected=")
                    .append(cloudSummary.getLlmReviewedCount()).append("/")
                    .append(cloudSummary.getLlmConfirmedCount()).append("/")
                    .append(cloudSummary.getLlmRejectedCount())
                    .append(", findings reviewed/confirmed/rejected=")
                    .append(cloudSummary.getLlmFindingReviewedCount()).append("/")
                    .append(cloudSummary.getLlmFindingConfirmedCount()).append("/")
                    .append(cloudSummary.getLlmFindingRejectedCount());
        }
        StaticScanResult.JsAstTaskStatus latest = latestTask(details);
        if (latest != null) {
            text.append("\n[UI] JS AST 进度: [").append(oneLine(latest.getPhase()))
                    .append("] ").append(oneLine(latest.getStatus()))
                    .append(" | ").append(oneLine(latest.getMessage()));
        }
        return text.toString();
    }

    private boolean hasStructuredStaticDetails(StaticScanResult details) {
        return details != null && (notEmpty(details.getCloudApis())
                || notEmpty(details.getCloudAssets())
                || notEmpty(details.getCloudParams())
                || notEmpty(details.getCloudAuthSignals())
                || notEmpty(details.getCloudSecrets())
                || notEmpty(details.getCloudRisks())
                || notEmpty(details.getCloudFindings())
                || notEmpty(details.getEndpointFindings())
                || notEmpty(details.getExposureFindings())
                || notEmpty(details.getScriptFindings())
                || notEmpty(details.getAnalyzedScripts())
                || notEmpty(details.getRecoveredEndpoints())
                || details.getCloudSummary() != null);
    }

    private boolean isFailureSummary(String summary) {
        return summary != null && summary.startsWith("静态分析失败");
    }

    private boolean notEmpty(List<?> values) {
        return values != null && values.stream().anyMatch(Objects::nonNull);
    }

    private List<StaticScanResult.CloudFinding> allCloudFindings(StaticScanResult details) {
        if (details == null) {
            return List.of();
        }
        Map<String, StaticScanResult.CloudFinding> findings = new LinkedHashMap<>();
        addFindings(findings, details.getEndpointFindings());
        addFindings(findings, details.getExposureFindings());
        addFindings(findings, details.getScriptFindings());
        addFindings(findings, details.getCloudFindings());
        addSecretFindings(findings, details.getCloudSecrets());
        addRiskFindings(findings, details.getCloudRisks());
        addAssetFindings(findings, details.getCloudAssets());
        return List.copyOf(findings.values());
    }

    private void addFindings(Map<String, StaticScanResult.CloudFinding> target,
                             List<StaticScanResult.CloudFinding> source) {
        if (target == null || source == null) {
            return;
        }
        for (StaticScanResult.CloudFinding finding : source) {
            addFinding(target, finding);
        }
    }

    private void addSecretFindings(Map<String, StaticScanResult.CloudFinding> target,
                                   List<StaticScanResult.CloudSecret> secrets) {
        if (target == null || secrets == null) {
            return;
        }
        for (StaticScanResult.CloudSecret secret : secrets) {
            if (secret == null) {
                continue;
            }
            StaticScanResult.CloudFinding finding = new StaticScanResult.CloudFinding();
            finding.setType(secret.getType());
            finding.setValue(secret.getValue());
            finding.setSeverity(secret.getSeverity());
            finding.setConfidence(secret.getConfidence());
            finding.setSource(secret.getSource());
            finding.setSourceScriptUrl(secret.getSourceScriptUrl());
            finding.setEvidence(secret.getEvidence());
            addFinding(target, finding);
        }
    }

    private void addRiskFindings(Map<String, StaticScanResult.CloudFinding> target,
                                 List<StaticScanResult.CloudRisk> risks) {
        if (target == null || risks == null) {
            return;
        }
        for (StaticScanResult.CloudRisk risk : risks) {
            if (risk == null) {
                continue;
            }
            StaticScanResult.CloudFinding finding = new StaticScanResult.CloudFinding();
            finding.setType(risk.getType());
            finding.setValue(risk.getType());
            finding.setSeverity(risk.getSeverity());
            finding.setSource("risk");
            finding.setSourceScriptUrl(risk.getSourceScriptUrl());
            finding.setEvidence(risk.getEvidence());
            addFinding(target, finding);
        }
    }

    private void addAssetFindings(Map<String, StaticScanResult.CloudFinding> target,
                                  List<StaticScanResult.CloudAsset> assets) {
        if (target == null || assets == null) {
            return;
        }
        for (StaticScanResult.CloudAsset asset : assets) {
            if (asset == null) {
                continue;
            }
            StaticScanResult.CloudFinding finding = new StaticScanResult.CloudFinding();
            finding.setType(!isBlank(asset.getType()) ? asset.getType() : "script");
            finding.setValue(!isBlank(asset.getResolvedUrl()) ? asset.getResolvedUrl() : asset.getUrl());
            finding.setSeverity("INFO");
            finding.setSource(!isBlank(asset.getSource()) ? asset.getSource() : "asset");
            finding.setSourceScriptUrl(asset.getSourceScriptUrl());
            finding.setEvidence("raw=" + safe(asset.getUrl()) + "\nresolved=" + safe(asset.getResolvedUrl())
                    + "\nchunk=" + safe(asset.getChunkName()));
            addFinding(target, finding);
        }
    }

    private void addFinding(Map<String, StaticScanResult.CloudFinding> target,
                            StaticScanResult.CloudFinding finding) {
        if (target == null || finding == null) {
            return;
        }
        target.putIfAbsent(findingKey(finding), finding);
    }

    private String findingKey(StaticScanResult.CloudFinding finding) {
        return safe(finding.getType()) + "\u0000"
                + safe(finding.getValue()) + "\u0000"
                + safe(finding.getSource()) + "\u0000"
                + safe(finding.getSourceScriptUrl()) + "\u0000"
                + safe(finding.getEvidence());
    }

    private int size(List<?> values) {
        return values != null ? values.size() : 0;
    }

    private int totalFindingCount(StaticScanResult details) {
        if (details == null) {
            return 0;
        }
        if (details.getCloudSummary() != null && details.getCloudSummary().getFindingCount() > 0) {
            return details.getCloudSummary().getFindingCount();
        }
        int grouped = size(details.getEndpointFindings())
                + size(details.getExposureFindings())
                + size(details.getScriptFindings());
        if (grouped > 0) {
            return grouped;
        }
        return size(details.getCloudFindings()) + size(details.getCloudSecrets()) + size(details.getCloudRisks());
    }

    private int endpointGroupCount(StaticScanResult details) {
        return details != null && details.getCloudSummary() != null && details.getCloudSummary().getEndpointCount() > 0
                ? details.getCloudSummary().getEndpointCount()
                : size(details != null ? details.getCloudApis() : null) + size(details != null ? details.getEndpointFindings() : null);
    }

    private int exposureGroupCount(StaticScanResult details) {
        return details != null && details.getCloudSummary() != null && details.getCloudSummary().getExposureCount() > 0
                ? details.getCloudSummary().getExposureCount()
                : size(details != null ? details.getCloudSecrets() : null) + size(details != null ? details.getExposureFindings() : null);
    }

    private int scriptGroupCount(StaticScanResult details) {
        return details != null && details.getCloudSummary() != null && details.getCloudSummary().getScriptCount() > 0
                ? details.getCloudSummary().getScriptCount()
                : size(details != null ? details.getCloudAssets() : null) + size(details != null ? details.getScriptFindings() : null);
    }

    private int apiCount(StaticScanResult details) {
        return details != null && details.getCloudSummary() != null && details.getCloudSummary().getApiCount() > 0
                ? details.getCloudSummary().getApiCount()
                : size(details != null ? details.getCloudApis() : null);
    }

    private int assetCount(StaticScanResult details) {
        return details != null && details.getCloudSummary() != null && details.getCloudSummary().getAssetCount() > 0
                ? details.getCloudSummary().getAssetCount()
                : size(details != null ? details.getCloudAssets() : null);
    }

    private int paramCount(StaticScanResult details) {
        return details != null && details.getCloudSummary() != null && details.getCloudSummary().getParamCount() > 0
                ? details.getCloudSummary().getParamCount()
                : size(details != null ? details.getCloudParams() : null);
    }

    private int authCount(StaticScanResult details) {
        return details != null && details.getCloudSummary() != null && details.getCloudSummary().getAuthCount() > 0
                ? details.getCloudSummary().getAuthCount()
                : size(details != null ? details.getCloudAuthSignals() : null);
    }

    private int secretCount(StaticScanResult details) {
        return details != null && details.getCloudSummary() != null && details.getCloudSummary().getSecretCount() > 0
                ? details.getCloudSummary().getSecretCount()
                : size(details != null ? details.getCloudSecrets() : null);
    }

    private int validRecoveredEndpointCount(StaticScanResult details) {
        if (details == null || details.getRecoveredEndpoints() == null) {
            return 0;
        }
        return (int) details.getRecoveredEndpoints().stream()
                .filter(endpoint -> endpoint != null && endpoint.isValidated())
                .count();
    }

    private StaticScanResult.JsAstTaskStatus latestTask(StaticScanResult details) {
        if (details == null || details.getJsAstTasks() == null || details.getJsAstTasks().isEmpty()) {
            return null;
        }
        for (int i = details.getJsAstTasks().size() - 1; i >= 0; i--) {
            StaticScanResult.JsAstTaskStatus task = details.getJsAstTasks().get(i);
            if (task != null) {
                return task;
            }
        }
        return null;
    }

    private void updateGenericDetail(String text, boolean preserveView) {
        UiUtil.setTextPreservingView(discoveryDetailArea, text, preserveView);
    }

    private void updateGenericDetailSafely(String source, Supplier<String> detailSupplier, boolean preserveView) {
        try {
            updateGenericDetail(detailSupplier != null ? detailSupplier.get() : "", preserveView);
        } catch (Exception e) {
            logUiError("detail-" + source, e);
            updateGenericDetail("详情渲染失败: " + e.getClass().getSimpleName()
                    + (e.getMessage() != null && !e.getMessage().isBlank() ? ": " + e.getMessage() : "")
                    + "\n具体原因已写入 Burp Error 和系统日志。", preserveView);
        }
    }

    private void logUiError(String phase, Exception e) {
        String message = "AI Burp Copilot: 静态文件分析 UI 刷新失败"
                + " phase=" + phase
                + ", requestId=" + safe(currentEntry != null ? currentEntry.getRequestId() : null)
                + ", url=" + safe(currentEntry != null ? currentEntry.getUrl() : null)
                + ", error=" + e.getClass().getSimpleName()
                + (e.getMessage() != null && !e.getMessage().isBlank() ? ": " + e.getMessage() : "")
                + firstStackLocation(e);
        if (api != null) {
            try {
                api.logging().logToError(message);
            } catch (Exception ignored) {
                System.err.println(message);
            }
        } else {
            System.err.println(message);
        }
        PluginLogger.getInstance().error(PluginLogger.Category.SYSTEM, "StaticScanUI", message);
    }

    private static String firstStackLocation(Exception e) {
        if (e == null || e.getStackTrace() == null || e.getStackTrace().length == 0) {
            return "";
        }
        StackTraceElement first = e.getStackTrace()[0];
        return " @ " + first.getClassName() + ":" + first.getLineNumber();
    }

    private String buildSelectedFindingDetail(JTable sourceTable, CloudFindingTableModel model) {
        int row = sourceTable != null ? sourceTable.getSelectedRow() : -1;
        if (row < 0 || model == null) {
            return "请选择一条 finding 查看证据。";
        }
        StaticScanResult.CloudFinding finding = model.getFindingAt(sourceTable.convertRowIndexToModel(row));
        if (finding == null) {
            return "当前 finding 为空。";
        }
        return buildFindingDetail(finding);
    }

    private String buildSelectedAssetDetail() {
        int row = cloudAssetTable.getSelectedRow();
        if (row < 0) {
            return "请选择一个脚本资源查看详情。";
        }
        StaticScanResult.CloudAsset asset = cloudAssetTableModel.getAssetAt(cloudAssetTable.convertRowIndexToModel(row));
        if (asset == null) {
            return "当前脚本资源为空。";
        }
        StringBuilder text = new StringBuilder("脚本资源\n");
        appendLine(text, "类型", asset.getType());
        appendLine(text, "原始 URL", asset.getUrl());
        appendLine(text, "解析 URL", asset.getResolvedUrl());
        appendLine(text, "Chunk", asset.getChunkName());
        appendLine(text, "来源", asset.getSource());
        appendLine(text, "来源脚本", asset.getSourceScriptUrl());
        appendLine(text, "说明", "是否探测、是否继续分析受配置项控制；不存在的 .js.map 不在这里展示。");
        return text.toString();
    }

    private String buildSelectedParamDetail() {
        int row = cloudParamTable.getSelectedRow();
        if (row < 0) {
            return "请选择一个参数查看详情。";
        }
        StaticScanResult.CloudParam param = cloudParamTableModel.getParamAt(cloudParamTable.convertRowIndexToModel(row));
        if (param == null) {
            return "当前参数为空。";
        }
        StringBuilder text = new StringBuilder("参数\n");
        appendLine(text, "名称", param.getName());
        appendLine(text, "位置", param.getLocation());
        appendLine(text, "API", param.getApi());
        appendLine(text, "来源", param.getSource());
        appendLine(text, "来源脚本", param.getSourceScriptUrl());
        return text.toString();
    }

    private String buildSelectedSecretDetail() {
        int row = cloudSecretTable.getSelectedRow();
        if (row < 0) {
            return "请选择一条敏感信息查看详情。";
        }
        StaticScanResult.CloudSecret secret = cloudSecretTableModel.getSecretAt(cloudSecretTable.convertRowIndexToModel(row));
        if (secret == null) {
            return "当前敏感信息为空。";
        }
        StringBuilder text = new StringBuilder("敏感信息\n");
        appendLine(text, "级别", secret.getSeverity());
        appendLine(text, "类型", secret.getType());
        appendLine(text, "值", secret.getValue());
        appendLine(text, "置信度", formatConfidence(secret.getConfidence()));
        appendLine(text, "来源", secret.getSource());
        appendLine(text, "来源脚本", secret.getSourceScriptUrl());
        text.append("\n证据\n").append(safe(secret.getEvidence()));
        return text.toString();
    }

    private String buildSelectedAnalyzedScriptDetail() {
        int row = analyzedScriptTable.getSelectedRow();
        if (row < 0) {
            return "请选择一个已分析脚本查看详情。";
        }
        StaticScanResult.AnalyzedScript script = analyzedScriptTableModel.getScriptAt(analyzedScriptTable.convertRowIndexToModel(row));
        if (script == null) {
            return "当前脚本记录为空。";
        }
        StringBuilder text = new StringBuilder("已分析脚本\n");
        appendLine(text, "URL", script.getUrl());
        appendLine(text, "验证", script.isValidated() ? "存在" : "未验证/不存在");
        appendLine(text, "状态码", script.getStatusCode() > 0 ? script.getStatusCode() : "-");
        appendLine(text, "API 数", script.getApiCount());
        appendLine(text, "Secret 数", script.getSecretCount());
        appendLine(text, "Risk 数", script.getRiskCount());
        appendLine(text, "Finding 数", script.getFindingCount());
        appendLine(text, "说明", script.getReason());
        return text.toString();
    }

    private String buildSelectedTaskDetail() {
        int row = jsTaskTable.getSelectedRow();
        if (row < 0) {
            return "请选择一个 JS AST 任务查看详情。";
        }
        StaticScanResult.JsAstTaskStatus task = jsTaskTableModel.getTaskAt(jsTaskTable.convertRowIndexToModel(row));
        if (task == null) {
            return "当前任务记录为空。";
        }
        StringBuilder text = new StringBuilder("JS AST 任务\n");
        appendLine(text, "阶段", task.getPhase());
        appendLine(text, "状态", task.getStatus());
        appendLine(text, "任务 ID", task.getTaskId());
        appendLine(text, "脚本", task.getScriptUrl());
        appendLine(text, "消息", task.getMessage());
        return text.toString();
    }

    private static String buildFindingDetail(StaticScanResult.CloudFinding finding) {
        StringBuilder text = new StringBuilder("Finding\n");
        appendLine(text, "类型", finding.getType());
        appendLine(text, "值", finding.getValue());
        appendLine(text, "级别", finding.getSeverity());
        appendLine(text, "置信度", formatConfidence(finding.getConfidence()));
        appendLine(text, "来源", finding.getSource());
        appendLine(text, "来源脚本", finding.getSourceScriptUrl());
        text.append("\n证据\n").append(safe(finding.getEvidence()));
        return text.toString();
    }

    private static class StaticScanTableModel extends AbstractTableModel {
        private final String[] columns = {"时间", "URL", "状态", "摘要"};
        private final MontoyaApi api;
        private List<HistoryEntry> entries = List.of();

        private StaticScanTableModel(MontoyaApi api) {
            this.api = api;
        }

        void setEntries(List<HistoryEntry> entries) {
            this.entries = nonNullList(entries);
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
            HistoryEntry entry = getEntryAt(row);
            if (entry == null || col < 0 || col >= columns.length) {
                return "";
            }
            try {
                return switch (col) {
                    case 0 -> DATE_FORMAT.format(new Date(entry.getTimestamp()));
                    case 1 -> safe(entry.getUrl());
                    case 2 -> latestStatus(entry);
                    case 3 -> findingSummary(entry);
                    default -> "";
                };
            } catch (Exception e) {
                logFindingColumnError(api, entry, "render", e);
                return col >= 2
                        ? "发现统计暂不可用: " + e.getClass().getSimpleName()
                        : "";
            }
        }

        private String latestStatus(HistoryEntry entry) {
            StaticScanResult details = entry != null ? entry.getStaticScanDetails() : null;
            StaticScanResult.JsAstTaskStatus latest = latestTask(details);
            if (latest == null) {
                return details != null ? "已记录" : "无结构化详情";
            }
            String status = safe(latest.getStatus());
            String phase = safe(latest.getPhase());
            if ("completed".equalsIgnoreCase(status) || "COMPLETED".equalsIgnoreCase(phase)) {
                return "完成";
            }
            if ("failed".equalsIgnoreCase(status) || "FAILED".equalsIgnoreCase(phase)) {
                return "失败";
            }
            if (phase.toUpperCase(java.util.Locale.ROOT).contains("POLL")) {
                return "轮询中";
            }
            if (phase.toUpperCase(java.util.Locale.ROOT).contains("SUBMIT")) {
                return "已提交";
            }
            return !status.isBlank() ? status : phase;
        }

        private String findingSummary(HistoryEntry entry) {
            try {
                if (entry == null || entry.getStaticScanDetails() == null) {
                    return extractFindingSummary(entry != null ? entry.getAiSummary() : null);
                }
                StaticScanResult details = entry.getStaticScanDetails();
                int total = summaryValue(details, "finding", groupedFindingCount(details));
                int endpoints = summaryValue(details, "endpoint",
                        safeSize(details.getCloudApis()) + safeSize(details.getEndpointFindings()));
                int exposures = summaryValue(details, "exposure",
                        safeSize(details.getCloudSecrets()) + safeSize(details.getExposureFindings()));
                int scripts = summaryValue(details, "script",
                        safeSize(details.getCloudAssets()) + safeSize(details.getScriptFindings()));
                int verifiedApis = validRecoveredEndpointCount(details);
                return "发现=" + total
                        + " | 接口=" + endpoints
                        + " | 已验证=" + verifiedApis
                        + " | 暴露=" + exposures
                        + " | 脚本=" + scripts;
            } catch (Exception e) {
                logFindingColumnError(api, entry, "summary", e);
                String fallback = extractFindingSummary(entry != null ? entry.getAiSummary() : null);
                if (fallback != null && !fallback.isBlank()) {
                    return fallback;
                }
                return "发现统计暂不可用: " + e.getClass().getSimpleName();
            }
        }

        private static String extractFindingSummary(String summary) {
            if (summary == null || summary.isBlank()) {
                return "";
            }
            for (String line : summary.split("\\R")) {
                if (line.startsWith("JS AST summary:") || line.startsWith("Cloud overview:")) {
                    return truncate(line, 100);
                }
            }
            return truncate(summary, 100);
        }

        private static int safeSize(List<?> values) {
            try {
                return values != null ? (int) values.stream().filter(Objects::nonNull).count() : 0;
            } catch (Exception e) {
                return 0;
            }
        }

        private static int groupedFindingCount(StaticScanResult details) {
            int grouped = safeSize(details.getEndpointFindings())
                    + safeSize(details.getExposureFindings())
                    + safeSize(details.getScriptFindings());
            if (grouped > 0) {
                return grouped;
            }
            return safeSize(details.getCloudFindings()) + safeSize(details.getCloudSecrets()) + safeSize(details.getCloudRisks());
        }

        private static int summaryValue(StaticScanResult details, String key, int fallback) {
            StaticScanResult.CloudSummary summary = details != null ? details.getCloudSummary() : null;
            if (summary == null) {
                return fallback;
            }
            int value = switch (key) {
                case "finding" -> summary.getFindingCount();
                case "endpoint" -> summary.getEndpointCount();
                case "exposure" -> summary.getExposureCount();
                case "script" -> summary.getScriptCount();
                default -> 0;
            };
            return value > 0 ? value : fallback;
        }

        private static int validRecoveredEndpointCount(StaticScanResult details) {
            if (details == null || details.getRecoveredEndpoints() == null) {
                return 0;
            }
            try {
                return (int) details.getRecoveredEndpoints().stream()
                        .filter(endpoint -> endpoint != null && endpoint.isValidated())
                        .count();
            } catch (Exception e) {
                return 0;
            }
        }

        private static StaticScanResult.JsAstTaskStatus latestTask(StaticScanResult details) {
            if (details == null || details.getJsAstTasks() == null || details.getJsAstTasks().isEmpty()) {
                return null;
            }
            for (int i = details.getJsAstTasks().size() - 1; i >= 0; i--) {
                StaticScanResult.JsAstTaskStatus task = details.getJsAstTasks().get(i);
                if (task != null) {
                    return task;
                }
            }
            return null;
        }

        private static String truncate(String value, int maxLen) {
            if (value == null) {
                return "";
            }
            return value.length() > maxLen ? value.substring(0, maxLen - 3) + "..." : value;
        }

        private static void logFindingColumnError(MontoyaApi api, HistoryEntry entry, String phase, Exception e) {
            String message = "AI Burp Copilot: 静态文件分析发现列刷新失败"
                    + " phase=" + phase
                    + ", requestId=" + safe(entry != null ? entry.getRequestId() : null)
                    + ", url=" + safe(entry != null ? entry.getUrl() : null)
                    + ", error=" + e.getClass().getSimpleName()
                    + (e.getMessage() != null && !e.getMessage().isBlank() ? ": " + e.getMessage() : "")
                    + firstStackLocation(e);
            if (api != null) {
                try {
                    api.logging().logToError(message);
                } catch (Exception ignored) {
                    System.err.println(message);
                }
            } else {
                System.err.println(message);
            }
            PluginLogger.getInstance().error(PluginLogger.Category.SYSTEM, "StaticScanUI", message);
        }

        private static String firstStackLocation(Exception e) {
            if (e == null || e.getStackTrace() == null || e.getStackTrace().length == 0) {
                return "";
            }
            StackTraceElement first = e.getStackTrace()[0];
            return " @ " + first.getClassName() + ":" + first.getLineNumber();
        }
    }

    private static class CloudFindingTableModel extends AbstractTableModel {
        private final String[] columns = {"类型", "值", "级别", "置信度", "来源", "来源脚本", "证据"};
        private List<StaticScanResult.CloudFinding> findings = List.of();

        void setFindings(List<StaticScanResult.CloudFinding> findings) {
            List<StaticScanResult.CloudFinding> nextFindings = nonNullList(findings);
            if (sameKeys(this.findings, nextFindings)) {
                this.findings = nextFindings;
                if (!nextFindings.isEmpty()) {
                    fireTableRowsUpdated(0, nextFindings.size() - 1);
                }
                return;
            }
            this.findings = nextFindings;
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return findings.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }

        StaticScanResult.CloudFinding getFindingAt(int row) {
            return row >= 0 && row < findings.size() ? findings.get(row) : null;
        }

        String keyAt(int row) {
            return key(getFindingAt(row));
        }

        int indexOfKey(String key) {
            if (key == null) {
                return -1;
            }
            for (int i = 0; i < findings.size(); i++) {
                if (key.equals(key(findings.get(i)))) {
                    return i;
                }
            }
            return -1;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            StaticScanResult.CloudFinding finding = findings.get(rowIndex);
            if (finding == null) {
                return "";
            }
            return switch (columnIndex) {
                case 0 -> finding.getType();
                case 1 -> finding.getValue();
                case 2 -> finding.getSeverity();
                case 3 -> formatConfidence(finding.getConfidence());
                case 4 -> finding.getSource();
                case 5 -> finding.getSourceScriptUrl();
                case 6 -> oneLine(finding.getEvidence());
                default -> "";
            };
        }

        private static String key(StaticScanResult.CloudFinding finding) {
            if (finding == null) {
                return null;
            }
            return safe(finding.getType()) + "|" + safe(finding.getValue()) + "|" + safe(finding.getSource()) + "|"
                    + safe(finding.getSourceScriptUrl());
        }

        private static boolean sameKeys(List<StaticScanResult.CloudFinding> left,
                                        List<StaticScanResult.CloudFinding> right) {
            List<StaticScanResult.CloudFinding> safeLeft = nonNullList(left);
            List<StaticScanResult.CloudFinding> safeRight = nonNullList(right);
            if (safeLeft.size() != safeRight.size()) {
                return false;
            }
            for (int i = 0; i < safeLeft.size(); i++) {
                if (!Objects.equals(key(safeLeft.get(i)), key(safeRight.get(i)))) {
                    return false;
                }
            }
            return true;
        }
    }

    private static class CloudApiTableModel extends AbstractTableModel {
        private final String[] columns = {"验证", "方法", "解析 URL", "原始 URL", "Base URL", "状态码", "置信度", "来源", "参数", "来源脚本", "说明"};
        private List<StaticScanResult.CloudApi> apis = List.of();
        private List<StaticScanResult.RecoveredEndpoint> recoveredEndpoints = List.of();

        void setApis(List<StaticScanResult.CloudApi> apis, List<StaticScanResult.RecoveredEndpoint> recoveredEndpoints) {
            this.apis = nonNullList(apis);
            List<StaticScanResult.RecoveredEndpoint> source = nonNullList(recoveredEndpoints);
            List<StaticScanResult.RecoveredEndpoint> matched = new ArrayList<>(this.apis.size());
            for (StaticScanResult.CloudApi api : this.apis) {
                matched.add(findRecovered(api, source));
            }
            this.recoveredEndpoints = matched;
            fireTableDataChanged();
        }

        StaticScanResult.CloudApi getApiAt(int row) {
            return row >= 0 && row < apis.size() ? apis.get(row) : null;
        }

        StaticScanResult.RecoveredEndpoint getRecoveredAt(int row) {
            return row >= 0 && row < recoveredEndpoints.size() ? recoveredEndpoints.get(row) : null;
        }

        String selectedKey(int viewRow) {
            if (viewRow < 0) {
                return null;
            }
            return key(getApiAt(viewRow));
        }

        int indexOfKey(String key) {
            if (key == null) {
                return -1;
            }
            for (int i = 0; i < apis.size(); i++) {
                if (key.equals(key(apis.get(i)))) {
                    return i;
                }
            }
            return -1;
        }

        @Override public int getRowCount() { return apis.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            StaticScanResult.CloudApi api = apis.get(rowIndex);
            if (api == null) {
                return "";
            }
            StaticScanResult.RecoveredEndpoint recovered = getRecoveredAt(rowIndex);
            return switch (columnIndex) {
                case 0 -> validationStatus(recovered);
                case 1 -> api.getMethod();
                case 2 -> api.getResolvedUrl();
                case 3 -> api.getRawUrl();
                case 4 -> api.getBaseUrl();
                case 5 -> recovered != null && recovered.getStatusCode() > 0 ? recovered.getStatusCode() : "-";
                case 6 -> api.getConfidence();
                case 7 -> api.getSource();
                case 8 -> join(api.getParams());
                case 9 -> api.getSourceScriptUrl();
                case 10 -> recovered != null ? recovered.getReason() : join(api.getNotes());
                default -> "";
            };
        }

        private static StaticScanResult.RecoveredEndpoint findRecovered(StaticScanResult.CloudApi api,
                                                                        List<StaticScanResult.RecoveredEndpoint> endpoints) {
            if (api == null || endpoints == null || endpoints.isEmpty()) {
                return null;
            }
            for (StaticScanResult.RecoveredEndpoint endpoint : endpoints) {
                if (endpoint == null || !methodMatches(api.getMethod(), endpoint.getMethod())) {
                    continue;
                }
                if (!scriptMatches(api.getSourceScriptUrl(), endpoint.getSourceScriptUrl())) {
                    continue;
                }
                if (sameValue(api.getRawUrl(), endpoint.getRawUrl())
                        || sameUrl(api.getResolvedUrl(), endpoint.getUrl())
                        || sameUrl(api.getRawUrl(), endpoint.getUrl())) {
                    return endpoint;
                }
            }
            return null;
        }

        private static boolean methodMatches(String apiMethod, String endpointMethod) {
            return isBlank(apiMethod) || isBlank(endpointMethod) || apiMethod.trim().equalsIgnoreCase(endpointMethod.trim());
        }

        private static boolean scriptMatches(String apiScript, String endpointScript) {
            return isBlank(apiScript) || isBlank(endpointScript) || sameValue(apiScript, endpointScript);
        }

        private static boolean sameUrl(String left, String right) {
            if (sameValue(left, right)) {
                return true;
            }
            String normalizedLeft = normalizeUrl(left);
            String normalizedRight = normalizeUrl(right);
            return !normalizedLeft.isBlank() && normalizedLeft.equals(normalizedRight);
        }

        private static String normalizeUrl(String value) {
            if (value == null) {
                return "";
            }
            String normalized = value.trim();
            while (normalized.endsWith("/") && normalized.length() > "https://x/".length()) {
                normalized = normalized.substring(0, normalized.length() - 1);
            }
            return normalized;
        }

        private static boolean sameValue(String left, String right) {
            return left != null && right != null && left.trim().equals(right.trim());
        }

        private static String key(StaticScanResult.CloudApi api) {
            if (api == null) {
                return null;
            }
            return safe(api.getMethod()) + "|" + safe(api.getSourceScriptUrl()) + "|"
                    + safe(api.getRawUrl()) + "|" + safe(api.getResolvedUrl());
        }
    }

    private static class CloudAssetTableModel extends AbstractTableModel {
        private final String[] columns = {"验证", "类型", "解析 URL", "原始 URL", "Chunk", "来源", "来源脚本"};
        private List<StaticScanResult.CloudAsset> assets = List.of();

        void setAssets(List<StaticScanResult.CloudAsset> assets) {
            this.assets = nonNullList(assets);
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return assets.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }

        StaticScanResult.CloudAsset getAssetAt(int row) {
            return row >= 0 && row < assets.size() ? assets.get(row) : null;
        }

        String keyAt(int row) {
            return key(getAssetAt(row));
        }

        int indexOfKey(String key) {
            if (key == null) {
                return -1;
            }
            for (int i = 0; i < assets.size(); i++) {
                if (key.equals(key(assets.get(i)))) {
                    return i;
                }
            }
            return -1;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            StaticScanResult.CloudAsset asset = assets.get(rowIndex);
            if (asset == null) {
                return "";
            }
            return switch (columnIndex) {
                case 0 -> "-";
                case 1 -> asset.getType();
                case 2 -> asset.getResolvedUrl();
                case 3 -> asset.getUrl();
                case 4 -> asset.getChunkName();
                case 5 -> asset.getSource();
                case 6 -> asset.getSourceScriptUrl();
                default -> "";
            };
        }

        private static String key(StaticScanResult.CloudAsset asset) {
            if (asset == null) {
                return null;
            }
            return safe(asset.getType()) + "|" + safe(asset.getResolvedUrl()) + "|"
                    + safe(asset.getUrl()) + "|" + safe(asset.getSourceScriptUrl());
        }
    }

    private static class CloudParamTableModel extends AbstractTableModel {
        private final String[] columns = {"名称", "位置", "API", "来源", "来源脚本"};
        private List<StaticScanResult.CloudParam> params = List.of();

        void setParams(List<StaticScanResult.CloudParam> params) {
            this.params = nonNullList(params);
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return params.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }

        StaticScanResult.CloudParam getParamAt(int row) {
            return row >= 0 && row < params.size() ? params.get(row) : null;
        }

        String keyAt(int row) {
            return key(getParamAt(row));
        }

        int indexOfKey(String key) {
            if (key == null) {
                return -1;
            }
            for (int i = 0; i < params.size(); i++) {
                if (key.equals(key(params.get(i)))) {
                    return i;
                }
            }
            return -1;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            StaticScanResult.CloudParam param = params.get(rowIndex);
            if (param == null) {
                return "";
            }
            return switch (columnIndex) {
                case 0 -> param.getName();
                case 1 -> param.getLocation();
                case 2 -> param.getApi();
                case 3 -> param.getSource();
                case 4 -> param.getSourceScriptUrl();
                default -> "";
            };
        }

        private static String key(StaticScanResult.CloudParam param) {
            if (param == null) {
                return null;
            }
            return safe(param.getName()) + "|" + safe(param.getLocation()) + "|"
                    + safe(param.getApi()) + "|" + safe(param.getSourceScriptUrl());
        }
    }

    private static class CloudSecretTableModel extends AbstractTableModel {
        private final String[] columns = {"级别", "类型", "值", "置信度", "来源", "来源脚本", "证据"};
        private List<StaticScanResult.CloudSecret> secrets = List.of();

        void setSecrets(List<StaticScanResult.CloudSecret> secrets) {
            this.secrets = nonNullList(secrets);
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return secrets.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }

        StaticScanResult.CloudSecret getSecretAt(int row) {
            return row >= 0 && row < secrets.size() ? secrets.get(row) : null;
        }

        String keyAt(int row) {
            return key(getSecretAt(row));
        }

        int indexOfKey(String key) {
            if (key == null) {
                return -1;
            }
            for (int i = 0; i < secrets.size(); i++) {
                if (key.equals(key(secrets.get(i)))) {
                    return i;
                }
            }
            return -1;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            StaticScanResult.CloudSecret secret = secrets.get(rowIndex);
            if (secret == null) {
                return "";
            }
            return switch (columnIndex) {
                case 0 -> secret.getSeverity();
                case 1 -> secret.getType();
                case 2 -> secret.getValue();
                case 3 -> formatConfidence(secret.getConfidence());
                case 4 -> secret.getSource();
                case 5 -> secret.getSourceScriptUrl();
                case 6 -> oneLine(secret.getEvidence());
                default -> "";
            };
        }

        private static String key(StaticScanResult.CloudSecret secret) {
            if (secret == null) {
                return null;
            }
            return safe(secret.getSeverity()) + "|" + safe(secret.getType()) + "|"
                    + safe(secret.getValue()) + "|" + safe(secret.getSourceScriptUrl()) + "|"
                    + safe(secret.getEvidence());
        }
    }

    private static class CloudRiskTableModel extends AbstractTableModel {
        private final String[] columns = {"类型", "级别", "证据", "来源脚本"};
        private List<StaticScanResult.CloudRisk> risks = List.of();

        void setRisks(List<StaticScanResult.CloudRisk> risks) {
            this.risks = nonNullList(risks);
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return risks.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            StaticScanResult.CloudRisk risk = risks.get(rowIndex);
            if (risk == null) {
                return "";
            }
            return switch (columnIndex) {
                case 0 -> risk.getType();
                case 1 -> risk.getSeverity();
                case 2 -> oneLine(risk.getEvidence());
                case 3 -> risk.getSourceScriptUrl();
                default -> "";
            };
        }
    }

    private static class AnalyzedScriptTableModel extends AbstractTableModel {
        private final String[] columns = {"URL", "验证", "状态码", "API", "Secret", "Risk", "Finding", "说明"};
        private List<StaticScanResult.AnalyzedScript> scripts = List.of();

        void setScripts(List<StaticScanResult.AnalyzedScript> scripts) {
            this.scripts = nonNullList(scripts);
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return scripts.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }

        StaticScanResult.AnalyzedScript getScriptAt(int row) {
            return row >= 0 && row < scripts.size() ? scripts.get(row) : null;
        }

        String keyAt(int row) {
            StaticScanResult.AnalyzedScript script = getScriptAt(row);
            return script != null ? safe(script.getUrl()) : null;
        }

        int indexOfKey(String key) {
            if (key == null) {
                return -1;
            }
            for (int i = 0; i < scripts.size(); i++) {
                if (key.equals(keyAt(i))) {
                    return i;
                }
            }
            return -1;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            StaticScanResult.AnalyzedScript script = scripts.get(rowIndex);
            if (script == null) {
                return "";
            }
            return switch (columnIndex) {
                case 0 -> script.getUrl();
                case 1 -> script.isValidated();
                case 2 -> script.getStatusCode() > 0 ? script.getStatusCode() : "-";
                case 3 -> script.getApiCount();
                case 4 -> script.getSecretCount();
                case 5 -> script.getRiskCount();
                case 6 -> script.getFindingCount();
                case 7 -> script.getReason();
                default -> "";
            };
        }
    }

    private static class JsTaskTableModel extends AbstractTableModel {
        private final String[] columns = {"阶段", "状态", "任务 ID", "脚本", "消息"};
        private List<StaticScanResult.JsAstTaskStatus> tasks = List.of();

        void setTasks(List<StaticScanResult.JsAstTaskStatus> tasks) {
            this.tasks = nonNullList(tasks);
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return tasks.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }

        StaticScanResult.JsAstTaskStatus getTaskAt(int row) {
            return row >= 0 && row < tasks.size() ? tasks.get(row) : null;
        }

        String keyAt(int row) {
            StaticScanResult.JsAstTaskStatus task = getTaskAt(row);
            if (task == null) {
                return null;
            }
            return safe(task.getTaskId()) + "|" + safe(task.getScriptUrl()) + "|"
                    + safe(task.getPhase()) + "|" + safe(task.getStatus());
        }

        int indexOfKey(String key) {
            if (key == null) {
                return -1;
            }
            for (int i = 0; i < tasks.size(); i++) {
                if (key.equals(keyAt(i))) {
                    return i;
                }
            }
            return -1;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            StaticScanResult.JsAstTaskStatus task = tasks.get(rowIndex);
            if (task == null) {
                return "";
            }
            return switch (columnIndex) {
                case 0 -> task.getPhase();
                case 1 -> task.getStatus();
                case 2 -> task.getTaskId();
                case 3 -> task.getScriptUrl();
                case 4 -> task.getMessage();
                default -> "";
            };
        }
    }

    private static String join(List<String> values) {
        if (values == null || values.isEmpty()) {
            return "";
        }
        return String.join(", ", values.stream()
                .filter(value -> value != null && !value.isBlank())
                .toList());
    }

    private static String formatConfidence(Double confidence) {
        return confidence != null ? String.format(java.util.Locale.ROOT, "%.2f", confidence) : "";
    }

    private static String oneLine(String value) {
        return value != null ? value.replace("\r", " ").replace("\n", " ").trim() : "";
    }

    private static String buildCloudApiDetail(StaticScanResult.CloudApi api,
                                              StaticScanResult.RecoveredEndpoint recovered) {
        if (api == null) {
            return "请选择上方接口候选，查看验证状态与详细结果。";
        }
        StringBuilder text = new StringBuilder();
        text.append("接口候选\n");
        appendLine(text, "方法", api.getMethod());
        appendLine(text, "原始 URL", api.getRawUrl());
        appendLine(text, "解析 URL", api.getResolvedUrl());
        appendLine(text, "Base URL", api.getBaseUrl());
        appendLine(text, "来源脚本", api.getSourceScriptUrl());
        appendLine(text, "来源", api.getSource());
        appendLine(text, "置信度", api.getConfidence());
        appendLine(text, "认证信号", api.getAuth());
        appendLine(text, "参数", join(api.getParams()));
        appendLine(text, "请求头", join(api.getHeaders()));
        appendLine(text, "说明", join(api.getNotes()));

        text.append("\n访问验证\n");
        appendLine(text, "结果", validationStatus(recovered));
        if (recovered != null) {
            appendLine(text, "验证 URL", recovered.getUrl());
            appendLine(text, "状态码", recovered.getStatusCode() > 0 ? String.valueOf(recovered.getStatusCode()) : "-");
            appendLine(text, "验证原因", recovered.getReason());
            appendLine(text, "验证来源脚本", recovered.getSourceScriptUrl());
        } else {
            appendLine(text, "验证原因", "未找到对应验证记录，可能受自动发包开关或最大验证数量限制。");
        }
        return text.toString();
    }

    private static void appendLine(StringBuilder text, String label, Object value) {
        text.append(label).append(": ").append(value != null && !String.valueOf(value).isBlank() ? value : "-").append('\n');
    }

    private static String validationStatus(StaticScanResult.RecoveredEndpoint recovered) {
        if (recovered == null) {
            return "未验证";
        }
        if (recovered.isValidated()) {
            return "访问成功";
        }
        String reason = recovered.getReason() != null ? recovered.getReason() : "";
        if (reason.contains("自动发包验证已关闭")) {
            return "未验证";
        }
        if (reason.contains("无法解析")) {
            return "解析失败";
        }
        if (recovered.getStatusCode() > 0) {
            return "访问失败";
        }
        return "未验证";
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String safe(String value) {
        return value != null ? value : "";
    }

    private static String firstNonBlank(String first, String second) {
        return first != null && !first.isBlank() ? first : second;
    }

    private static <T> List<T> nonNullList(List<T> values) {
        return values != null ? values.stream().filter(Objects::nonNull).toList() : List.of();
    }
}
