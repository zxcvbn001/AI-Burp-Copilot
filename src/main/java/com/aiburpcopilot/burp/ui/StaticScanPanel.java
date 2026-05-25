package com.aiburpcopilot.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.scanner.staticresource.StaticScanResult;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

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
    private final JTextArea cloudApiDetailArea;
    private final JTable cloudAssetTable;
    private final CloudAssetTableModel cloudAssetTableModel;
    private final JTable cloudParamTable;
    private final CloudParamTableModel cloudParamTableModel;
    private final JTable cloudSecretTable;
    private final CloudSecretTableModel cloudSecretTableModel;
    private final JTable cloudRiskTable;
    private final CloudRiskTableModel cloudRiskTableModel;
    private final JTable endpointFindingTable;
    private final CloudFindingTableModel endpointFindingTableModel;
    private final JTable exposureFindingTable;
    private final CloudFindingTableModel exposureFindingTableModel;
    private final JTable scriptFindingTable;
    private final CloudFindingTableModel scriptFindingTableModel;
    private final JTable analyzedScriptTable;
    private final AnalyzedScriptTableModel analyzedScriptTableModel;
    private final JTable jsTaskTable;
    private final JsTaskTableModel jsTaskTableModel;
    private final JTextArea authSignalArea;
    private final BurpMessageViewer.RequestView requestViewer;
    private final BurpMessageViewer.ResponseView responseViewer;

    private HistoryEntry currentEntry;
    private String displayedEntryId;
    private boolean refreshing;

    public StaticScanPanel(MontoyaApi api, IHistoryService historyService) {
        this.historyService = historyService;
        setLayout(new BorderLayout());

        tableModel = new StaticScanTableModel();
        table = new JTable(tableModel);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        UiUtil.applyBurpFont(table);
        UiUtil.setScaledColumnWidths(table, 85, 75, 380, 560);
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
        cloudFindingTable = createDataTable(cloudFindingTableModel, 120, 100, 180, 90, 75, 100, 280, 420);
        cloudApiTableModel = new CloudApiTableModel();
        cloudApiTable = createDataTable(cloudApiTableModel, 65, 240, 300, 90, 65, 80, 95, 160, 280, 240);
        cloudApiTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !refreshing) {
                updateCloudApiDetail(false);
            }
        });
        cloudApiDetailArea = createWrappedTextArea();
        cloudAssetTableModel = new CloudAssetTableModel();
        cloudAssetTable = createDataTable(cloudAssetTableModel, 70, 260, 300, 130, 120, 180);
        cloudParamTableModel = new CloudParamTableModel();
        cloudParamTable = createDataTable(cloudParamTableModel, 130, 80, 240, 120, 240);
        cloudSecretTableModel = new CloudSecretTableModel();
        cloudSecretTable = createDataTable(cloudSecretTableModel, 120, 180, 80, 80, 100, 280, 420);
        cloudRiskTableModel = new CloudRiskTableModel();
        cloudRiskTable = createDataTable(cloudRiskTableModel, 140, 80, 320, 260);
        endpointFindingTableModel = new CloudFindingTableModel();
        endpointFindingTable = createDataTable(endpointFindingTableModel, 120, 100, 180, 90, 75, 100, 280, 420);
        exposureFindingTableModel = new CloudFindingTableModel();
        exposureFindingTable = createDataTable(exposureFindingTableModel, 120, 100, 180, 90, 75, 100, 280, 420);
        scriptFindingTableModel = new CloudFindingTableModel();
        scriptFindingTable = createDataTable(scriptFindingTableModel, 120, 100, 180, 90, 75, 100, 280, 420);
        analyzedScriptTableModel = new AnalyzedScriptTableModel();
        analyzedScriptTable = createDataTable(analyzedScriptTableModel, 360, 80, 70, 65, 65, 65, 440);
        jsTaskTableModel = new JsTaskTableModel();
        jsTaskTable = createDataTable(jsTaskTableModel, 90, 90, 230, 280, 520);
        authSignalArea = createWrappedTextArea();
        requestViewer = new BurpMessageViewer.RequestView(api);
        responseViewer = new BurpMessageViewer.ResponseView(api);

        JTabbedPane resultTabs = new JTabbedPane();
        UiUtil.applyBurpFont(resultTabs);
        resultTabs.addTab("总览", titledScroll("扫描摘要", findingArea));
        resultTabs.addTab("Endpoints", createEndpointGroupPanel());
        resultTabs.addTab("Sensitive", createExposureGroupPanel());
        resultTabs.addTab("Scripts", createScriptGroupPanel());
        resultTabs.addTab("Raw Findings", titledScroll("Cloud Findings", cloudFindingTable));
        resultTabs.addTab("Params", titledScroll("Recovered Params", cloudParamTable));
        resultTabs.addTab("Auth", titledScroll("Auth Signals", authSignalArea));
        resultTabs.addTab("Tasks", titledScroll("JS AST Tasks", jsTaskTable));

        JPanel findingPanel = new JPanel(new BorderLayout());
        findingPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        findingPanel.add(resultTabs, BorderLayout.CENTER);

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
        SwingUtilities.invokeLater(() -> {
            refreshing = true;
            try {
                List<HistoryEntry> staticResources = historyService.searchAdvanced(
                                null, null, EndpointType.STATIC_RESOURCE, null, null, null, null, 0, 200).stream()
                        .filter(entry -> entry.getAiSummary() != null
                                && !entry.getAiSummary().startsWith("静态文件扫描已跳过"))
                        .toList();
                tableModel.setEntries(staticResources);
                restoreSelection(staticResources, preserveId);
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
        UiUtil.setTextPreservingView(
                findingArea,
                buildSummaryText(entry, details),
                sameEntry);
        cloudFindingTableModel.setFindings(details != null ? details.getCloudFindings() : List.of());
        cloudApiTableModel.setApis(
                details != null ? details.getCloudApis() : List.of(),
                details != null ? details.getRecoveredEndpoints() : List.of());
        restoreCloudApiSelection(sameEntry ? selectedApiKey : null);
        updateCloudApiDetail(sameEntry);
        cloudAssetTableModel.setAssets(details != null ? details.getCloudAssets() : List.of());
        cloudParamTableModel.setParams(details != null ? details.getCloudParams() : List.of());
        cloudSecretTableModel.setSecrets(details != null ? details.getCloudSecrets() : List.of());
        cloudRiskTableModel.setRisks(details != null ? details.getCloudRisks() : List.of());
        endpointFindingTableModel.setFindings(details != null ? details.getEndpointFindings() : List.of());
        exposureFindingTableModel.setFindings(details != null ? details.getExposureFindings() : List.of());
        scriptFindingTableModel.setFindings(details != null ? details.getScriptFindings() : List.of());
        analyzedScriptTableModel.setScripts(details != null ? details.getAnalyzedScripts() : List.of());
        jsTaskTableModel.setTasks(details != null ? details.getJsAstTasks() : List.of());
        UiUtil.setTextPreservingView(authSignalArea, buildAuthSignalText(details), sameEntry);
        requestViewer.setBytes(entry.getRawRequest());
        responseViewer.setBytes(entry.getRawResponse());
        displayedEntryId = currentId;
    }

    private void clearDetail() {
        currentEntry = null;
        displayedEntryId = null;
        findingArea.setText("");
        cloudFindingTableModel.setFindings(List.of());
        cloudApiTableModel.setApis(List.of(), List.of());
        cloudApiDetailArea.setText("");
        cloudAssetTableModel.setAssets(List.of());
        cloudParamTableModel.setParams(List.of());
        cloudSecretTableModel.setSecrets(List.of());
        cloudRiskTableModel.setRisks(List.of());
        endpointFindingTableModel.setFindings(List.of());
        exposureFindingTableModel.setFindings(List.of());
        scriptFindingTableModel.setFindings(List.of());
        analyzedScriptTableModel.setScripts(List.of());
        jsTaskTableModel.setTasks(List.of());
        authSignalArea.setText("");
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
        JTabbedPane lowerTabs = new JTabbedPane();
        UiUtil.applyBurpFont(lowerTabs);
        lowerTabs.addTab("选中接口详情", titledScroll("访问验证 / 接口详情", cloudApiDetailArea));
        lowerTabs.addTab("Endpoint Findings", titledScroll("Endpoint findings", endpointFindingTable));

        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                titledScroll("API / Endpoint candidates（验证结果见表格）", cloudApiTable),
                lowerTabs);
        split.setResizeWeight(0.65);
        split.setDividerLocation(260);
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    private void restoreCloudApiSelection(String selectedApiKey) {
        if (cloudApiTableModel.getRowCount() == 0) {
            cloudApiTable.clearSelection();
            return;
        }
        int row = selectedApiKey != null ? cloudApiTableModel.indexOfKey(selectedApiKey) : -1;
        if (row < 0) {
            row = 0;
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

    private void updateCloudApiDetail(boolean preserveView) {
        int row = cloudApiTable.getSelectedRow();
        if (row < 0) {
            UiUtil.setTextPreservingView(cloudApiDetailArea, "请选择上方接口候选，查看验证状态与详细结果。", preserveView);
            return;
        }
        int modelRow = cloudApiTable.convertRowIndexToModel(row);
        StaticScanResult.CloudApi api = cloudApiTableModel.getApiAt(modelRow);
        StaticScanResult.RecoveredEndpoint recovered = cloudApiTableModel.getRecoveredAt(modelRow);
        UiUtil.setTextPreservingView(cloudApiDetailArea, buildCloudApiDetail(api, recovered), preserveView);
    }

    private JPanel createExposureGroupPanel() {
        JSplitPane top = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                titledScroll("Sensitive information (云端已完成 LLM 复核)", cloudSecretTable),
                titledScroll("Exposure findings", exposureFindingTable));
        top.setResizeWeight(0.55);
        top.setDividerLocation(220);
        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                top,
                titledScroll("Risk signals", cloudRiskTable));
        split.setResizeWeight(0.78);
        split.setDividerLocation(360);
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createScriptGroupPanel() {
        JSplitPane top = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                titledScroll("Webpack / script assets (探测与递归分析受配置管控)", cloudAssetTable),
                titledScroll("Script findings", scriptFindingTable));
        top.setResizeWeight(0.55);
        top.setDividerLocation(220);
        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                top,
                titledScroll("Analyzed scripts", analyzedScriptTable));
        split.setResizeWeight(0.72);
        split.setDividerLocation(350);
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    private String buildAuthSignalText(StaticScanResult details) {
        if (details == null || details.getCloudAuthSignals() == null || details.getCloudAuthSignals().isEmpty()) {
            return "";
        }
        return String.join("\n", details.getCloudAuthSignals());
    }

    private String buildSummaryText(HistoryEntry entry, StaticScanResult details) {
        StringBuilder text = new StringBuilder(entry.getAiSummary() != null ? entry.getAiSummary() : "未扫描或无发现");
        if (details == null) {
            text.append("\n\n[UI] 未读取到结构化静态扫描详情，分组 Tab 将为空。请重新扫描该 JS。");
            return text.toString();
        }
        text.append("\n\n[UI] JS AST 结果已加载: findings=").append(totalFindingCount(details))
                .append(", endpointFindings=").append(size(details.getEndpointFindings()))
                .append(", sensitiveFindings=").append(size(details.getExposureFindings()))
                .append(", scriptFindings=").append(size(details.getScriptFindings()))
                .append(", rawFindings=").append(size(details.getCloudFindings()))
                .append(", apis=").append(size(details.getCloudApis()))
                .append(", verifiedApis=").append(validRecoveredEndpointCount(details))
                .append(", assets=").append(size(details.getCloudAssets()))
                .append(", params=").append(size(details.getCloudParams()))
                .append(", auth=").append(size(details.getCloudAuthSignals()))
                .append(", secrets=").append(size(details.getCloudSecrets()))
                .append(", risks=").append(size(details.getCloudRisks()));
        StaticScanResult.JsAstTaskStatus latest = latestTask(details);
        if (latest != null) {
            text.append("\n[UI] JS AST 进度: [").append(oneLine(latest.getPhase()))
                    .append("] ").append(oneLine(latest.getStatus()))
                    .append(" | ").append(oneLine(latest.getMessage()));
        }
        return text.toString();
    }

    private int size(List<?> values) {
        return values != null ? values.size() : 0;
    }

    private int totalFindingCount(StaticScanResult details) {
        if (details == null) {
            return 0;
        }
        int grouped = size(details.getEndpointFindings())
                + size(details.getExposureFindings())
                + size(details.getScriptFindings());
        if (grouped > 0) {
            return grouped;
        }
        return size(details.getCloudFindings()) + size(details.getCloudSecrets()) + size(details.getCloudRisks());
    }

    private int validRecoveredEndpointCount(StaticScanResult details) {
        if (details == null || details.getRecoveredEndpoints() == null) {
            return 0;
        }
        return (int) details.getRecoveredEndpoints().stream()
                .filter(StaticScanResult.RecoveredEndpoint::isValidated)
                .count();
    }

    private StaticScanResult.JsAstTaskStatus latestTask(StaticScanResult details) {
        if (details == null || details.getJsAstTasks() == null || details.getJsAstTasks().isEmpty()) {
            return null;
        }
        return details.getJsAstTasks().get(details.getJsAstTasks().size() - 1);
    }

    private static class StaticScanTableModel extends AbstractTableModel {
        private final String[] columns = {"时间", "方法", "URL", "发现"};
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

    private static class CloudFindingTableModel extends AbstractTableModel {
        private final String[] columns = {"Category", "Type", "Value", "Severity", "Confidence", "Source", "Script", "Evidence"};
        private List<StaticScanResult.CloudFinding> findings = List.of();

        void setFindings(List<StaticScanResult.CloudFinding> findings) {
            this.findings = findings != null ? findings : List.of();
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return findings.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            StaticScanResult.CloudFinding finding = findings.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> finding.getCategory();
                case 1 -> finding.getType();
                case 2 -> finding.getValue();
                case 3 -> finding.getSeverity();
                case 4 -> formatConfidence(finding.getConfidence());
                case 5 -> finding.getSource();
                case 6 -> finding.getSourceScriptUrl();
                case 7 -> oneLine(finding.getEvidence());
                default -> "";
            };
        }
    }

    private static class CloudApiTableModel extends AbstractTableModel {
        private final String[] columns = {"方法", "原始 URL", "解析 URL", "访问验证", "状态码", "置信度", "来源", "参数", "来源脚本", "说明"};
        private List<StaticScanResult.CloudApi> apis = List.of();
        private List<StaticScanResult.RecoveredEndpoint> recoveredEndpoints = List.of();

        void setApis(List<StaticScanResult.CloudApi> apis, List<StaticScanResult.RecoveredEndpoint> recoveredEndpoints) {
            this.apis = apis != null ? apis : List.of();
            List<StaticScanResult.RecoveredEndpoint> source = recoveredEndpoints != null ? recoveredEndpoints : List.of();
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
            StaticScanResult.RecoveredEndpoint recovered = getRecoveredAt(rowIndex);
            return switch (columnIndex) {
                case 0 -> api.getMethod();
                case 1 -> api.getRawUrl();
                case 2 -> api.getResolvedUrl();
                case 3 -> validationStatus(recovered);
                case 4 -> recovered != null && recovered.getStatusCode() > 0 ? recovered.getStatusCode() : "-";
                case 5 -> api.getConfidence();
                case 6 -> api.getSource();
                case 7 -> join(api.getParams());
                case 8 -> api.getSourceScriptUrl();
                case 9 -> recovered != null ? recovered.getReason() : join(api.getNotes());
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
        private final String[] columns = {"Type", "URL", "Resolved URL", "Chunk", "Source", "Script"};
        private List<StaticScanResult.CloudAsset> assets = List.of();

        void setAssets(List<StaticScanResult.CloudAsset> assets) {
            this.assets = assets != null ? assets : List.of();
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return assets.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            StaticScanResult.CloudAsset asset = assets.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> asset.getType();
                case 1 -> asset.getUrl();
                case 2 -> asset.getResolvedUrl();
                case 3 -> asset.getChunkName();
                case 4 -> asset.getSource();
                case 5 -> asset.getSourceScriptUrl();
                default -> "";
            };
        }
    }

    private static class CloudParamTableModel extends AbstractTableModel {
        private final String[] columns = {"Name", "Location", "API", "Source", "Script"};
        private List<StaticScanResult.CloudParam> params = List.of();

        void setParams(List<StaticScanResult.CloudParam> params) {
            this.params = params != null ? params : List.of();
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return params.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            StaticScanResult.CloudParam param = params.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> param.getName();
                case 1 -> param.getLocation();
                case 2 -> param.getApi();
                case 3 -> param.getSource();
                case 4 -> param.getSourceScriptUrl();
                default -> "";
            };
        }
    }

    private static class CloudSecretTableModel extends AbstractTableModel {
        private final String[] columns = {"Type", "Value", "Severity", "Confidence", "Source", "Script", "Evidence"};
        private List<StaticScanResult.CloudSecret> secrets = List.of();

        void setSecrets(List<StaticScanResult.CloudSecret> secrets) {
            this.secrets = secrets != null ? secrets : List.of();
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return secrets.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            StaticScanResult.CloudSecret secret = secrets.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> secret.getType();
                case 1 -> secret.getValue();
                case 2 -> secret.getSeverity();
                case 3 -> formatConfidence(secret.getConfidence());
                case 4 -> secret.getSource();
                case 5 -> secret.getSourceScriptUrl();
                case 6 -> oneLine(secret.getEvidence());
                default -> "";
            };
        }
    }

    private static class CloudRiskTableModel extends AbstractTableModel {
        private final String[] columns = {"Type", "Severity", "Evidence", "Script"};
        private List<StaticScanResult.CloudRisk> risks = List.of();

        void setRisks(List<StaticScanResult.CloudRisk> risks) {
            this.risks = risks != null ? risks : List.of();
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return risks.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            StaticScanResult.CloudRisk risk = risks.get(rowIndex);
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
        private final String[] columns = {"URL", "Validated", "Status", "APIs", "Secrets", "Risks", "Reason"};
        private List<StaticScanResult.AnalyzedScript> scripts = List.of();

        void setScripts(List<StaticScanResult.AnalyzedScript> scripts) {
            this.scripts = scripts != null ? scripts : List.of();
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return scripts.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            StaticScanResult.AnalyzedScript script = scripts.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> script.getUrl();
                case 1 -> script.isValidated();
                case 2 -> script.getStatusCode() > 0 ? script.getStatusCode() : "-";
                case 3 -> script.getApiCount();
                case 4 -> script.getSecretCount();
                case 5 -> script.getRiskCount();
                case 6 -> script.getReason();
                default -> "";
            };
        }
    }

    private static class JsTaskTableModel extends AbstractTableModel {
        private final String[] columns = {"Phase", "Status", "Task ID", "Script", "Message"};
        private List<StaticScanResult.JsAstTaskStatus> tasks = List.of();

        void setTasks(List<StaticScanResult.JsAstTaskStatus> tasks) {
            this.tasks = tasks != null ? tasks : List.of();
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return tasks.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            StaticScanResult.JsAstTaskStatus task = tasks.get(rowIndex);
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
        return values != null && !values.isEmpty() ? String.join(", ", values) : "";
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
}
