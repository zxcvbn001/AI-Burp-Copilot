package com.aiburpcopilot.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.aiburpcopilot.core.discovery.DiscoveryAttempt;
import com.aiburpcopilot.core.discovery.DiscoveryCandidate;
import com.aiburpcopilot.core.discovery.DiscoveryJudgment;
import com.aiburpcopilot.core.discovery.DiscoveryValidation;
import com.aiburpcopilot.core.discovery.DiscoveryValidationStatus;
import com.aiburpcopilot.core.discovery.ISiteDiscoveryService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class SitePatternDiscoveryPanel extends JPanel {

    private static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("MM-dd HH:mm:ss");

    private final ISiteDiscoveryService discoveryService;
    private final JComboBox<String> hostFilterCombo;
    private final JTable table;
    private final CandidateTableModel tableModel;
    private final JTextArea structureArea;
    private final JTextArea sourceArea;
    private final JList<DiscoveryAttempt> attemptList;
    private final DefaultListModel<DiscoveryAttempt> attemptListModel;
    private final BurpMessageViewer.RequestView requestViewer;
    private final BurpMessageViewer.ResponseView responseViewer;
    private final JTextArea reviewArea;
    private final JLabel summaryLabel;
    private final JLabel attemptHintLabel;

    private List<DiscoveryCandidate> currentCandidates = List.of();
    private String displayedCandidateKey;
    private SwingWorker<List<DiscoveryCandidate>, Void> inferenceWorker;
    private SwingWorker<List<DiscoveryCandidate>, DiscoveryCandidate> validationWorker;

    public SitePatternDiscoveryPanel(MontoyaApi api, ISiteDiscoveryService discoveryService) {
        this.discoveryService = discoveryService;
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 5));
        hostFilterCombo = new JComboBox<>();
        UiUtil.applyBurpLabelFont(hostFilterCombo);
        toolbar.add(new JLabel("站点 Endpoint:"));
        toolbar.add(hostFilterCombo);

        JButton inferButton = new JButton("开始 LLM 推理");
        inferButton.addActionListener(e -> startLlmInference());
        toolbar.add(inferButton);

        JButton validateButton = new JButton("验证当前 Endpoint");
        validateButton.addActionListener(e -> validateSelectedCandidate());
        toolbar.add(validateButton);

        JButton validateAllButton = new JButton("一键验证候选");
        validateAllButton.addActionListener(e -> validateAllCandidates());
        toolbar.add(validateAllButton);

        summaryLabel = new JLabel("候选: 0");
        toolbar.add(Box.createHorizontalStrut(16));
        toolbar.add(summaryLabel);
        add(toolbar, BorderLayout.NORTH);

        tableModel = new CandidateTableModel();
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        UiUtil.applyBurpFont(table);
        UiUtil.setScaledMinimumColumnWidths(table, 90, 70, 100, 360, 80, 80, 140);
        table.getColumnModel().getColumn(6).setCellRenderer(new JudgmentRenderer());

        structureArea = UiUtil.createMessageArea();
        sourceArea = UiUtil.createMessageArea();
        attemptListModel = new DefaultListModel<>();
        attemptList = new JList<>(attemptListModel);
        attemptList.setCellRenderer(new AttemptRenderer());
        UiUtil.applyBurpLabelFont(attemptList);
        requestViewer = new BurpMessageViewer.RequestView(api);
        responseViewer = new BurpMessageViewer.ResponseView(api);
        reviewArea = UiUtil.createMessageArea();
        attemptHintLabel = new JLabel("未发送验证请求");

        JTabbedPane detailTabs = new JTabbedPane();
        UiUtil.applyBurpFont(detailTabs);
        detailTabs.addTab("请求", requestViewer);
        detailTabs.addTab("响应", responseViewer);
        detailTabs.addTab("研判", UiUtil.searchableTextPanel(reviewArea));

        JTabbedPane leftTabs = new JTabbedPane();
        UiUtil.applyBurpFont(leftTabs);
        leftTabs.addTab("接口结构图", UiUtil.searchableTextPanel(structureArea));
        leftTabs.addTab("规律来源", UiUtil.searchableTextPanel(sourceArea));

        JPanel attemptPanel = new JPanel(new BorderLayout(0, 6));
        attemptPanel.setBorder(new EmptyBorder(6, 6, 6, 6));
        attemptPanel.add(new JLabel("验证请求 / 响应"), BorderLayout.NORTH);
        attemptPanel.add(new JScrollPane(attemptList), BorderLayout.CENTER);
        attemptPanel.add(attemptHintLabel, BorderLayout.SOUTH);

        JSplitPane lowerLeft = new JSplitPane(JSplitPane.VERTICAL_SPLIT, leftTabs, attemptPanel);
        lowerLeft.setResizeWeight(0.45);
        lowerLeft.setDividerLocation(180);

        JSplitPane lowerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, lowerLeft, detailTabs);
        lowerSplit.setResizeWeight(0.34);
        lowerSplit.setDividerLocation(360);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), lowerSplit);
        mainSplit.setResizeWeight(0.40);
        mainSplit.setDividerLocation(240);
        add(mainSplit, BorderLayout.CENTER);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateCandidateDetail();
            }
        });
        attemptList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateAttemptDetail();
            }
        });

        refresh();
    }

    public void refresh() {
        String previousHost = hostFilterCombo.getSelectedItem() instanceof String value ? value : "ALL";
        String previousKey = selectedCandidateKey();
        reloadHostFilter(previousHost);
        String hostFilter = selectedHostFilter();
        structureArea.setText(discoveryService.describeEndpointStructure(hostFilter));
        currentCandidates = discoveryService.getCandidates(hostFilter);
        tableModel.setRows(currentCandidates);
        summaryLabel.setText(statusText());
        restoreSelection(previousKey);
        if (table.getSelectedRow() < 0 && !currentCandidates.isEmpty()) {
            table.setRowSelectionInterval(0, 0);
        } else {
            updateCandidateDetail();
        }
    }

    private void startLlmInference() {
        if (inferenceWorker != null && !inferenceWorker.isDone()) {
            summaryLabel.setText(statusText() + " | LLM 推理中...");
            return;
        }
        String previousKey = selectedCandidateKey();
        String hostFilter = selectedHostFilter();
        summaryLabel.setText(statusText() + " | LLM 推理中...");
        inferenceWorker = new SwingWorker<>() {
            @Override
            protected List<DiscoveryCandidate> doInBackground() {
                return discoveryService.inferCandidates(hostFilter);
            }

            @Override
            protected void done() {
                try {
                    currentCandidates = get();
                } catch (Exception e) {
                    currentCandidates = List.of();
                    reviewArea.setText("接口推理失败: " + e.getMessage());
                }
                tableModel.setRows(currentCandidates);
                summaryLabel.setText(statusText());
                restoreSelection(previousKey);
                if (table.getSelectedRow() < 0 && !currentCandidates.isEmpty()) {
                    table.setRowSelectionInterval(0, 0);
                } else {
                    updateCandidateDetail();
                }
            }
        };
        inferenceWorker.execute();
    }

    private void reloadHostFilter(String preferred) {
        for (var listener : hostFilterCombo.getActionListeners()) {
            hostFilterCombo.removeActionListener(listener);
        }
        hostFilterCombo.removeAllItems();
        hostFilterCombo.addItem("ALL");
        for (String host : discoveryService.listHosts()) {
            hostFilterCombo.addItem(host);
        }
        hostFilterCombo.setSelectedItem(preferred != null ? preferred : "ALL");
        if (hostFilterCombo.getSelectedIndex() < 0) {
            hostFilterCombo.setSelectedItem("ALL");
        }
        hostFilterCombo.addActionListener(e -> refresh());
    }

    private void validateSelectedCandidate() {
        DiscoveryCandidate candidate = tableModel.getRowAt(table.getSelectedRow());
        if (candidate == null) {
            JOptionPane.showMessageDialog(this, "请先选择一个候选项。");
            return;
        }

        summaryLabel.setText("候选: " + currentCandidates.size() + " | 正在验证...");
        new SwingWorker<DiscoveryCandidate, Void>() {
            @Override
            protected DiscoveryCandidate doInBackground() {
                return discoveryService.validateCandidate(candidate);
            }

            @Override
            protected void done() {
                try {
                    replaceCandidate(get());
                } catch (Exception ignored) {
                }
                restoreSelection(candidate.getKey());
                tableModel.setRows(currentCandidates);
                summaryLabel.setText(statusText());
                updateCandidateDetail();
            }
        }.execute();
    }

    private void validateAllCandidates() {
        if (validationWorker != null && !validationWorker.isDone()) {
            summaryLabel.setText(statusText() + " | 正在批量验证...");
            return;
        }
        List<DiscoveryCandidate> targets = currentCandidates.stream()
                .filter(candidate -> candidate != null
                        && (candidate.getValidation() == null
                        || candidate.getValidation().getStatus() == DiscoveryValidationStatus.NOT_RUN))
                .toList();
        if (targets.isEmpty()) {
            JOptionPane.showMessageDialog(this, "当前没有待验证候选。");
            return;
        }
        String previousKey = selectedCandidateKey();
        summaryLabel.setText(statusText() + " | 正在批量验证 0/" + targets.size());
        validationWorker = new SwingWorker<>() {
            @Override
            protected List<DiscoveryCandidate> doInBackground() {
                List<DiscoveryCandidate> validated = new ArrayList<>();
                int done = 0;
                for (DiscoveryCandidate target : targets) {
                    DiscoveryCandidate result = discoveryService.validateCandidate(target);
                    validated.add(result);
                    done++;
                    publish(result);
                    setProgress((int) Math.round(done * 100.0 / targets.size()));
                }
                return validated;
            }

            @Override
            protected void process(List<DiscoveryCandidate> chunks) {
                if (chunks == null || chunks.isEmpty()) {
                    return;
                }
                for (DiscoveryCandidate candidate : chunks) {
                    replaceCandidate(candidate);
                }
                tableModel.setRows(currentCandidates);
                summaryLabel.setText(statusText() + " | 正在批量验证 " + validatedCount(targets) + "/" + targets.size());
            }

            @Override
            protected void done() {
                try {
                    get();
                } catch (Exception ignored) {
                }
                refresh();
                restoreSelection(previousKey);
            }
        };
        validationWorker.execute();
    }

    private void updateCandidateDetail() {
        DiscoveryCandidate candidate = tableModel.getRowAt(table.getSelectedRow());
        if (candidate == null) {
            displayedCandidateKey = null;
            structureArea.setText(discoveryService.describeEndpointStructure(selectedHostFilter()));
            sourceArea.setText("");
            attemptListModel.clear();
            reviewArea.setText("");
            requestViewer.setBytes(null);
            responseViewer.setBytes(null);
            attemptHintLabel.setText("未选择候选");
            return;
        }

        String currentKey = candidate.getKey();
        boolean sameCandidate = currentKey != null && currentKey.equals(displayedCandidateKey);
        UiUtil.setTextPreservingView(sourceArea, buildSourceText(candidate), sameCandidate);
        UiUtil.setTextPreservingView(reviewArea, buildReviewText(candidate), sameCandidate);
        attemptListModel.clear();
        DiscoveryValidation validation = candidate.getValidation();
        if (validation != null) {
            for (DiscoveryAttempt attempt : validation.getAttempts()) {
                attemptListModel.addElement(attempt);
            }
        }
        attemptHintLabel.setText(validationHint(candidate));
        displayedCandidateKey = currentKey;
        if (!attemptListModel.isEmpty()) {
            attemptList.setSelectedIndex(0);
        } else {
            requestViewer.setBytes(null);
            responseViewer.setBytes(null);
        }
    }

    private void updateAttemptDetail() {
        DiscoveryAttempt attempt = attemptList.getSelectedValue();
        if (attempt == null) {
            requestViewer.setBytes(null);
            responseViewer.setBytes(null);
            return;
        }
        requestViewer.setBytes(attempt.getRequestBytes());
        responseViewer.setBytes(attempt.getResponseBytes());
        attemptHintLabel.setText("Request " + attempt.getSequence() + " / Response " + attempt.getSequence()
                + " | " + attempt.getMethod() + " | HTTP " + attempt.getStatusCode()
                + " | " + (attempt.isSignalMatched() ? "有存在信号" : "无明显存在信号"));
    }

    private String buildSourceText(DiscoveryCandidate candidate) {
        StringBuilder sb = new StringBuilder();
        sb.append("目标: ").append(candidate.getUrl()).append("\n");
        if (candidate.getMethodHint() != null && !candidate.getMethodHint().isBlank()) {
            sb.append("建议方法: ").append(candidate.getMethodHint()).append("\n");
        }
        sb.append("类型: ").append(candidate.getAssetType()).append("\n");
        sb.append("评分: ").append(String.format("%.2f", candidate.getScore())).append("\n");
        sb.append("规律来源: ").append(candidate.getSourceReason()).append("\n");
        sb.append("支撑流量数: ").append(candidate.getSupportingObservationCount()).append("\n");

        if (!candidate.getSupportingMethods().isEmpty()) {
            sb.append("\n关联方法:\n");
            for (String method : candidate.getSupportingMethods()) {
                sb.append("- ").append(method).append("\n");
            }
        }

        if (!candidate.getSupportingPaths().isEmpty()) {
            sb.append("\n参考路径:\n");
            for (String path : candidate.getSupportingPaths()) {
                sb.append("- ").append(path).append("\n");
            }
        }

        if (!candidate.getSupportingParameters().isEmpty()) {
            sb.append("\n关联参数特征:\n");
            for (String param : candidate.getSupportingParameters()) {
                sb.append("- ").append(param).append("\n");
            }
        }
        return sb.toString();
    }

    private String buildReviewText(DiscoveryCandidate candidate) {
        DiscoveryValidation validation = candidate.getValidation();
        if (validation == null || validation.getStatus() == DiscoveryValidationStatus.NOT_RUN) {
            return "尚未发起存在性验证。\n\n这里会展示最终研判结论，以及每次请求/响应的命中情况。";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("最终结论: ").append(validation.getJudgment().getDisplayName()).append("\n");
        sb.append("验证状态: ").append(validation.getStatus()).append("\n");
        if (validation.getFinalStatusCode() > 0) {
            sb.append("最终状态码: ").append(validation.getFinalStatusCode()).append("\n");
        }
        if (validation.getContentType() != null && !validation.getContentType().isBlank()) {
            sb.append("Content-Type: ").append(validation.getContentType()).append("\n");
        }
        if (validation.getValidatedAt() > 0) {
            sb.append("验证时间: ").append(TIME_FORMAT.format(new Date(validation.getValidatedAt()))).append("\n");
        }
        sb.append("\n研判说明:\n").append(validation.getReasoning() != null ? validation.getReasoning() : "-");
        if (!validation.getAttempts().isEmpty()) {
            sb.append("\n\n执行记录:\n");
            for (DiscoveryAttempt attempt : validation.getAttempts()) {
                sb.append("- Request ").append(attempt.getSequence())
                        .append(" / Response ").append(attempt.getSequence())
                        .append(" | ").append(attempt.getMethod())
                        .append(" | HTTP ").append(attempt.getStatusCode());
                if (attempt.getSummary() != null && !attempt.getSummary().isBlank()) {
                    sb.append(" | ").append(attempt.getSummary());
                }
                sb.append("\n");
            }
        }
        return sb.toString();
    }

    private String validationHint(DiscoveryCandidate candidate) {
        DiscoveryValidation validation = candidate.getValidation();
        if (validation == null || validation.getStatus() == DiscoveryValidationStatus.NOT_RUN) {
            return "尚未验证，点击“验证当前候选”后会在这里展示请求/响应";
        }
        if (validation.getStatus() == DiscoveryValidationStatus.RUNNING) {
            return "正在发包验证...";
        }
        return "共 " + validation.getAttempts().size() + " 次请求，最终结论："
                + validation.getJudgment().getDisplayName();
    }

    private String statusText() {
        long validated = currentCandidates.stream()
                .filter(candidate -> candidate != null
                        && candidate.getValidation() != null
                        && candidate.getValidation().getStatus() == DiscoveryValidationStatus.COMPLETED)
                .count();
        return "候选: " + currentCandidates.size() + " | 已验证: " + validated;
    }

    private int validatedCount(List<DiscoveryCandidate> targets) {
        int count = 0;
        for (DiscoveryCandidate target : targets) {
            DiscoveryCandidate current = findCurrentCandidate(target.getKey());
            if (current != null
                    && current.getValidation() != null
                    && current.getValidation().getStatus() == DiscoveryValidationStatus.COMPLETED) {
                count++;
            }
        }
        return count;
    }

    private void replaceCandidate(DiscoveryCandidate updated) {
        if (updated == null || updated.getKey() == null) {
            return;
        }
        List<DiscoveryCandidate> updatedRows = new ArrayList<>(currentCandidates);
        for (int i = 0; i < updatedRows.size(); i++) {
            DiscoveryCandidate candidate = updatedRows.get(i);
            if (candidate != null && updated.getKey().equals(candidate.getKey())) {
                updatedRows.set(i, updated);
                currentCandidates = List.copyOf(updatedRows);
                return;
            }
        }
    }

    private DiscoveryCandidate findCurrentCandidate(String key) {
        if (key == null) {
            return null;
        }
        for (DiscoveryCandidate candidate : currentCandidates) {
            if (candidate != null && key.equals(candidate.getKey())) {
                return candidate;
            }
        }
        return null;
    }

    private String selectedHostFilter() {
        Object selected = hostFilterCombo.getSelectedItem();
        return selected instanceof String value ? value : "ALL";
    }

    private String selectedCandidateKey() {
        DiscoveryCandidate candidate = tableModel.getRowAt(table.getSelectedRow());
        return candidate != null ? candidate.getKey() : null;
    }

    private void restoreSelection(String key) {
        if (key == null) {
            return;
        }
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            DiscoveryCandidate row = tableModel.getRowAt(i);
            if (row != null && key.equals(row.getKey())) {
                table.setRowSelectionInterval(i, i);
                return;
            }
        }
    }

    private static class CandidateTableModel extends AbstractTableModel {
        private final String[] columns = {"Host", "Method", "Type", "Path", "Score", "状态码", "研判"};
        private List<DiscoveryCandidate> rows = List.of();

        void setRows(List<DiscoveryCandidate> rows) {
            this.rows = rows != null ? rows : List.of();
            fireTableDataChanged();
        }

        DiscoveryCandidate getRowAt(int row) {
            return row >= 0 && row < rows.size() ? rows.get(row) : null;
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            DiscoveryCandidate candidate = rows.get(rowIndex);
            DiscoveryValidation validation = candidate.getValidation();
            return switch (columnIndex) {
                case 0 -> candidate.getHost();
                case 1 -> candidate.getMethodHint() != null && !candidate.getMethodHint().isBlank()
                        ? candidate.getMethodHint() : "-";
                case 2 -> candidate.getAssetType();
                case 3 -> candidate.getPath();
                case 4 -> String.format("%.2f", candidate.getScore());
                case 5 -> validation != null && validation.getFinalStatusCode() > 0
                        ? String.valueOf(validation.getFinalStatusCode()) : "-";
                case 6 -> validation != null ? validation.getJudgment().getDisplayName() : DiscoveryJudgment.UNVALIDATED.getDisplayName();
                default -> "";
            };
        }
    }

    private static class AttemptRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list,
                                                      Object value,
                                                      int index,
                                                      boolean isSelected,
                                                      boolean cellHasFocus) {
            JLabel label = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            if (value instanceof DiscoveryAttempt attempt) {
                label.setText("Request " + attempt.getSequence() + " / Response " + attempt.getSequence()
                        + " | " + attempt.getMethod()
                        + " | HTTP " + attempt.getStatusCode()
                        + " | " + (attempt.getSummary() != null ? attempt.getSummary() : ""));
            }
            return label;
        }
    }

    private static class JudgmentRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table,
                                                       Object value,
                                                       boolean isSelected,
                                                       boolean hasFocus,
                                                       int row,
                                                       int column) {
            Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected && value instanceof String text) {
                if (text.contains("失败") || text.contains("不存在")) {
                    component.setForeground(new Color(170, 0, 0));
                } else if (text.contains("待人工")) {
                    component.setForeground(new Color(200, 120, 0));
                } else if (text.contains("存在")) {
                    component.setForeground(new Color(0, 128, 0));
                } else {
                    component.setForeground(Color.GRAY);
                }
            }
            return component;
        }
    }
}
