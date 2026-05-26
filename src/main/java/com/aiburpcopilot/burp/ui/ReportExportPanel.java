package com.aiburpcopilot.burp.ui;

import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.core.report.ReportExportTaskRecord;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.UUID;

public class ReportExportPanel extends JPanel {

    private static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("HH:mm:ss");

    private final IHistoryService historyService;
    private final ExportTaskTableModel tableModel;
    private final JTable table;
    private final JTextArea detailArea;
    private ExportTaskHandle displayedHandle;

    public ReportExportPanel(IHistoryService historyService) {
        this.historyService = historyService;
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        tableModel = new ExportTaskTableModel();
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);
        UiUtil.applyBurpFont(table);
        UiUtil.setScaledColumnWidths(table, 90, 110, 80, 100, 420);

        detailArea = UiUtil.createMessageArea();

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateDetail();
            }
        });

        JSplitPane splitPane = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table),
                UiUtil.searchableTextPanel(detailArea));
        splitPane.setResizeWeight(0.45);
        add(splitPane, BorderLayout.CENTER);
        loadPersistedTasks();
    }

    public void refresh() {
        tableModel.refresh();
        updateDetail();
    }

    public ExportTaskHandle createTask(String host, int itemCount, Path outputPath) {
        ExportTaskHandle handle = new ExportTaskHandle(historyService, host, itemCount, outputPath);
        SwingUtilities.invokeLater(() -> {
            tableModel.addTask(handle);
            int row = tableModel.indexOf(handle);
            if (row >= 0) {
                table.setRowSelectionInterval(row, row);
            }
        });
        return handle;
    }

    private void loadPersistedTasks() {
        if (historyService == null) {
            return;
        }
        String selectedTaskId = selectedTaskId();
        List<ReportExportTaskRecord> records = historyService.listReportExportTasks();
        tableModel.clear();
        for (ReportExportTaskRecord record : records) {
            tableModel.addTaskSilently(new ExportTaskHandle(historyService, record));
        }
        tableModel.refresh();
        restoreSelection(selectedTaskId);
    }

    private void updateDetail() {
        ExportTaskHandle handle = tableModel.getRowAt(table.getSelectedRow());
        if (handle == null) {
            displayedHandle = null;
            detailArea.setText("");
            return;
        }
        boolean sameHandle = handle == displayedHandle;
        UiUtil.setTextPreservingView(detailArea, handle.detailText(), sameHandle);
        displayedHandle = handle;
    }

    private String selectedTaskId() {
        ExportTaskHandle handle = tableModel.getRowAt(table.getSelectedRow());
        return handle != null ? handle.taskId() : displayedHandle != null ? displayedHandle.taskId() : null;
    }

    private void restoreSelection(String taskId) {
        if (taskId == null || taskId.isBlank()) {
            return;
        }
        int row = tableModel.indexOfTaskId(taskId);
        if (row >= 0) {
            table.setRowSelectionInterval(row, row);
            table.scrollRectToVisible(table.getCellRect(row, 0, true));
            updateDetail();
        }
    }

    public static final class ExportTaskHandle {
        private final IHistoryService historyService;
        private final String taskId;
        private final long createdAt;
        private final String host;
        private final int itemCount;
        private final Path outputPath;
        private final List<String> logs = new CopyOnWriteArrayList<>();
        private volatile String status = "QUEUED";
        private volatile int percent;
        private volatile String stage = "QUEUED";
        private volatile String message = "Waiting to start";
        private volatile Path completedPath;
        private volatile String error;

        private ExportTaskHandle(IHistoryService historyService, String host, int itemCount, Path outputPath) {
            this.historyService = historyService;
            this.taskId = UUID.randomUUID().toString();
            this.createdAt = System.currentTimeMillis();
            this.host = host;
            this.itemCount = itemCount;
            this.outputPath = outputPath;
            addLog("Task created");
            persist();
        }

        private ExportTaskHandle(IHistoryService historyService, ReportExportTaskRecord record) {
            this.historyService = historyService;
            this.taskId = record.getTaskId();
            this.createdAt = record.getCreatedAt();
            this.host = record.getHost();
            this.itemCount = record.getItemCount();
            this.outputPath = record.getOutputPath() != null ? Path.of(record.getOutputPath()) : null;
            this.status = record.getStatus();
            this.percent = record.getPercent();
            this.stage = record.getStage();
            this.message = record.getMessage();
            this.completedPath = record.getCompletedPath() != null ? Path.of(record.getCompletedPath()) : null;
            this.error = record.getError();
            this.logs.addAll(record.getLogs());
        }

        public String taskId() { return taskId; }
        public long createdAt() { return createdAt; }
        public String host() { return host; }
        public int itemCount() { return itemCount; }
        public Path outputPath() { return outputPath; }
        public String status() { return status; }
        public int percent() { return percent; }
        public String stage() { return stage; }
        public String message() { return message; }
        public Path completedPath() { return completedPath; }
        public String error() { return error; }

        public void markRunning(String stage, int percent, String message) {
            this.status = "RUNNING";
            this.stage = stage;
            this.percent = percent;
            this.message = message;
            addLog("[" + stage + "] " + message + " (" + percent + "%)");
            persist();
        }

        public void markCompleted(Path completedPath) {
            this.status = "DONE";
            this.stage = "DONE";
            this.percent = 100;
            this.message = "Report ready";
            this.completedPath = completedPath;
            addLog("Report ready: " + completedPath);
            persist();
        }

        public void markFailed(String error) {
            this.status = "FAILED";
            this.stage = "FAILED";
            this.error = error;
            this.message = error != null ? error : "Export failed";
            addLog("Export failed: " + this.message);
            persist();
        }

        public String detailText() {
            StringBuilder sb = new StringBuilder();
            sb.append("Created: ").append(TIME_FORMAT.format(new Date(createdAt))).append("\n");
            sb.append("Host: ").append(host).append("\n");
            sb.append("Items: ").append(itemCount).append("\n");
            sb.append("Status: ").append(status).append("\n");
            sb.append("Stage: ").append(stage).append("\n");
            sb.append("Progress: ").append(percent).append("%\n");
            sb.append("Target: ").append(outputPath != null ? outputPath.toAbsolutePath() : "-").append("\n");
            if (completedPath != null) {
                sb.append("Download: ").append(completedPath.toAbsolutePath()).append("\n");
            }
            if (error != null && !error.isBlank()) {
                sb.append("Error: ").append(error).append("\n");
            }
            sb.append("\nLogs:\n");
            for (String log : logs) {
                sb.append("- ").append(log).append("\n");
            }
            return sb.toString();
        }

        private void addLog(String log) {
            logs.add(TIME_FORMAT.format(new Date()) + " " + log);
        }

        private void persist() {
            if (historyService == null) {
                return;
            }
            ReportExportTaskRecord record = new ReportExportTaskRecord();
            record.setTaskId(taskId);
            record.setCreatedAt(createdAt);
            record.setUpdatedAt(System.currentTimeMillis());
            record.setHost(host);
            record.setItemCount(itemCount);
            record.setOutputPath(outputPath != null ? outputPath.toString() : null);
            record.setStatus(status);
            record.setPercent(percent);
            record.setStage(stage);
            record.setMessage(message);
            record.setCompletedPath(completedPath != null ? completedPath.toString() : null);
            record.setError(error);
            record.setLogs(logs);
            historyService.saveReportExportTask(record);
        }
    }

    private static final class ExportTaskTableModel extends AbstractTableModel {
        private final String[] columns = {"Time", "Status", "Progress", "Host", "Message"};
        private final List<ExportTaskHandle> rows = new ArrayList<>();

        void addTask(ExportTaskHandle handle) {
            rows.add(0, handle);
            fireTableDataChanged();
        }

        void addTaskSilently(ExportTaskHandle handle) {
            rows.add(handle);
        }

        void clear() {
            rows.clear();
        }

        int indexOf(ExportTaskHandle handle) {
            return rows.indexOf(handle);
        }

        int indexOfTaskId(String taskId) {
            if (taskId == null) {
                return -1;
            }
            for (int i = 0; i < rows.size(); i++) {
                ExportTaskHandle row = rows.get(i);
                if (row != null && taskId.equals(row.taskId())) {
                    return i;
                }
            }
            return -1;
        }

        ExportTaskHandle getRowAt(int row) {
            return row >= 0 && row < rows.size() ? rows.get(row) : null;
        }

        void refresh() {
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ExportTaskHandle row = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> TIME_FORMAT.format(new Date(row.createdAt()));
                case 1 -> row.status();
                case 2 -> row.percent() + "%";
                case 3 -> row.host();
                case 4 -> row.message();
                default -> "";
            };
        }
    }
}
