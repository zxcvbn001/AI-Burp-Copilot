package com.aiburpcopilot.burp.ui;

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

public class ReportExportPanel extends JPanel {

    private static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("HH:mm:ss");

    private final ExportTaskTableModel tableModel;
    private final JTable table;
    private final JTextArea detailArea;
    private ExportTaskHandle displayedHandle;

    public ReportExportPanel() {
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
    }

    public ExportTaskHandle createTask(String host, int itemCount, Path outputPath) {
        ExportTaskHandle handle = new ExportTaskHandle(host, itemCount, outputPath);
        SwingUtilities.invokeLater(() -> {
            tableModel.addTask(handle);
            int row = tableModel.indexOf(handle);
            if (row >= 0) {
                table.setRowSelectionInterval(row, row);
            }
        });
        return handle;
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

    public static final class ExportTaskHandle {
        private final long createdAt = System.currentTimeMillis();
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

        private ExportTaskHandle(String host, int itemCount, Path outputPath) {
            this.host = host;
            this.itemCount = itemCount;
            this.outputPath = outputPath;
            addLog("Task created");
        }

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
        }

        public void markCompleted(Path completedPath) {
            this.status = "DONE";
            this.stage = "DONE";
            this.percent = 100;
            this.message = "Report ready";
            this.completedPath = completedPath;
            addLog("Report ready: " + completedPath);
        }

        public void markFailed(String error) {
            this.status = "FAILED";
            this.stage = "FAILED";
            this.error = error;
            this.message = error != null ? error : "Export failed";
            addLog("Export failed: " + this.message);
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
    }

    private static final class ExportTaskTableModel extends AbstractTableModel {
        private final String[] columns = {"Time", "Status", "Progress", "Host", "Message"};
        private final List<ExportTaskHandle> rows = new ArrayList<>();

        void addTask(ExportTaskHandle handle) {
            rows.add(0, handle);
            fireTableDataChanged();
        }

        int indexOf(ExportTaskHandle handle) {
            return rows.indexOf(handle);
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
