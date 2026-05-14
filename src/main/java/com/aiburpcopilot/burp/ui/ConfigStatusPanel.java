package com.aiburpcopilot.burp.ui;

import com.aiburpcopilot.core.config.ExternalResourcePaths;
import com.aiburpcopilot.utils.PluginLogger;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class ConfigStatusPanel extends JPanel {

    private final JTable fileTable;
    private final DefaultTableModel tableModel;
    private final JTextArea detailArea;
    private final JLabel statusLabel;
    private final PluginLogger pluginLog;

    private Runnable onReload;

    public ConfigStatusPanel() {
        this.pluginLog = PluginLogger.getInstance();
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel topPanel = new JPanel(new BorderLayout());
        statusLabel = new JLabel("No config directory selected.");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD));
        topPanel.add(statusLabel, BorderLayout.NORTH);

        String[] columns = {"Resource", "Path", "Status", "Size"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        fileTable = new JTable(tableModel);
        UiUtil.applyBurpFont(fileTable);
        UiUtil.setScaledColumnWidths(fileTable, 190, 460, 110, 100);
        fileTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        fileTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showDetailForRow(fileTable.getSelectedRow());
            }
        });

        JScrollPane tableScroll = new JScrollPane(fileTable);
        tableScroll.setPreferredSize(new Dimension(800, 200));
        add(tableScroll, BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.setBorder(new EmptyBorder(10, 0, 0, 0));
        bottomPanel.add(new JLabel("File Details:"), BorderLayout.NORTH);

        detailArea = new JTextArea(8, 60);
        detailArea.setEditable(false);
        detailArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane detailScroll = new JScrollPane(detailArea);
        bottomPanel.add(detailScroll, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton reloadAllBtn = new JButton("Reload Selected Directory");
        reloadAllBtn.addActionListener(e -> reloadAll());
        JButton refreshBtn = new JButton("Refresh Status");
        refreshBtn.addActionListener(e -> refreshFileList());
        buttonPanel.add(reloadAllBtn);
        buttonPanel.add(refreshBtn);

        bottomPanel.add(buttonPanel, BorderLayout.SOUTH);
        add(bottomPanel, BorderLayout.SOUTH);

        refreshFileList();
    }

    public void setOnReload(Runnable onReload) {
        this.onReload = onReload;
    }

    public void refreshFileList() {
        tableModel.setRowCount(0);
        detailArea.setText("");
        List<Path> allFiles = new ArrayList<>();

        Path configDir = ExternalResourcePaths.homeDirOrNull();
        if (configDir == null) {
            statusLabel.setText("No config directory selected. Please load a config directory first.");
            statusLabel.setForeground(Color.RED);
            return;
        }
        if (!Files.exists(configDir)) {
            statusLabel.setText("Configured directory not found: " + configDir);
            statusLabel.setForeground(Color.RED);
            return;
        }

        statusLabel.setText("Selected config directory: " + configDir);
        statusLabel.setForeground(new Color(0, 100, 0));

        try {
            Files.walk(configDir, 3).forEach(path -> {
                if (Files.isRegularFile(path)) {
                    allFiles.add(path);
                }
            });
        } catch (Exception e) {
            pluginLog.warn(PluginLogger.Category.SYSTEM, "Config",
                    "Failed to walk config dir: " + e.getMessage());
        }

        for (Path file : allFiles) {
            String relativePath = configDir.relativize(file).toString().replace('\\', '/');
            String status = Files.isReadable(file) ? "LOADED" : "ERROR";
            String size = "";
            try {
                long bytes = Files.size(file);
                size = bytes < 1024 ? bytes + " B" : String.format("%.1f KB", bytes / 1024.0);
                if (bytes == 0) {
                    status = "EMPTY";
                }
            } catch (Exception ignored) {
            }

            String resourceType = "Unknown";
            if (relativePath.endsWith("application.yml")) {
                resourceType = "Application Config";
            } else if (relativePath.startsWith("prompts/")) {
                resourceType = "Prompt: " + relativePath.substring("prompts/".length());
            } else if (relativePath.startsWith("rules/payloads/")) {
                resourceType = "Payload Rule: " + relativePath.substring("rules/payloads/".length());
            } else if (relativePath.equals("rules/static-resource-rules.yaml")) {
                resourceType = "Static Resource Rules";
            } else if (relativePath.startsWith("rules/")) {
                resourceType = "Rule: " + relativePath.substring("rules/".length());
            }

            tableModel.addRow(new Object[]{resourceType, relativePath, status, size});
        }

        if (allFiles.isEmpty()) {
            tableModel.addRow(new Object[]{
                    "No config files found",
                    "Place your config files in " + configDir,
                    "EMPTY",
                    ""
            });
        }
    }

    private void reloadAll() {
        if (ExternalResourcePaths.homeDirOrNull() == null) {
            JOptionPane.showMessageDialog(this,
                    "Please select a config directory first.",
                    "No Config Directory",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (onReload != null) {
            onReload.run();
        }

        refreshFileList();
        pluginLog.info(PluginLogger.Category.SYSTEM, "Config",
                "Reloaded config directory: " + ExternalResourcePaths.homeDir());
        JOptionPane.showMessageDialog(this,
                "Selected config directory reloaded.\n"
                        + tableModel.getRowCount() + " files detected.",
                "Reload Complete",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void showDetailForRow(int row) {
        if (row < 0) {
            detailArea.setText("");
            return;
        }

        Path configDir = ExternalResourcePaths.homeDirOrNull();
        if (configDir == null) {
            detailArea.setText("No config directory selected.");
            return;
        }

        Object pathObj = tableModel.getValueAt(row, 1);
        if (pathObj == null) {
            return;
        }

        String relativePath = pathObj.toString();
        Path fullPath = configDir.resolve(relativePath);

        StringBuilder sb = new StringBuilder();
        sb.append("File: ").append(fullPath).append("\n");
        sb.append("Exists: ").append(Files.exists(fullPath)).append("\n");
        sb.append("Readable: ").append(Files.isReadable(fullPath)).append("\n");

        try {
            long bytes = Files.size(fullPath);
            sb.append("Size: ").append(bytes).append(" bytes\n\n");
            String content = Files.readString(fullPath);
            if (content.length() > 2000) {
                content = content.substring(0, 2000) + "\n\n... (truncated, "
                        + (content.length() - 2000) + " more characters)";
            }
            sb.append("Content Preview:\n---\n");
            sb.append(content);
        } catch (Exception e) {
            sb.append("Error reading file: ").append(e.getMessage());
        }

        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }
}
