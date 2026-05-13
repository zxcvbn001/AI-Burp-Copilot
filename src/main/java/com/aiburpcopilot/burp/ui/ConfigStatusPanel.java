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

/**
 * 外部配置/资源文件状态面板。
 * <p>
 * 显示所有外部配置文件、规则、Prompt 的加载状态，
 * 支持查看详情和重新加载。
 */
public class ConfigStatusPanel extends JPanel {

    private static final Path CONFIG_DIR = ExternalResourcePaths.homeDir();

    private final JTable fileTable;
    private final DefaultTableModel tableModel;
    private final JTextArea detailArea;
    private final JLabel statusLabel;
    private final PluginLogger pluginLog;

    private Runnable onReload;

    public ConfigStatusPanel() {
        ExternalResourcePaths.initialize();
        this.pluginLog = PluginLogger.getInstance();
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        // 顶部：状态概览
        JPanel topPanel = new JPanel(new BorderLayout());
        statusLabel = new JLabel("Checking external config directory...");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD));
        topPanel.add(statusLabel, BorderLayout.NORTH);

        // 文件列表表格
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

        // 详情区域
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.setBorder(new EmptyBorder(10, 0, 0, 0));
        bottomPanel.add(new JLabel("File Details:"), BorderLayout.NORTH);

        detailArea = new JTextArea(8, 60);
        detailArea.setEditable(false);
        detailArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane detailScroll = new JScrollPane(detailArea);
        bottomPanel.add(detailScroll, BorderLayout.CENTER);

        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton reloadAllBtn = new JButton("Reload All Config Files");
        reloadAllBtn.addActionListener(e -> reloadAll());
        JButton refreshBtn = new JButton("Refresh Status");
        refreshBtn.addActionListener(e -> refreshFileList());
        buttonPanel.add(reloadAllBtn);
        buttonPanel.add(refreshBtn);

        bottomPanel.add(buttonPanel, BorderLayout.SOUTH);
        add(bottomPanel, BorderLayout.SOUTH);

        // 初始加载
        refreshFileList();
    }

    /**
     * 设置重新加载回调。
     */
    public void setOnReload(Runnable onReload) {
        this.onReload = onReload;
    }

    /**
     * 刷新文件列表。
     */
    public void refreshFileList() {
        tableModel.setRowCount(0);
        List<Path> allFiles = new ArrayList<>();

        Path configDir = CONFIG_DIR;
        if (!Files.exists(configDir)) {
            statusLabel.setText("External config directory not found: " + configDir);
            statusLabel.setForeground(Color.RED);
            return;
        }

        statusLabel.setText("External config directory: " + configDir);
        statusLabel.setForeground(new Color(0, 100, 0));

        // 收集所有配置文件
        try {
            Files.walk(configDir, 3).forEach(path -> {
                if (Files.isRegularFile(path)) {
                    allFiles.add(path);
                }
            });
        } catch (Exception e) {
            pluginLog.warn("Config", "Failed to walk config dir: " + e.getMessage());
        }

        for (Path file : allFiles) {
            String relativePath = configDir.relativize(file).toString().replace('\\', '/');
            String status = Files.isReadable(file) ? "LOADED" : "ERROR";
            String size = "";
            try {
                long bytes = Files.size(file);
                size = bytes < 1024 ? bytes + " B" : String.format("%.1f KB", bytes / 1024.0);
                // Check if file is empty
                if (bytes == 0) {
                    status = "EMPTY";
                }
            } catch (Exception ignored) {}

            // 判断资源类型
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

            tableModel.addRow(new Object[]{
                    resourceType,
                    relativePath,
                    status,
                    size
            });
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

    /**
     * 重新加载所有配置。
     */
    private void reloadAll() {
        int confirm = JOptionPane.showConfirmDialog(this,
                "Reload all external config files, rules, and prompts?\n"
                        + "Current settings will be replaced with file content.",
                "Confirm Reload", JOptionPane.YES_NO_OPTION);
        if (confirm != JOptionPane.YES_OPTION) return;

        if (onReload != null) {
            onReload.run();
        }

        // 刷新文件列表
        refreshFileList();

        pluginLog.info("Config", "All config files reloaded from: " + CONFIG_DIR);
        JOptionPane.showMessageDialog(this,
                "All config files reloaded successfully.\n"
                        + String.valueOf(tableModel.getRowCount()) + " files detected.",
                "Reload Complete", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * 显示选中文件的详情。
     */
    private void showDetailForRow(int row) {
        if (row < 0) {
            detailArea.setText("");
            return;
        }

        Object pathObj = tableModel.getValueAt(row, 1);
        if (pathObj == null) return;

        String relativePath = pathObj.toString();
        Path fullPath = CONFIG_DIR.resolve(relativePath);

        StringBuilder sb = new StringBuilder();
        sb.append("File: ").append(fullPath).append("\n");
        sb.append("Exists: ").append(Files.exists(fullPath)).append("\n");
        sb.append("Readable: ").append(Files.isReadable(fullPath)).append("\n");

        try {
            long bytes = Files.size(fullPath);
            sb.append("Size: ").append(bytes).append(" bytes\n\n");

            // Preview first 2000 chars
            String content = Files.readString(fullPath);
            if (content.length() > 2000) {
                content = content.substring(0, 2000) + "\n\n... (truncated, "
                        + (content.length() - 2000) + " more characters)";
            }
            sb.append("Content Preview:\n");
            sb.append("---\n");
            sb.append(content);
        } catch (Exception e) {
            sb.append("Error reading file: ").append(e.getMessage());
        }

        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }
}
