package com.aiburpcopilot.burp.ui;

import com.aiburpcopilot.core.config.ExternalResourcePaths;
import com.aiburpcopilot.utils.PluginLogger;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class ConfigStatusPanel extends JPanel {

    private final JTable fileTable;
    private final DefaultTableModel tableModel;
    private final JTextArea detailArea;
    private final JLabel statusLabel;
    private final PluginLogger pluginLog;

    private Runnable onReload;
    private String displayedRelativePath;

    public ConfigStatusPanel() {
        this.pluginLog = PluginLogger.getInstance();
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel topPanel = new JPanel(new BorderLayout());
        statusLabel = new JLabel("尚未选择配置目录。");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD));
        topPanel.add(statusLabel, BorderLayout.NORTH);

        String[] columns = {"资源类型", "路径", "状态", "大小"};
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
        bottomPanel.add(new JLabel("文件详情："), BorderLayout.NORTH);

        detailArea = new JTextArea(8, 60);
        detailArea.setEditable(false);
        detailArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane detailScroll = new JScrollPane(detailArea);
        bottomPanel.add(detailScroll, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton reloadAllBtn = new JButton("重新加载当前目录");
        reloadAllBtn.addActionListener(e -> reloadAll());
        JButton refreshBtn = new JButton("刷新状态");
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
        String selectedPath = selectedRelativePath();
        tableModel.setRowCount(0);
        List<Path> allFiles = new ArrayList<>();

        Path configDir = ExternalResourcePaths.homeDirOrNull();
        if (configDir == null) {
            statusLabel.setText("尚未选择配置目录，请先加载配置目录。");
            statusLabel.setForeground(Color.RED);
            return;
        }
        String validationError = ExternalResourcePaths.validateConfigDirectory(configDir);
        if (validationError != null) {
            statusLabel.setText("配置目录无效：" + validationError);
            statusLabel.setForeground(Color.RED);
            return;
        }
        if (!Files.exists(configDir)) {
            statusLabel.setText("配置目录不存在：" + configDir);
            statusLabel.setForeground(Color.RED);
            return;
        }

        statusLabel.setText("当前配置目录：" + configDir);
        statusLabel.setForeground(new Color(0, 100, 0));

        try {
            Files.walk(configDir, 3).forEach(path -> {
                if (Files.isRegularFile(path)) {
                    allFiles.add(path);
                }
            });
        } catch (Exception e) {
            pluginLog.warn(PluginLogger.Category.SYSTEM, "Config",
                    "遍历配置目录失败：" + e.getMessage());
        }

        for (Path file : allFiles) {
            String relativePath = configDir.relativize(file).toString().replace('\\', '/');
            String status = Files.isReadable(file) ? "已加载" : "错误";
            String size = "";
            try {
                long bytes = Files.size(file);
                size = bytes < 1024 ? bytes + " B" : String.format("%.1f KB", bytes / 1024.0);
                if (bytes == 0) {
                    status = "空文件";
                }
            } catch (Exception ignored) {
            }

            String resourceType = "未知";
            if (relativePath.endsWith("application.yml")) {
                resourceType = "应用配置";
            } else if (relativePath.startsWith("prompts/")) {
                resourceType = "提示词：" + relativePath.substring("prompts/".length());
            } else if (relativePath.startsWith("rules/payloads/")) {
                resourceType = "Payload 规则：" + relativePath.substring("rules/payloads/".length());
            } else if (relativePath.startsWith("rules/")) {
                resourceType = "规则：" + relativePath.substring("rules/".length());
            }

            tableModel.addRow(new Object[]{resourceType, relativePath, status, size});
        }

        if (allFiles.isEmpty()) {
            tableModel.addRow(new Object[]{
                    "未发现配置文件",
                    "请将配置文件放入 " + configDir,
                    "空",
                    ""
            });
        }
        restoreSelection(selectedPath);
        if (fileTable.getSelectedRow() < 0) {
            if (selectedPath == null) {
                detailArea.setText("");
            } else {
                displayedRelativePath = null;
                detailArea.setText("");
            }
        }
    }

    private void reloadAll() {
        if (ExternalResourcePaths.homeDirOrNull() == null) {
            JOptionPane.showMessageDialog(this,
                    "请先选择配置目录。",
                    "未选择配置目录",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (onReload != null) {
            onReload.run();
        }

        refreshFileList();
        pluginLog.info(PluginLogger.Category.SYSTEM, "Config",
                "已重新加载配置目录：" + ExternalResourcePaths.homeDir());
        JOptionPane.showMessageDialog(this,
                "当前配置目录已重新加载。\n"
                        + "检测到 " + tableModel.getRowCount() + " 个文件。",
                "重新加载完成",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void showDetailForRow(int row) {
        if (row < 0) {
            displayedRelativePath = null;
            detailArea.setText("");
            return;
        }

        Path configDir = ExternalResourcePaths.homeDirOrNull();
        if (configDir == null) {
            detailArea.setText("尚未选择配置目录。");
            return;
        }

        Object pathObj = tableModel.getValueAt(row, 1);
        if (pathObj == null) {
            return;
        }

        String relativePath = pathObj.toString();
        Path fullPath = configDir.resolve(relativePath);
        boolean sameFile = relativePath.equals(displayedRelativePath);

        StringBuilder sb = new StringBuilder();
        sb.append("文件：").append(fullPath).append("\n");
        sb.append("存在：").append(Files.exists(fullPath)).append("\n");
        sb.append("可读：").append(Files.isReadable(fullPath)).append("\n");

        try {
            long bytes = Files.size(fullPath);
            sb.append("大小：").append(bytes).append(" 字节\n\n");
            String content = Files.readString(fullPath, StandardCharsets.UTF_8);
            if (content.length() > 2000) {
                content = content.substring(0, 2000) + "\n\n...（已截断，剩余 "
                        + (content.length() - 2000) + " 个字符）";
            }
            sb.append("内容预览：\n---\n");
            sb.append(content);
        } catch (Exception e) {
            sb.append("读取文件失败：").append(e.getMessage());
        }

        UiUtil.setTextPreservingView(detailArea, sb.toString(), sameFile);
        displayedRelativePath = relativePath;
    }

    private String selectedRelativePath() {
        int row = fileTable.getSelectedRow();
        if (row < 0) {
            return displayedRelativePath;
        }
        Object value = tableModel.getValueAt(row, 1);
        return value != null ? value.toString() : displayedRelativePath;
    }

    private void restoreSelection(String relativePath) {
        if (relativePath == null || relativePath.isBlank()) {
            return;
        }
        for (int row = 0; row < tableModel.getRowCount(); row++) {
            Object value = tableModel.getValueAt(row, 1);
            if (value != null && relativePath.equals(value.toString())) {
                fileTable.setRowSelectionInterval(row, row);
                fileTable.scrollRectToVisible(fileTable.getCellRect(row, 0, true));
                showDetailForRow(row);
                return;
            }
        }
    }
}
