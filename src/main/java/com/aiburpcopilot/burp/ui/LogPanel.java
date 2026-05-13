package com.aiburpcopilot.burp.ui;

import com.aiburpcopilot.utils.PluginLogger;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.*;
import java.awt.*;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.StringJoiner;

/**
 * 插件诊断日志面板。
 * <p>
 * 实时展示插件运行日志，支持：
 * <ul>
 *   <li>四级过滤（ALL / INFO / WARN / ERROR）</li>
 *   <li>自动滚动到底部</li>
 *   <li>暂停/恢复 实时刷新</li>
 *   <li>清空日志</li>
 * </ul>
 * <p>
 * 刷新策略：使用 Swing Timer 定时从 PluginLogger 拉取最新日志，
 * 仅新增条目时更新表格，避免无变化时重建模型。
 */
public class LogPanel extends JPanel {

    private static final int REFRESH_INTERVAL_MS = 500;

    private final JTable table;
    private final LogTableModel tableModel;
    private final JComboBox<String> levelFilter;
    private final JCheckBox autoScrollCb;
    private final JCheckBox pauseCb;

    private int lastSeenCount = 0;

    public LogPanel() {
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        // ========== 工具栏 ==========
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 5));

        toolbar.add(new JLabel("Level:"));
        levelFilter = new JComboBox<>(new String[]{"ALL", "INFO", "WARN", "ERROR"});
        levelFilter.addActionListener(e -> refresh());
        toolbar.add(levelFilter);

        autoScrollCb = new JCheckBox("Auto Scroll", true);
        toolbar.add(autoScrollCb);

        pauseCb = new JCheckBox("Pause", false);
        pauseCb.addActionListener(e -> {
            if (!pauseCb.isSelected()) {
                lastSeenCount = 0;
                refresh();
            }
        });
        toolbar.add(pauseCb);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            PluginLogger.getInstance().clear();
            lastSeenCount = 0;
            refresh();
        });
        toolbar.add(clearBtn);

        // 状态标签
        JLabel statusLabel = new JLabel("Logs: 0");
        toolbar.add(Box.createHorizontalStrut(20));
        toolbar.add(statusLabel);

        add(toolbar, BorderLayout.NORTH);

        // ========== 表格 ==========
        tableModel = new LogTableModel();
        table = new JTable(tableModel);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        UiUtil.applyBurpFont(table);

        // 列宽
        TableColumnModel colModel = table.getColumnModel();
        UiUtil.setScaledColumnWidths(table, 90, 75, 190, 720);

        // 自定义渲染：按级别着色
        colModel.getColumn(0).setCellRenderer(new LevelCellRenderer());
        colModel.getColumn(1).setCellRenderer(new LevelCellRenderer());
        colModel.getColumn(2).setCellRenderer(new LevelCellRenderer());
        colModel.getColumn(3).setCellRenderer(new LevelCellRenderer());

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        add(scrollPane, BorderLayout.CENTER);

        // Ctrl+C 复制选中行
        table.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                .put(KeyStroke.getKeyStroke("ctrl C"), "copy");
        table.getActionMap().put("copy", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copySelectedRows();
            }
        });

        // ========== 定时刷新 ==========
        Timer timer = new Timer(REFRESH_INTERVAL_MS, e -> {
            if (!pauseCb.isSelected()) {
                int currentSize = PluginLogger.getInstance().getSize();
                if (currentSize != lastSeenCount) {
                    refresh();
                    statusLabel.setText("Logs: " + PluginLogger.getInstance().getSize());
                }
            }
        });
        timer.start();

        // 初始加载
        refresh();
    }

    private void copySelectedRows() {
        int[] rows = table.getSelectedRows();
        if (rows.length == 0) return;

        StringJoiner sj = new StringJoiner("\n");
        for (int row : rows) {
            PluginLogger.LogEntry entry = tableModel.getEntryAt(row);
            if (entry != null) {
                sj.add(entry.formatTimestamp() + "\t"
                        + entry.level().name() + "\t"
                        + entry.source() + "\t"
                        + entry.message());
            }
        }
        StringSelection sel = new StringSelection(sj.toString());
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
    }

    private void refresh() {
        SwingUtilities.invokeLater(() -> {
            Set<PluginLogger.Level> levels = parseLevelFilter();
            List<PluginLogger.LogEntry> entries = PluginLogger.getInstance().getEntries(levels);
            lastSeenCount = PluginLogger.getInstance().getSize();
            tableModel.setEntries(entries);

            // 自动滚动
            if (autoScrollCb.isSelected() && !entries.isEmpty()) {
                table.scrollRectToVisible(
                        table.getCellRect(entries.size() - 1, 0, true));
            }
        });
    }

    private Set<PluginLogger.Level> parseLevelFilter() {
        String selected = (String) levelFilter.getSelectedItem();
        if (selected == null || "ALL".equals(selected)) {
            return EnumSet.allOf(PluginLogger.Level.class);
        }
        return switch (selected) {
            case "INFO" -> EnumSet.of(PluginLogger.Level.INFO,
                    PluginLogger.Level.WARN, PluginLogger.Level.ERROR);
            case "WARN" -> EnumSet.of(PluginLogger.Level.WARN, PluginLogger.Level.ERROR);
            case "ERROR" -> EnumSet.of(PluginLogger.Level.ERROR);
            default -> EnumSet.allOf(PluginLogger.Level.class);
        };
    }

    // ========== Table Model ==========

    private static class LogTableModel extends AbstractTableModel {
        private final String[] columns = {"Time", "Level", "Source", "Message"};
        private List<PluginLogger.LogEntry> entries = List.of();

        void setEntries(List<PluginLogger.LogEntry> entries) {
            this.entries = entries;
            fireTableDataChanged();
        }

        PluginLogger.LogEntry getEntryAt(int row) {
            if (row >= 0 && row < entries.size()) {
                return entries.get(row);
            }
            return null;
        }

        @Override
        public int getColumnCount() { return columns.length; }

        @Override
        public int getRowCount() { return entries.size(); }

        @Override
        public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            PluginLogger.LogEntry e = entries.get(row);
            return switch (col) {
                case 0 -> e.formatTimestamp();
                case 1 -> e.level().name();
                case 2 -> e.source();
                case 3 -> e.message();
                default -> "";
            };
        }
    }

    // ========== Cell Renderer (颜色编码) ==========

    private static class LevelCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(
                JTable table, Object value, boolean isSelected,
                boolean hasFocus, int row, int column) {

            Component c = super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, column);

            LogTableModel model = (LogTableModel) table.getModel();
            PluginLogger.LogEntry entry = model.getEntryAt(row);

            if (!isSelected && entry != null) {
                c.setForeground(switch (entry.level()) {
                    case DEBUG -> new Color(128, 128, 128); // 灰色
                    case INFO  -> new Color(0, 0, 0);       // 黑色
                    case WARN  -> new Color(200, 120, 0);   // 橙色
                    case ERROR -> new Color(200, 0, 0);     // 红色
                });
            }

            // 禁止编辑
            if (c instanceof JTextField) {
                ((JTextField) c).setEditable(false);
            }

            return c;
        }
    }
}
