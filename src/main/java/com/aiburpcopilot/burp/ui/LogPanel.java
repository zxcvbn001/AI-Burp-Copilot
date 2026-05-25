package com.aiburpcopilot.burp.ui;

import com.aiburpcopilot.utils.PluginLogger;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.StringJoiner;

public class LogPanel extends JPanel {

    public LogPanel() {
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        JTabbedPane tabs = new JTabbedPane();
        UiUtil.applyBurpFont(tabs);
        tabs.addTab("\u7cfb\u7edf\u65e5\u5fd7", new CategoryLogView(PluginLogger.Category.SYSTEM));
        tabs.addTab("LLM\u65e5\u5fd7", new CategoryLogView(PluginLogger.Category.LLM));
        tabs.addTab("\u9a8c\u8bc1\u65e5\u5fd7", new CategoryLogView(PluginLogger.Category.VERIFICATION));
        add(tabs, BorderLayout.CENTER);
    }

    private static class CategoryLogView extends JPanel {
        private static final int REFRESH_INTERVAL_MS = 500;

        private final PluginLogger.Category category;
        private final JTable table;
        private final LogTableModel tableModel;
        private final JComboBox<String> levelFilter;
        private final JCheckBox autoScrollCb;
        private final JCheckBox wrapDetailCb;
        private final JCheckBox pauseCb;
        private final JTextArea detailArea;
        private final JLabel detailMetaLabel;
        private final JLabel statusLabel;

        private int lastSeenCount = -1;
        private long lastSeenVersion = -1;
        private String displayedEntryKey;

        private CategoryLogView(PluginLogger.Category category) {
            this.category = category;
            setLayout(new BorderLayout());

            JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 5));
            toolbar.add(new JLabel("Level:"));
            levelFilter = new JComboBox<>(new String[]{"ALL", "INFO", "WARN", "ERROR"});
            levelFilter.addActionListener(e -> refresh());
            toolbar.add(levelFilter);

            autoScrollCb = new JCheckBox("Auto Scroll", true);
            toolbar.add(autoScrollCb);

            wrapDetailCb = new JCheckBox("Wrap Detail", true);
            wrapDetailCb.addActionListener(e -> applyDetailWrap());
            toolbar.add(wrapDetailCb);

            pauseCb = new JCheckBox("Pause", false);
            pauseCb.addActionListener(e -> {
                if (!pauseCb.isSelected()) {
                    lastSeenCount = -1;
                    refresh();
                }
            });
            toolbar.add(pauseCb);

            JButton clearBtn = new JButton("Clear");
            clearBtn.addActionListener(e -> {
                PluginLogger.getInstance().clear(category);
                lastSeenCount = -1;
                lastSeenVersion = -1;
                refresh();
            });
            toolbar.add(clearBtn);

            JButton copyDetailBtn = new JButton("Copy Detail");
            copyDetailBtn.addActionListener(e -> copyDetail());
            toolbar.add(copyDetailBtn);

            statusLabel = new JLabel(buildStatusText(0));
            toolbar.add(Box.createHorizontalStrut(20));
            toolbar.add(statusLabel);
            add(toolbar, BorderLayout.NORTH);

            tableModel = new LogTableModel();
            table = new JTable(tableModel);
            table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
            table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            UiUtil.applyBurpFont(table);

            TableColumnModel colModel = table.getColumnModel();
            UiUtil.setScaledColumnWidths(table, 90, 75, 190, 760);
            UiUtil.setScaledMinimumColumnWidths(table, 80, 70, 150, 300);
            for (int i = 0; i < 4; i++) {
                colModel.getColumn(i).setCellRenderer(new LevelCellRenderer());
            }

            table.getSelectionModel().addListSelectionListener(this::onSelectionChanged);
            table.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                    .put(KeyStroke.getKeyStroke("ctrl C"), "copy");
            table.getActionMap().put("copy", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    copySelectedRows();
                }
            });

            JScrollPane tableScroll = new JScrollPane(table);
            tableScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

            detailArea = UiUtil.createMessageArea();
            applyDetailWrap();
            detailMetaLabel = new JLabel("Select one row to view the full log.");
            UiUtil.applyBurpLabelFont(detailMetaLabel);
            JPanel detailPanel = new JPanel(new BorderLayout(0, 6));
            detailPanel.setBorder(new EmptyBorder(6, 0, 0, 0));
            detailPanel.add(detailMetaLabel, BorderLayout.NORTH);
            detailPanel.add(UiUtil.searchableTextPanel(detailArea), BorderLayout.CENTER);

            JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailPanel);
            splitPane.setResizeWeight(0.62);
            splitPane.setBorder(null);
            add(splitPane, BorderLayout.CENTER);

            Timer timer = new Timer(REFRESH_INTERVAL_MS, e -> {
                if (!pauseCb.isSelected()) {
                    long currentVersion = PluginLogger.getInstance().getVersion(category);
                    if (currentVersion != lastSeenVersion) {
                        refresh();
                    }
                }
            });
            timer.start();

            refresh();
        }

        private String buildStatusText(int count) {
            return switch (category) {
                case SYSTEM -> "\u7cfb\u7edf\u65e5\u5fd7: " + count;
                case LLM -> "LLM\u65e5\u5fd7: " + count;
                case VERIFICATION -> "\u9a8c\u8bc1\u65e5\u5fd7: " + count;
            };
        }

        private void onSelectionChanged(ListSelectionEvent event) {
            if (event.getValueIsAdjusting()) {
                return;
            }
            int row = table.getSelectedRow();
            if (row < 0) {
                displayedEntryKey = null;
                detailMetaLabel.setText("Select one row to view the full log.");
                detailArea.setText("");
                return;
            }
            PluginLogger.LogEntry entry = tableModel.getEntryAt(table.convertRowIndexToModel(row));
            if (entry == null) {
                displayedEntryKey = null;
                detailMetaLabel.setText("Select one row to view the full log.");
                detailArea.setText("");
                return;
            }
            String currentKey = entry.formatTimestamp() + "|" + entry.level().name() + "|" + LogTableModel.displaySource(entry);
            boolean sameEntry = currentKey.equals(displayedEntryKey);
            detailMetaLabel.setText(entry.formatTimestamp() + "  [" + entry.level().name() + "]  "
                    + LogTableModel.displaySource(entry));
            UiUtil.setTextPreservingView(detailArea, entry.message() != null ? entry.message() : "", sameEntry);
            displayedEntryKey = currentKey;
        }

        private void copySelectedRows() {
            int[] rows = table.getSelectedRows();
            if (rows.length == 0) {
                return;
            }
            StringJoiner joiner = new StringJoiner("\n");
            for (int row : rows) {
                PluginLogger.LogEntry entry = tableModel.getEntryAt(table.convertRowIndexToModel(row));
                if (entry != null) {
                    joiner.add(entry.formatTimestamp() + "\t"
                            + entry.level().name() + "\t"
                            + LogTableModel.displaySource(entry) + "\t"
                            + entry.message());
                }
            }
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(joiner.toString()), null);
        }

        private void copyDetail() {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(detailArea.getText()), null);
        }

        private void applyDetailWrap() {
            if (detailArea == null) {
                return;
            }
            boolean wrap = wrapDetailCb == null || wrapDetailCb.isSelected();
            detailArea.setLineWrap(wrap);
            detailArea.setWrapStyleWord(false);
        }

        private void refresh() {
            SwingUtilities.invokeLater(() -> {
                int selectedModelRow = table.getSelectedRow() >= 0
                        ? table.convertRowIndexToModel(table.getSelectedRow())
                        : -1;
                List<PluginLogger.LogEntry> entries = PluginLogger.getInstance()
                        .getEntries(parseLevelFilter(), category);
                lastSeenCount = PluginLogger.getInstance().getSize(category);
                lastSeenVersion = PluginLogger.getInstance().getVersion(category);
                statusLabel.setText(buildStatusText(lastSeenCount));
                tableModel.setEntries(entries);

                if (selectedModelRow >= 0 && selectedModelRow < entries.size()) {
                    int selectedViewRow = table.convertRowIndexToView(selectedModelRow);
                    table.getSelectionModel().setSelectionInterval(selectedViewRow, selectedViewRow);
                } else if (!entries.isEmpty() && autoScrollCb.isSelected()) {
                    int lastRow = entries.size() - 1;
                    table.getSelectionModel().setSelectionInterval(lastRow, lastRow);
                    table.scrollRectToVisible(table.getCellRect(lastRow, 0, true));
                } else {
                    onSelectionChanged(new ListSelectionEvent(table, -1, -1, false));
                }
            });
        }

        private Set<PluginLogger.Level> parseLevelFilter() {
            String selected = (String) levelFilter.getSelectedItem();
            if (selected == null || "ALL".equals(selected)) {
                return EnumSet.allOf(PluginLogger.Level.class);
            }
            return switch (selected) {
                case "INFO" -> EnumSet.of(PluginLogger.Level.INFO, PluginLogger.Level.WARN, PluginLogger.Level.ERROR);
                case "WARN" -> EnumSet.of(PluginLogger.Level.WARN, PluginLogger.Level.ERROR);
                case "ERROR" -> EnumSet.of(PluginLogger.Level.ERROR);
                default -> EnumSet.allOf(PluginLogger.Level.class);
            };
        }
    }

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
        public int getRowCount() {
            return entries.size();
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
            PluginLogger.LogEntry entry = entries.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> entry.formatTimestamp();
                case 1 -> entry.level().name();
                case 2 -> displaySource(entry);
                case 3 -> displayMessage(entry);
                default -> "";
            };
        }

        static String displaySource(PluginLogger.LogEntry entry) {
            if (entry.kind() == PluginLogger.EntryKind.LLM_REQUEST) {
                return entry.source() + " Request";
            }
            if (entry.kind() == PluginLogger.EntryKind.LLM_RESPONSE) {
                return entry.source() + " Response";
            }
            return entry.source();
        }

        private static String displayMessage(PluginLogger.LogEntry entry) {
            if (entry.title() != null && !entry.title().isBlank()) {
                return entry.title();
            }
            return entry.message();
        }
    }

    private static class LevelCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            LogTableModel model = (LogTableModel) table.getModel();
            PluginLogger.LogEntry entry = model.getEntryAt(row);
            if (!isSelected && entry != null) {
                component.setForeground(switch (entry.level()) {
                    case DEBUG -> new Color(128, 128, 128);
                    case INFO -> new Color(0, 0, 0);
                    case WARN -> new Color(200, 120, 0);
                    case ERROR -> new Color(200, 0, 0);
                });
            }
            return component;
        }
    }
}
