package com.aiburpcopilot.burp.ui;

import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.core.pipeline.HistoryEventBus;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;

final class UiUtil {

    private UiUtil() {
    }

    static Font burpTableFont() {
        Font font = UIManager.getFont("Table.font");
        return font != null ? font : new JLabel().getFont();
    }

    static Font burpMessageFont() {
        Font font = UIManager.getFont("TextArea.font");
        if (font == null) {
            font = new Font(Font.MONOSPACED, Font.PLAIN, 12);
        }
        return font;
    }

    static void applyBurpFont(JTable table) {
        table.setFont(burpTableFont());
        table.getTableHeader().setFont(burpTableFont());
        table.setRowHeight(Math.max(table.getRowHeight(), burpTableFont().getSize() + 8));
    }

    static int scaledWidth(int baseWidth) {
        Font font = burpTableFont();
        float scale = Math.max(1.0f, font.getSize2D() / 12.0f);
        return Math.round(baseWidth * scale);
    }

    static void setScaledColumnWidths(JTable table, int... baseWidths) {
        TableColumnModel columns = table.getColumnModel();
        for (int index = 0; index < baseWidths.length && index < columns.getColumnCount(); index++) {
            columns.getColumn(index).setPreferredWidth(scaledWidth(baseWidths[index]));
        }
    }

    static void setScaledMinimumColumnWidths(JTable table, int... baseWidths) {
        TableColumnModel columns = table.getColumnModel();
        for (int index = 0; index < baseWidths.length && index < columns.getColumnCount(); index++) {
            columns.getColumn(index).setMinWidth(scaledWidth(baseWidths[index]));
        }
    }

    static void applyBurpFont(JTabbedPane tabbedPane) {
        tabbedPane.setFont(burpTableFont());
    }

    static void applyBurpLabelFont(JComponent component) {
        component.setFont(burpTableFont());
    }

    static JTextArea createMessageArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(false);
        area.setFont(burpMessageFont());
        return area;
    }

    static JPanel searchableTextPanel(JTextArea area) {
        return searchableTextPanel((JTextComponent) area);
    }

    static JPanel searchableTextPanel(JTextComponent component) {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        JTextField searchField = new JTextField(26);
        JButton searchBtn = new JButton("搜索");
        JLabel hitLabel = new JLabel(" ");

        searchBar.add(new JLabel("包内搜索:"));
        searchBar.add(searchField);
        searchBar.add(searchBtn);
        searchBar.add(hitLabel);
        panel.add(searchBar, BorderLayout.NORTH);
        panel.add(new JScrollPane(component), BorderLayout.CENTER);

        Runnable search = () -> highlight(component, searchField.getText(), hitLabel);
        searchBtn.addActionListener(e -> search.run());
        searchField.addActionListener(e -> search.run());
        return panel;
    }

    static TextViewState captureTextViewState(JTextComponent component) {
        if (component == null) {
            return null;
        }
        JViewport viewport = (JViewport) SwingUtilities.getAncestorOfClass(JViewport.class, component);
        Point viewPosition = viewport != null ? viewport.getViewPosition() : null;
        return new TextViewState(component.getCaretPosition(), viewPosition != null ? new Point(viewPosition) : null);
    }

    static void restoreTextViewState(JTextComponent component, TextViewState state) {
        if (component == null) {
            return;
        }
        if (state == null) {
            resetTextView(component);
            return;
        }
        SwingUtilities.invokeLater(() -> {
            int length = component.getDocument() != null ? component.getDocument().getLength() : 0;
            int caret = Math.max(0, Math.min(state.caretPosition(), length));
            component.setCaretPosition(caret);
            JViewport viewport = (JViewport) SwingUtilities.getAncestorOfClass(JViewport.class, component);
            if (viewport != null && state.viewPosition() != null) {
                Point point = state.viewPosition();
                int maxX = Math.max(0, component.getWidth() - viewport.getWidth());
                int maxY = Math.max(0, component.getHeight() - viewport.getHeight());
                viewport.setViewPosition(new Point(
                        Math.max(0, Math.min(point.x, maxX)),
                        Math.max(0, Math.min(point.y, maxY))));
            }
        });
    }

    static void setTextPreservingView(JTextComponent component, String text, boolean preserveView) {
        String safeText = text != null ? text : "";
        if (component != null && safeText.equals(component.getText())) {
            if (!preserveView) {
                resetTextView(component);
            }
            return;
        }
        TextViewState state = preserveView ? captureTextViewState(component) : null;
        component.setText(safeText);
        if (preserveView) {
            restoreTextViewState(component, state);
        } else {
            resetTextView(component);
        }
    }

    static void resetTextView(JTextComponent component) {
        if (component == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            component.setCaretPosition(0);
            JViewport viewport = (JViewport) SwingUtilities.getAncestorOfClass(JViewport.class, component);
            if (viewport != null) {
                viewport.setViewPosition(new Point(0, 0));
            }
        });
    }

    static void highlight(JTextComponent component, String needle, JLabel hitLabel) {
        component.getHighlighter().removeAllHighlights();
        if (needle == null || needle.isBlank()) {
            hitLabel.setText(" ");
            return;
        }

        String text = component.getText();
        String lowerText = text.toLowerCase();
        String lowerNeedle = needle.toLowerCase();
        int index = lowerText.indexOf(lowerNeedle);
        int hits = 0;
        while (index >= 0) {
            try {
                component.getHighlighter().addHighlight(
                        index,
                        index + needle.length(),
                        new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 230, 120)));
                if (hits == 0) {
                    component.setCaretPosition(index);
                }
            } catch (BadLocationException ignored) {
            }
            hits++;
            index = lowerText.indexOf(lowerNeedle, index + Math.max(1, needle.length()));
        }
        hitLabel.setText("命中: " + hits);
    }

    static String bytesToText(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    static void installHistoryDeleteMenu(JTable table,
                                         IHistoryService historyService,
                                         Supplier<HistoryEntry> selectedEntrySupplier,
                                         Runnable afterDelete) {
        if (table == null || historyService == null || selectedEntrySupplier == null) {
            return;
        }
        JPopupMenu menu = new JPopupMenu();
        JMenuItem deleteItem = new JMenuItem("删除选中记录");
        deleteItem.addActionListener(e -> {
            HistoryEntry entry = selectedEntrySupplier.get();
            if (entry == null || entry.getRequestId() == null || entry.getRequestId().isBlank()) {
                JOptionPane.showMessageDialog(table, "请先选择一条记录。", "删除记录", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            String message = "确认删除这条历史记录？\n\n"
                    + nullToEmpty(entry.getMethod()) + " " + nullToEmpty(entry.getUrl())
                    + "\nrequestId=" + entry.getRequestId();
            int confirm = JOptionPane.showConfirmDialog(
                    table,
                    message,
                    "确认删除",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) {
                return;
            }
            try {
                boolean deleted = historyService.deleteById(entry.getRequestId());
                if (!deleted) {
                    JOptionPane.showMessageDialog(table, "未找到对应记录，可能已经被删除。", "删除记录", JOptionPane.INFORMATION_MESSAGE);
                }
                HistoryEventBus.getInstance().fireRefreshNeeded();
                if (afterDelete != null) {
                    afterDelete.run();
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(
                        table,
                        "删除失败：" + ex.getMessage(),
                        "删除记录",
                        JOptionPane.ERROR_MESSAGE);
            }
        });
        menu.add(deleteItem);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                maybeShowPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                maybeShowPopup(e);
            }

            private void maybeShowPopup(MouseEvent e) {
                if (!e.isPopupTrigger()) {
                    return;
                }
                int row = table.rowAtPoint(e.getPoint());
                if (row >= 0 && row < table.getRowCount()) {
                    table.setRowSelectionInterval(row, row);
                    deleteItem.setEnabled(true);
                } else {
                    deleteItem.setEnabled(false);
                }
                menu.show(e.getComponent(), e.getX(), e.getY());
            }
        });
    }

    private static String nullToEmpty(Object value) {
        return value != null ? String.valueOf(value) : "";
    }

    static final class TextViewState {
        private final int caretPosition;
        private final Point viewPosition;

        private TextViewState(int caretPosition, Point viewPosition) {
            this.caretPosition = caretPosition;
            this.viewPosition = viewPosition;
        }

        int caretPosition() {
            return caretPosition;
        }

        Point viewPosition() {
            return viewPosition;
        }
    }
}
