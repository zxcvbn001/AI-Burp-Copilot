package com.aiburpcopilot.burp.ui;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.nio.charset.StandardCharsets;

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
}
