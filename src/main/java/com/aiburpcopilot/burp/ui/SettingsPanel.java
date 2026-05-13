package com.aiburpcopilot.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.aiburpcopilot.core.config.AppConfig;
import com.aiburpcopilot.core.config.IConfigService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.nio.file.Paths;

/**
 * 璁剧疆闈㈡澘銆? * <p>
 * 鎻愪緵鎻掍欢鎵€鏈夐厤缃」鐨?UI 缂栬緫鐣岄潰銆? * 淇敼鍚庝細鑷姩淇濆瓨鍒?YAML 閰嶇疆鏂囦欢骞剁珛鍗崇敓鏁堛€? */
public class SettingsPanel extends JPanel {

    private final IConfigService configService;
    private final MontoyaApi api;
    private JTextField configPathField;

    // LLM Settings
    private JTextField apiKeyField;
    private JTextField modelField;
    private JTextField apiUrlField;
    private JTextField providerField;

    // Scan Settings
    private JTextField skipExtensionsField;
    private JTextField skipKeywordsField;
    private JTextField skipStatusCodesField;
    private JCheckBox responseScanEnabled;
    private JTextField responseMaxSizeField;
    private JTextField staticScanMaxSizeField;

    // AI Settings
    private JTextField maxTokensField;
    private JTextField timeoutField;

    // Storage Settings
    private JTextField maxHistoryField;
    private JTextField cacheTtlField;

    // Verification Settings
    private JCheckBox verificationEnabled;
    private JTextField verificationMaxRequestsField;
    private JTextField verificationTimeoutField;
    private JTextField verificationWhitelistField;
    private JTextField verificationMaxPayloadLengthField;

    public SettingsPanel(IConfigService configService, MontoyaApi api) {
        this.configService = configService;
        this.api = api;

        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel configPathPanel = createConfigPathPanel();
        add(configPathPanel, BorderLayout.NORTH);

        JTabbedPane settingsTabs = new JTabbedPane();
        UiUtil.applyBurpFont(settingsTabs);
        settingsTabs.addTab("LLM", createLLMPanel());
        settingsTabs.addTab("Scan", createScanPanel());
        settingsTabs.addTab("AI", createAIPanel());
        settingsTabs.addTab("Storage", createStoragePanel());
        settingsTabs.addTab("Verification", createVerificationPanel());
        ConfigStatusPanel configStatusPanel = new ConfigStatusPanel();
        configStatusPanel.setOnReload(this::reloadSettingsFromDisk);
        settingsTabs.addTab("Config Files", configStatusPanel);

        add(settingsTabs, BorderLayout.CENTER);

        // 搴曢儴鎸夐挳
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveBtn = new JButton("Save & Apply");
        saveBtn.addActionListener(e -> saveSettings());
        JButton resetBtn = new JButton("Reset to Defaults");
        resetBtn.addActionListener(e -> resetSettings());
        buttonPanel.add(saveBtn);
        buttonPanel.add(resetBtn);

        add(buttonPanel, BorderLayout.SOUTH);

        loadSettings();
    }

    private JPanel createConfigPathPanel() {
        JPanel panel = new JPanel(new BorderLayout(6, 0));
        panel.setBorder(new EmptyBorder(0, 0, 8, 0));
        configPathField = new JTextField(60);
        JButton loadBtn = new JButton("Load Config Path");
        loadBtn.addActionListener(e -> loadConfigFromPath());
        panel.add(new JLabel("application.yml Path:"), BorderLayout.WEST);
        panel.add(configPathField, BorderLayout.CENTER);
        panel.add(loadBtn, BorderLayout.EAST);
        return panel;
    }

    // ---------- Panels ----------

    private JPanel createLLMPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0;
        gbc.gridy = 0;

        // Provider
        panel.add(new JLabel("Provider:"), gbc);
        gbc.gridx = 1;
        providerField = new JTextField(30);
        panel.add(providerField, gbc);

        // Model
        gbc.gridx = 0; gbc.gridy++;
        panel.add(new JLabel("Model:"), gbc);
        gbc.gridx = 1;
        modelField = new JTextField(30);
        panel.add(modelField, gbc);

        // API URL
        gbc.gridx = 0; gbc.gridy++;
        panel.add(new JLabel("API URL:"), gbc);
        gbc.gridx = 1;
        apiUrlField = new JTextField(30);
        panel.add(apiUrlField, gbc);

        // API Key
        gbc.gridx = 0; gbc.gridy++;
        panel.add(new JLabel("API Key:"), gbc);
        gbc.gridx = 1;
        apiKeyField = new JPasswordField(30);
        panel.add(apiKeyField, gbc);

        return panel;
    }

    private JPanel createScanPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0;
        gbc.gridy = 0;

        // Skip Extensions
        panel.add(new JLabel("Skip Extensions (comma separated):"), gbc);
        gbc.gridx = 1;
        skipExtensionsField = new JTextField(30);
        panel.add(skipExtensionsField, gbc);

        // Skip Keywords
        gbc.gridx = 0; gbc.gridy++;
        panel.add(new JLabel("Skip Keywords (comma separated):"), gbc);
        gbc.gridx = 1;
        skipKeywordsField = new JTextField(30);
        panel.add(skipKeywordsField, gbc);

        // Skip Status Codes
        gbc.gridx = 0; gbc.gridy++;
        panel.add(new JLabel("Skip Status Codes (comma separated):"), gbc);
        gbc.gridx = 1;
        skipStatusCodesField = new JTextField(30);
        skipStatusCodesField.setToolTipText("Example: 204, 304, 404");
        panel.add(skipStatusCodesField, gbc);

        // Response Body Scan
        gbc.gridx = 0; gbc.gridy++;
        panel.add(new JLabel("Response Body Scan:"), gbc);
        gbc.gridx = 1;
        responseScanEnabled = new JCheckBox("Enabled");
        panel.add(responseScanEnabled, gbc);

        // Response Max Size
        gbc.gridx = 0; gbc.gridy++;
        panel.add(new JLabel("Response Max Size (bytes):"), gbc);
        gbc.gridx = 1;
        responseMaxSizeField = new JTextField(20);
        panel.add(responseMaxSizeField, gbc);

        // Static Scan Max Size
        gbc.gridx = 0; gbc.gridy++;
        panel.add(new JLabel("Static Scan Max Size (bytes):"), gbc);
        gbc.gridx = 1;
        staticScanMaxSizeField = new JTextField(20);
        panel.add(staticScanMaxSizeField, gbc);

        return panel;
    }

    private JPanel createAIPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0;
        gbc.gridy = 0;

        panel.add(new JLabel("Max Tokens:"), gbc);
        gbc.gridx = 1;
        maxTokensField = new JTextField(20);
        panel.add(maxTokensField, gbc);

        gbc.gridx = 0; gbc.gridy++;
        panel.add(new JLabel("Timeout (ms):"), gbc);
        gbc.gridx = 1;
        timeoutField = new JTextField(20);
        panel.add(timeoutField, gbc);

        return panel;
    }

    private JPanel createStoragePanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0;
        gbc.gridy = 0;

        panel.add(new JLabel("Max History Records:"), gbc);
        gbc.gridx = 1;
        maxHistoryField = new JTextField(20);
        panel.add(maxHistoryField, gbc);

        gbc.gridx = 0; gbc.gridy++;
        panel.add(new JLabel("Cache TTL (seconds):"), gbc);
        gbc.gridx = 1;
        cacheTtlField = new JTextField(20);
        panel.add(cacheTtlField, gbc);

        return panel;
    }

    private JPanel createVerificationPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(5, 5, 5, 5));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0;
        gbc.gridy = 0;

        // Enabled
        panel.add(new JLabel("Enable Verification:"), gbc);
        gbc.gridx = 1;
        verificationEnabled = new JCheckBox("Enabled (off by default for safety)");
        panel.add(verificationEnabled, gbc);

        // Max Requests Per Endpoint
        gbc.gridx = 0; gbc.gridy++;
        panel.add(new JLabel("Max Requests Per Endpoint:"), gbc);
        gbc.gridx = 1;
        verificationMaxRequestsField = new JTextField(20);
        verificationMaxRequestsField.setToolTipText("Maximum verification requests per endpoint (default: 5)");
        panel.add(verificationMaxRequestsField, gbc);

        // Request Timeout
        gbc.gridx = 0; gbc.gridy++;
        panel.add(new JLabel("Request Timeout (seconds):"), gbc);
        gbc.gridx = 1;
        verificationTimeoutField = new JTextField(20);
        verificationTimeoutField.setToolTipText("Timeout for each verification request (default: 5)");
        panel.add(verificationTimeoutField, gbc);

        // Max Payload Length
        gbc.gridx = 0; gbc.gridy++;
        panel.add(new JLabel("Max Payload Length:"), gbc);
        gbc.gridx = 1;
        verificationMaxPayloadLengthField = new JTextField(20);
        verificationMaxPayloadLengthField.setToolTipText("Maximum payload string length (default: 128)");
        panel.add(verificationMaxPayloadLengthField, gbc);

        // Whitelist
        gbc.gridx = 0; gbc.gridy++;
        panel.add(new JLabel("Host Whitelist (comma separated):"), gbc);
        gbc.gridx = 1;
        verificationWhitelistField = new JTextField(30);
        verificationWhitelistField.setToolTipText("Only verify these hosts. Leave empty to allow all.");
        panel.add(verificationWhitelistField, gbc);

        // 鍗犱綅濉厖
        gbc.gridx = 0; gbc.gridy++;
        gbc.weighty = 1.0;
        panel.add(new JLabel(), gbc);

        return panel;
    }

    // ---------- Operations ----------

    private void loadSettings() {
        AppConfig config = configService.getConfig();
        if (configPathField != null) {
            configPathField.setText(String.valueOf(configService.getConfigFilePath()));
        }

        providerField.setText(config.getLlm().getProvider());
        modelField.setText(config.getLlm().getModel());
        apiUrlField.setText(config.getLlm().getApiUrl());
        apiKeyField.setText(config.getLlm().getApiKey());

        skipExtensionsField.setText(joinList(config.getScan().getSkipExtensions()));
        skipKeywordsField.setText(joinList(config.getScan().getSkipKeywords()));
        skipStatusCodesField.setText(joinIntegerList(config.getScan().getSkipStatusCodes()));
        responseScanEnabled.setSelected(config.getScan().getResponseBodyScan().isEnabled());
        responseMaxSizeField.setText(String.valueOf(config.getScan().getResponseBodyScan().getMaxSize()));
        staticScanMaxSizeField.setText(String.valueOf(config.getScan().getStaticScanMaxSize()));

        maxTokensField.setText(String.valueOf(config.getAi().getMaxTokens()));
        timeoutField.setText(String.valueOf(config.getAi().getTimeoutMs()));

        maxHistoryField.setText(String.valueOf(config.getStorage().getMaxHistory()));
        cacheTtlField.setText(String.valueOf(config.getStorage().getCacheTtlSeconds()));

        verificationEnabled.setSelected(config.getVerification().isEnabled());
        verificationMaxRequestsField.setText(String.valueOf(config.getVerification().getMaxRequestsPerEndpoint()));
        verificationTimeoutField.setText(String.valueOf(config.getVerification().getRequestTimeoutSeconds()));
        verificationWhitelistField.setText(joinList(config.getVerification().getWhitelist()));
        verificationMaxPayloadLengthField.setText(String.valueOf(config.getVerification().getMaxPayloadLength()));
    }

    private String joinList(java.util.List<String> values) {
        return values != null ? String.join(", ", values) : "";
    }

    private String joinIntegerList(java.util.List<Integer> values) {
        return values != null
                ? values.stream().map(String::valueOf).collect(java.util.stream.Collectors.joining(", "))
                : "";
    }

    private void saveSettings() {
        try {
            AppConfig config = configService.getConfig();

            config.getLlm().setProvider(providerField.getText().trim());
            config.getLlm().setModel(modelField.getText().trim());
            config.getLlm().setApiUrl(apiUrlField.getText().trim());
            config.getLlm().setApiKey(apiKeyField.getText().trim());

            config.getScan().setSkipExtensions(
                    java.util.Arrays.stream(skipExtensionsField.getText().split(","))
                            .map(String::trim)
                            .filter(s -> !s.isEmpty())
                            .toList());
            config.getScan().setSkipKeywords(
                    java.util.Arrays.stream(skipKeywordsField.getText().split(","))
                            .map(String::trim)
                            .filter(s -> !s.isEmpty())
                            .toList());
            config.getScan().setSkipStatusCodes(parseIntegerList(skipStatusCodesField.getText()));
            config.getScan().getResponseBodyScan().setEnabled(responseScanEnabled.isSelected());
            config.getScan().getResponseBodyScan().setMaxSize(Integer.parseInt(responseMaxSizeField.getText().trim()));
            config.getScan().setStaticScanMaxSize(Integer.parseInt(staticScanMaxSizeField.getText().trim()));

            config.getAi().setMaxTokens(Integer.parseInt(maxTokensField.getText().trim()));
            config.getAi().setTimeoutMs(Integer.parseInt(timeoutField.getText().trim()));

            config.getStorage().setMaxHistory(Integer.parseInt(maxHistoryField.getText().trim()));
            config.getStorage().setCacheTtlSeconds(Integer.parseInt(cacheTtlField.getText().trim()));

            config.getVerification().setEnabled(verificationEnabled.isSelected());
            config.getVerification().setMaxRequestsPerEndpoint(Integer.parseInt(verificationMaxRequestsField.getText().trim()));
            config.getVerification().setRequestTimeoutSeconds(Integer.parseInt(verificationTimeoutField.getText().trim()));
            config.getVerification().setWhitelist(
                    java.util.Arrays.stream(verificationWhitelistField.getText().split(","))
                            .map(String::trim)
                            .filter(s -> !s.isEmpty())
                            .toList());
            config.getVerification().setMaxPayloadLength(Integer.parseInt(verificationMaxPayloadLengthField.getText().trim()));

            configService.updateConfig(config);
            configService.save();

            JOptionPane.showMessageDialog(this,
                    "Settings saved successfully!", "Success",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this,
                    "Invalid number format: " + e.getMessage(), "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void reloadSettingsFromDisk() {
        configService.reload();
        loadSettings();
    }

    private void loadConfigFromPath() {
        try {
            String path = configPathField.getText() != null ? configPathField.getText().trim() : "";
            if (path.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                        "Please enter application.yml path.", "Error",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
            configService.reloadFrom(Paths.get(path));
            loadSettings();
            JOptionPane.showMessageDialog(this,
                    "Loaded config from: " + configService.getConfigFilePath(),
                    "Success", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "Failed to load config: " + e.getMessage(), "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private java.util.List<Integer> parseIntegerList(String raw) {
        if (raw == null || raw.isBlank()) {
            return java.util.List.of();
        }
        return java.util.Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(Integer::parseInt)
                .toList();
    }

    private void resetSettings() {
        int confirm = JOptionPane.showConfirmDialog(this,
                "Reset all settings to defaults?", "Confirm",
                JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            configService.updateConfig(new AppConfig());
            configService.save();
            loadSettings();
            JOptionPane.showMessageDialog(this,
                    "Settings reset to defaults.", "Info",
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }
}
