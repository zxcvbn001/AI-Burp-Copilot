package com.aiburpcopilot.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.ai.impl.AIProviderFactory;
import com.aiburpcopilot.core.config.AppConfig;
import com.aiburpcopilot.core.config.ExternalResourcePaths;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.utils.JsonUtil;
import com.aiburpcopilot.utils.PluginLogger;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class SettingsPanel extends JPanel {

    private final IConfigService configService;
    private final MontoyaApi api;
    private final Runnable reloadRuntimeResources;
    private JTextField configPathField;

    private JTextField apiKeyField;
    private JTextField modelField;
    private JTextField apiUrlField;
    private JComboBox<String> providerCombo;
    private JButton testLlmButton;

    private JTextField skipExtensionsField;
    private JTextField skipKeywordsField;
    private JTextField skipStatusCodesField;
    private JCheckBox responseScanEnabled;
    private JTextField responseMaxSizeField;
    private JTextField staticScanMaxSizeField;

    private JTextField maxTokensField;
    private JTextField timeoutField;

    private JTextField maxHistoryField;
    private JTextField cacheTtlField;

    private JCheckBox verificationEnabled;
    private JTextField verificationMaxRequestsField;
    private JTextField verificationTimeoutField;
    private JTextField verificationWhitelistField;
    private JTextField verificationMaxPayloadLengthField;
    private Map<String, JCheckBox> allowedInfluenceActionChecks;
    private Map<String, JCheckBox> allowedVerificationActionChecks;

    public SettingsPanel(IConfigService configService, MontoyaApi api, Runnable reloadRuntimeResources) {
        this.configService = configService;
        this.api = api;
        this.reloadRuntimeResources = reloadRuntimeResources;

        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        add(createConfigPathPanel(), BorderLayout.NORTH);

        JTabbedPane settingsTabs = new JTabbedPane();
        UiUtil.applyBurpFont(settingsTabs);
        settingsTabs.addTab("Basic", createBasicSettingsPanel());
        ConfigStatusPanel configStatusPanel = new ConfigStatusPanel();
        configStatusPanel.setOnReload(this::reloadSettingsFromDisk);
        settingsTabs.addTab("Config Files", configStatusPanel);
        add(settingsTabs, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveBtn = new JButton("Save & Apply");
        saveBtn.addActionListener(e -> saveSettings());
        JButton resetBtn = new JButton("Reset Current Config");
        resetBtn.addActionListener(e -> resetSettings());
        buttonPanel.add(saveBtn);
        buttonPanel.add(resetBtn);
        add(buttonPanel, BorderLayout.SOUTH);

        loadSettingsSafely();
    }

    private JPanel createConfigPathPanel() {
        JPanel panel = new JPanel(new BorderLayout(6, 0));
        panel.setBorder(new EmptyBorder(0, 0, 8, 0));
        configPathField = new JTextField(60);
        Path currentPath = configService.getConfigFilePath();
        configPathField.setText(currentPath != null && currentPath.getParent() != null
                ? currentPath.getParent().toString()
                : "");
        JButton loadBtn = new JButton("Load Config Directory");
        loadBtn.addActionListener(e -> loadConfigDirectory());
        panel.add(new JLabel("Config Directory:"), BorderLayout.WEST);
        panel.add(configPathField, BorderLayout.CENTER);
        panel.add(loadBtn, BorderLayout.EAST);
        return panel;
    }

    private JPanel createBasicSettingsPanel() {
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.add(wrapSection("LLM", createLLMPanel()));
        content.add(wrapSection("AI", createAIPanel()));
        content.add(wrapSection("Scan", createScanPanel()));
        content.add(wrapSection("Storage", createStoragePanel()));
        content.add(wrapSection("Verification Safety", createVerificationPanel()));
        JScrollPane scrollPane = new JScrollPane(content);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel wrapSection(String title, JPanel inner) {
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBorder(BorderFactory.createTitledBorder(title));
        wrapper.add(inner, BorderLayout.CENTER);
        return wrapper;
    }

    private JPanel createLLMPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseGbc();

        panel.add(new JLabel("Provider:"), gbc);
        gbc.gridx = 1;
        providerCombo = new JComboBox<>(new String[]{"deepseek", "qwen", "openai"});
        providerCombo.setEditable(true);
        panel.add(providerCombo, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("Model:"), gbc);
        gbc.gridx = 1;
        modelField = new JTextField(30);
        panel.add(modelField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("API URL:"), gbc);
        gbc.gridx = 1;
        apiUrlField = new JTextField(30);
        panel.add(apiUrlField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("API Key:"), gbc);
        gbc.gridx = 1;
        apiKeyField = new JPasswordField(30);
        panel.add(apiKeyField, gbc);

        gbc.gridx = 1;
        gbc.gridy++;
        gbc.anchor = GridBagConstraints.WEST;
        testLlmButton = new JButton("Test LLM");
        testLlmButton.addActionListener(e -> testLlmConfiguration());
        panel.add(testLlmButton, gbc);

        return panel;
    }

    private JPanel createScanPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseGbc();

        panel.add(new JLabel("Skip Extensions (comma separated):"), gbc);
        gbc.gridx = 1;
        skipExtensionsField = new JTextField(30);
        panel.add(skipExtensionsField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("Skip Keywords (comma separated):"), gbc);
        gbc.gridx = 1;
        skipKeywordsField = new JTextField(30);
        panel.add(skipKeywordsField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("Skip Status Codes (comma separated):"), gbc);
        gbc.gridx = 1;
        skipStatusCodesField = new JTextField(30);
        panel.add(skipStatusCodesField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("Response Body Scan:"), gbc);
        gbc.gridx = 1;
        responseScanEnabled = new JCheckBox("Enabled");
        panel.add(responseScanEnabled, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("Response Max Size (bytes):"), gbc);
        gbc.gridx = 1;
        responseMaxSizeField = new JTextField(20);
        panel.add(responseMaxSizeField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("Static Scan Max Size (bytes):"), gbc);
        gbc.gridx = 1;
        staticScanMaxSizeField = new JTextField(20);
        panel.add(staticScanMaxSizeField, gbc);

        return panel;
    }

    private JPanel createAIPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseGbc();

        panel.add(new JLabel("Max Tokens:"), gbc);
        gbc.gridx = 1;
        maxTokensField = new JTextField(20);
        panel.add(maxTokensField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("Timeout (ms):"), gbc);
        gbc.gridx = 1;
        timeoutField = new JTextField(20);
        panel.add(timeoutField, gbc);

        return panel;
    }

    private JPanel createStoragePanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseGbc();

        panel.add(new JLabel("Max History Records:"), gbc);
        gbc.gridx = 1;
        maxHistoryField = new JTextField(20);
        panel.add(maxHistoryField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("Cache TTL (seconds):"), gbc);
        gbc.gridx = 1;
        cacheTtlField = new JTextField(20);
        panel.add(cacheTtlField, gbc);

        return panel;
    }

    private JPanel createVerificationPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(5, 5, 5, 5));
        GridBagConstraints gbc = baseGbc();

        panel.add(new JLabel("Enable Verification:"), gbc);
        gbc.gridx = 1;
        verificationEnabled = new JCheckBox("Enabled");
        panel.add(verificationEnabled, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("Max Requests Per Endpoint:"), gbc);
        gbc.gridx = 1;
        verificationMaxRequestsField = new JTextField(20);
        panel.add(verificationMaxRequestsField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("Request Timeout (seconds):"), gbc);
        gbc.gridx = 1;
        verificationTimeoutField = new JTextField(20);
        panel.add(verificationTimeoutField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("Max Payload Length:"), gbc);
        gbc.gridx = 1;
        verificationMaxPayloadLengthField = new JTextField(20);
        panel.add(verificationMaxPayloadLengthField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("Host Whitelist (comma separated):"), gbc);
        gbc.gridx = 1;
        verificationWhitelistField = new JTextField(30);
        panel.add(verificationWhitelistField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("Allowed Influence Actions:"), gbc);
        gbc.gridx = 1;
        allowedInfluenceActionChecks = createActionChecks();
        panel.add(createActionCheckPanel(allowedInfluenceActionChecks), gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("Allowed Verification Actions:"), gbc);
        gbc.gridx = 1;
        allowedVerificationActionChecks = createActionChecks();
        panel.add(createActionCheckPanel(allowedVerificationActionChecks), gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        gbc.weighty = 1.0;
        panel.add(new JLabel(), gbc);

        return panel;
    }

    private GridBagConstraints baseGbc() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0;
        gbc.gridy = 0;
        return gbc;
    }

    private Map<String, JCheckBox> createActionChecks() {
        Map<String, JCheckBox> checks = new LinkedHashMap<>();
        for (String action : List.of("READ", "CREATE", "UPDATE", "DELETE", "AUTH", "UNKNOWN", "ALL")) {
            checks.put(action, new JCheckBox(action));
        }
        return checks;
    }

    private JPanel createActionCheckPanel(Map<String, JCheckBox> checks) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        for (JCheckBox checkBox : checks.values()) {
            panel.add(checkBox);
        }
        return panel;
    }

    private void loadSettingsSafely() {
        try {
            if (configService.getConfigFilePath() == null) {
                return;
            }
            loadSettings();
        } catch (Exception e) {
            PluginLogger.getInstance().warn(
                    PluginLogger.Category.SYSTEM,
                    "Settings",
                    "Config not loaded yet: " + e.getMessage());
        }
    }

    private void loadSettings() {
        AppConfig config = configService.getConfig();
        if (configPathField != null) {
            java.nio.file.Path configFile = configService.getConfigFilePath();
            configPathField.setText(configFile != null && configFile.getParent() != null
                    ? configFile.getParent().toString()
                    : "");
        }

        providerCombo.setSelectedItem(config.getLlm().getProvider());
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
        setActionChecks(allowedInfluenceActionChecks, config.getVerification().getAllowedInfluenceActions());
        setActionChecks(allowedVerificationActionChecks, config.getVerification().getAllowedVerificationActions());
    }

    private String joinList(List<String> values) {
        return values != null ? String.join(", ", values) : "";
    }

    private String joinIntegerList(List<Integer> values) {
        return values != null
                ? values.stream().map(String::valueOf).collect(Collectors.joining(", "))
                : "";
    }

    private void saveSettings() {
        try {
            AppConfig config = configService.getConfig();
            config.getLlm().setProvider(String.valueOf(providerCombo.getSelectedItem()).trim());
            config.getLlm().setModel(modelField.getText().trim());
            config.getLlm().setApiUrl(apiUrlField.getText().trim());
            config.getLlm().setApiKey(apiKeyField.getText().trim());

            config.getScan().setSkipExtensions(parseStringList(skipExtensionsField.getText()));
            config.getScan().setSkipKeywords(parseStringList(skipKeywordsField.getText()));
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
            config.getVerification().setWhitelist(parseStringList(verificationWhitelistField.getText()));
            config.getVerification().setMaxPayloadLength(Integer.parseInt(verificationMaxPayloadLengthField.getText().trim()));
            config.getVerification().setAllowedInfluenceActions(selectedActions(allowedInfluenceActionChecks));
            config.getVerification().setAllowedVerificationActions(selectedActions(allowedVerificationActionChecks));

            configService.updateConfig(config);
            configService.save();
            PluginLogger.getInstance().info(
                    PluginLogger.Category.SYSTEM,
                    "Settings",
                    "Settings applied from configured directory: " + configService.getConfigFilePath());
            JOptionPane.showMessageDialog(this,
                    "Settings saved successfully!",
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "Failed to save settings: " + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void reloadSettingsFromDisk() {
        configService.reload();
        if (reloadRuntimeResources != null) {
            reloadRuntimeResources.run();
        }
        loadSettings();
    }

    private void loadConfigDirectory() {
        try {
            String path = configPathField.getText() != null ? configPathField.getText().trim() : "";
            if (path.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                        "Please enter a config directory path.",
                        "Error",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
            configService.reloadFrom(Paths.get(path));
            if (reloadRuntimeResources != null) {
                reloadRuntimeResources.run();
            }
            loadSettings();
            JOptionPane.showMessageDialog(this,
                    "Loaded config directory: " + Paths.get(path).toAbsolutePath().normalize(),
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "Failed to load config directory: " + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private List<Integer> parseIntegerList(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(Integer::parseInt)
                .toList();
    }

    private void setActionChecks(Map<String, JCheckBox> checks, List<String> selected) {
        if (checks == null) {
            return;
        }
        Set<String> values = selected != null
                ? selected.stream().map(value -> value.toUpperCase(java.util.Locale.ROOT)).collect(Collectors.toSet())
                : Set.of();
        for (Map.Entry<String, JCheckBox> entry : checks.entrySet()) {
            entry.getValue().setSelected(values.contains(entry.getKey()));
        }
    }

    private List<String> selectedActions(Map<String, JCheckBox> checks) {
        if (checks == null) {
            return List.of();
        }
        return checks.entrySet().stream()
                .filter(entry -> entry.getValue().isSelected())
                .map(Map.Entry::getKey)
                .toList();
    }

    private List<String> parseStringList(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    private void resetSettings() {
        try {
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Reset current application.yml content to defaults?",
                    "Confirm",
                    JOptionPane.YES_NO_OPTION);
            if (confirm != JOptionPane.YES_OPTION) {
                return;
            }
            configService.updateConfig(new AppConfig());
            configService.save();
            loadSettings();
            JOptionPane.showMessageDialog(this,
                    "Current config file reset to defaults.",
                    "Info",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "Failed to reset config: " + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void testLlmConfiguration() {
        if (testLlmButton != null) {
            testLlmButton.setEnabled(false);
            testLlmButton.setText("Testing...");
        }

        try {
            AppConfig testConfig = buildTestConfigFromFields();
            IAIProvider provider = AIProviderFactory.create(new StaticConfigService(testConfig));
            if (!provider.isAvailable()) {
                throw new IllegalStateException("LLM configuration is incomplete. Check API Key or authorization settings.");
            }

            String providerName = provider.getProviderName();
            String prompt = "This is a connectivity test for AI Burp Copilot.\n"
                    + "Reply with a short single-line JSON only.\n"
                    + "{\"ok\":true,\"message\":\"pong\",\"provider\":\"" + providerName + "\"}";

            PluginLogger.getInstance().info(
                    PluginLogger.Category.LLM,
                    "Settings",
                    "Running LLM connectivity test with provider=" + providerName
                            + ", model=" + testConfig.getLlm().getModel()
                            + ", url=" + testConfig.getLlm().getApiUrl());

            provider.classifyEndpoint("", prompt).whenComplete((response, throwable) ->
                    SwingUtilities.invokeLater(() -> {
                        if (testLlmButton != null) {
                            testLlmButton.setEnabled(true);
                            testLlmButton.setText("Test LLM");
                        }
                        if (throwable != null) {
                            PluginLogger.getInstance().error(
                                    PluginLogger.Category.LLM,
                                    "Settings",
                                    "LLM connectivity test failed: " + throwable.getMessage(),
                                    throwable instanceof Exception ? (Exception) throwable : new RuntimeException(throwable));
                            JOptionPane.showMessageDialog(this,
                                    "LLM test failed:\n" + throwable.getMessage(),
                                    "LLM Test Failed",
                                    JOptionPane.ERROR_MESSAGE);
                            return;
                        }

                        String normalized = response != null ? response.trim() : "";
                        String pretty = prettyJsonOrRaw(normalized);
                        PluginLogger.getInstance().info(
                                PluginLogger.Category.LLM,
                                "Settings",
                                "LLM connectivity test succeeded: " + normalized);
                        JOptionPane.showMessageDialog(this,
                                "LLM test succeeded.\n\nProvider: " + providerName
                                        + "\nModel: " + testConfig.getLlm().getModel()
                                        + "\nAPI URL: " + testConfig.getLlm().getApiUrl()
                                        + "\n\nResponse:\n" + pretty,
                                "LLM Test Success",
                                JOptionPane.INFORMATION_MESSAGE);
                    }));
        } catch (Exception ex) {
            if (testLlmButton != null) {
                testLlmButton.setEnabled(true);
                testLlmButton.setText("Test LLM");
            }
            JOptionPane.showMessageDialog(this,
                    "Unable to run LLM test:\n" + ex.getMessage(),
                    "LLM Test Failed",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private AppConfig buildTestConfigFromFields() {
        AppConfig base = configService.getConfig();
        AppConfig copy = JsonUtil.fromJsonSafe(JsonUtil.toJson(base), AppConfig.class);
        if (copy == null) {
            copy = new AppConfig();
        }
        copy.getLlm().setProvider(String.valueOf(providerCombo.getSelectedItem()).trim());
        copy.getLlm().setModel(modelField.getText().trim());
        copy.getLlm().setApiUrl(apiUrlField.getText().trim());
        copy.getLlm().setApiKey(apiKeyField.getText().trim());
        copy.getAi().setMaxTokens(parseIntOrDefault(maxTokensField.getText(), copy.getAi().getMaxTokens()));
        copy.getAi().setTimeoutMs(parseIntOrDefault(timeoutField.getText(), copy.getAi().getTimeoutMs()));
        return copy;
    }

    private int parseIntOrDefault(String value, int defaultValue) {
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        return Integer.parseInt(value.trim());
    }

    private String prettyJsonOrRaw(String value) {
        if (value == null || value.isBlank()) {
            return "(empty response)";
        }
        Object parsed = JsonUtil.fromJsonSafe(value, Object.class);
        if (parsed == null) {
            return value;
        }
        return JsonUtil.toPrettyJson(parsed);
    }

    private static final class StaticConfigService implements IConfigService {
        private final AppConfig config;

        private StaticConfigService(AppConfig config) {
            this.config = config;
        }

        @Override
        public void reload() {
        }

        @Override
        public Path getConfigFilePath() {
            Path homeDir = ExternalResourcePaths.homeDirOrNull();
            return homeDir != null ? homeDir.resolve("application.yml") : null;
        }

        @Override
        public void save() {
            throw new UnsupportedOperationException("Test config service does not save");
        }

        @Override
        public AppConfig getConfig() {
            return config;
        }

        @Override
        public void updateConfig(AppConfig config) {
            throw new UnsupportedOperationException("Test config service is read-only");
        }

        @Override
        public void addChangeListener(ConfigChangeListener listener) {
        }
    }
}
