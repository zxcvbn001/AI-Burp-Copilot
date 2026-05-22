package com.aiburpcopilot.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.ai.impl.AIProviderFactory;
import com.aiburpcopilot.core.config.AppConfig;
import com.aiburpcopilot.core.config.ExternalResourcePaths;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.core.history.HistoryStorageProbe;
import com.aiburpcopilot.core.history.HistoryStorageStatus;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.core.pipeline.HistoryEventBus;
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
    private final IHistoryService historyService;
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
    private JTextField rateLimitField;

    private JCheckBox jsAnalysisEnabled;
    private JTextField jsAnalysisBaseUrlField;
    private JTextField jsAnalysisApiKeyField;
    private JTextField jsAnalysisApiKeyHeaderField;
    private JTextField jsAnalysisHealthPathField;
    private JTextField jsAnalysisAnalyzePathField;
    private JCheckBox jsAnalysisFastModeEnabled;
    private JTextField jsAnalysisModeField;
    private JCheckBox jsAnalysisSubmitAsyncEnabled;
    private JTextField jsAnalysisTaskPollIntervalField;
    private JTextField jsAnalysisTaskTimeoutField;
    private JTextField jsAnalysisConnectTimeoutField;
    private JTextField jsAnalysisReadTimeoutField;
    private JTextField jsAnalysisWriteTimeoutField;
    private JTextField jsAnalysisMaxReferencedScriptsField;
    private JTextField jsAnalysisMaxRecursiveDepthField;
    private JTextField jsAnalysisMaxVerifiedEndpointsField;
    private JCheckBox jsAnalysisAutoVerifyRecoveredApisEnabled;
    private JCheckBox jsAnalysisAutoAnalyzeVerifiedApisEnabled;
    private JCheckBox jsAnalysisAutoFetchReferencedScriptsEnabled;
    private JCheckBox jsRequestBuilderEnabled;
    private JCheckBox jsRequestBuilderAppendParamsEnabled;
    private JCheckBox jsRequestBuilderBuildBodyEnabled;
    private JTextField jsRequestBuilderBodyFormatField;
    private JTextField jsRequestBuilderPlaceholderField;
    private JCheckBox jsRequestBuilderCopyHeadersEnabled;
    private JCheckBox jsRequestBuilderCopyAuthHeadersEnabled;
    private JTextField jsRequestBuilderMaxParamsField;
    private JTextField jsRequestBuilderMaxHeadersField;

    private JTextField maxHistoryField;
    private JTextField cacheTtlField;
    private JTextField historyDbPathField;
    private JLabel activeConfigPathValueLabel;
    private JLabel historyStorageModeValueLabel;
    private JLabel historyStoragePathValueLabel;
    private JButton testHistoryDbButton;
    private JButton clearHistoryDbButton;

    private JCheckBox verificationEnabled;
    private JTextField verificationMaxRequestsField;
    private JTextField verificationTimeoutField;
    private JTextField verificationWhitelistField;
    private JTextField verificationMaxPayloadLengthField;
    private Map<String, JCheckBox> allowedInfluenceActionChecks;
    private Map<String, JCheckBox> allowedVerificationActionChecks;

    public SettingsPanel(IConfigService configService,
                         IHistoryService historyService,
                         MontoyaApi api,
                         Runnable reloadRuntimeResources) {
        this.configService = configService;
        this.historyService = historyService;
        this.api = api;
        this.reloadRuntimeResources = reloadRuntimeResources;

        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        add(createConfigPathPanel(), BorderLayout.NORTH);

        JTabbedPane settingsTabs = new JTabbedPane();
        UiUtil.applyBurpFont(settingsTabs);
        settingsTabs.addTab("基础设置", createBasicSettingsPanel());
        ConfigStatusPanel configStatusPanel = new ConfigStatusPanel();
        configStatusPanel.setOnReload(this::reloadSettingsFromDisk);
        settingsTabs.addTab("配置文件", configStatusPanel);
        add(settingsTabs, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveBtn = new JButton("保存并应用");
        saveBtn.addActionListener(e -> saveSettings());
        JButton resetBtn = new JButton("重置当前配置");
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
        JButton loadBtn = new JButton("加载配置目录");
        loadBtn.addActionListener(e -> loadConfigDirectory());
        panel.add(new JLabel("配置目录："), BorderLayout.WEST);
        panel.add(configPathField, BorderLayout.CENTER);
        panel.add(loadBtn, BorderLayout.EAST);
        return panel;
    }

    private JPanel createBasicSettingsPanel() {
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.add(wrapSection("大模型配置", createLLMPanel()));
        content.add(wrapSection("AI 通用参数", createAIPanel()));
        content.add(wrapSection("JS 静态分析", createJsAnalysisPanel()));
        content.add(wrapSection("扫描配置", createScanPanel()));
        content.add(wrapSection("存储配置", createStoragePanel()));
        content.add(wrapSection("验证安全策略", createVerificationPanel()));
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

        panel.add(new JLabel("服务商："), gbc);
        gbc.gridx = 1;
        providerCombo = new JComboBox<>(new String[]{"deepseek", "qwen", "openai"});
        providerCombo.setEditable(true);
        panel.add(providerCombo, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("模型："), gbc);
        gbc.gridx = 1;
        modelField = new JTextField(30);
        panel.add(modelField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("API 地址："), gbc);
        gbc.gridx = 1;
        apiUrlField = new JTextField(30);
        panel.add(apiUrlField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("API Key："), gbc);
        gbc.gridx = 1;
        apiKeyField = new JPasswordField(30);
        panel.add(apiKeyField, gbc);

        gbc.gridx = 1;
        gbc.gridy++;
        gbc.anchor = GridBagConstraints.WEST;
        testLlmButton = new JButton("测试 LLM");
        testLlmButton.addActionListener(e -> testLlmConfiguration());
        panel.add(testLlmButton, gbc);

        return panel;
    }

    private JPanel createScanPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseGbc();

        panel.add(new JLabel("跳过扩展名（逗号分隔）："), gbc);
        gbc.gridx = 1;
        skipExtensionsField = new JTextField(30);
        panel.add(skipExtensionsField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("跳过关键字（逗号分隔）："), gbc);
        gbc.gridx = 1;
        skipKeywordsField = new JTextField(30);
        panel.add(skipKeywordsField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("跳过状态码（逗号分隔）："), gbc);
        gbc.gridx = 1;
        skipStatusCodesField = new JTextField(30);
        panel.add(skipStatusCodesField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("响应体扫描："), gbc);
        gbc.gridx = 1;
        responseScanEnabled = new JCheckBox("启用");
        panel.add(responseScanEnabled, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("响应体最大扫描大小（字节）："), gbc);
        gbc.gridx = 1;
        responseMaxSizeField = new JTextField(20);
        panel.add(responseMaxSizeField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("静态文件最大扫描大小（KB）："), gbc);
        gbc.gridx = 1;
        staticScanMaxSizeField = new JTextField(20);
        panel.add(staticScanMaxSizeField, gbc);

        return panel;
    }

    private JPanel createAIPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseGbc();

        panel.add(new JLabel("最大 Token 数："), gbc);
        gbc.gridx = 1;
        maxTokensField = new JTextField(20);
        panel.add(maxTokensField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("超时时间（毫秒）："), gbc);
        gbc.gridx = 1;
        timeoutField = new JTextField(20);
        panel.add(timeoutField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("LLM 限速（次/分钟）："), gbc);
        gbc.gridx = 1;
        rateLimitField = new JTextField(20);
        panel.add(rateLimitField, gbc);

        return panel;
    }

    private JPanel createJsAnalysisPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseGbc();

        panel.add(new JLabel("启用："), gbc);
        gbc.gridx = 1;
        jsAnalysisEnabled = new JCheckBox("启用");
        panel.add(jsAnalysisEnabled, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("服务地址："), gbc);
        gbc.gridx = 1;
        jsAnalysisBaseUrlField = new JTextField(30);
        panel.add(jsAnalysisBaseUrlField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("API Key："), gbc);
        gbc.gridx = 1;
        jsAnalysisApiKeyField = new JTextField(30);
        panel.add(jsAnalysisApiKeyField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("API Key 请求头："), gbc);
        gbc.gridx = 1;
        jsAnalysisApiKeyHeaderField = new JTextField(30);
        panel.add(jsAnalysisApiKeyHeaderField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("健康检查路径："), gbc);
        gbc.gridx = 1;
        jsAnalysisHealthPathField = new JTextField(30);
        panel.add(jsAnalysisHealthPathField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("分析接口路径："), gbc);
        gbc.gridx = 1;
        jsAnalysisAnalyzePathField = new JTextField(30);
        panel.add(jsAnalysisAnalyzePathField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("快速模式："), gbc);
        gbc.gridx = 1;
        jsAnalysisFastModeEnabled = new JCheckBox("启用");
        panel.add(jsAnalysisFastModeEnabled, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("分析模式："), gbc);
        gbc.gridx = 1;
        jsAnalysisModeField = new JTextField(20);
        panel.add(jsAnalysisModeField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("异步提交："), gbc);
        gbc.gridx = 1;
        jsAnalysisSubmitAsyncEnabled = new JCheckBox("启用");
        panel.add(jsAnalysisSubmitAsyncEnabled, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("任务轮询间隔（毫秒）："), gbc);
        gbc.gridx = 1;
        jsAnalysisTaskPollIntervalField = new JTextField(20);
        panel.add(jsAnalysisTaskPollIntervalField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("任务超时（毫秒）："), gbc);
        gbc.gridx = 1;
        jsAnalysisTaskTimeoutField = new JTextField(20);
        panel.add(jsAnalysisTaskTimeoutField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("连接超时（毫秒）："), gbc);
        gbc.gridx = 1;
        jsAnalysisConnectTimeoutField = new JTextField(20);
        panel.add(jsAnalysisConnectTimeoutField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("读取超时（毫秒）："), gbc);
        gbc.gridx = 1;
        jsAnalysisReadTimeoutField = new JTextField(20);
        panel.add(jsAnalysisReadTimeoutField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("写入超时（毫秒）："), gbc);
        gbc.gridx = 1;
        jsAnalysisWriteTimeoutField = new JTextField(20);
        panel.add(jsAnalysisWriteTimeoutField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("最多引用脚本数："), gbc);
        gbc.gridx = 1;
        jsAnalysisMaxReferencedScriptsField = new JTextField(20);
        panel.add(jsAnalysisMaxReferencedScriptsField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("最大递归深度："), gbc);
        gbc.gridx = 1;
        jsAnalysisMaxRecursiveDepthField = new JTextField(20);
        panel.add(jsAnalysisMaxRecursiveDepthField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("最多验证接口数："), gbc);
        gbc.gridx = 1;
        jsAnalysisMaxVerifiedEndpointsField = new JTextField(20);
        panel.add(jsAnalysisMaxVerifiedEndpointsField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("自动验证恢复接口："), gbc);
        gbc.gridx = 1;
        jsAnalysisAutoVerifyRecoveredApisEnabled = new JCheckBox("启用");
        panel.add(jsAnalysisAutoVerifyRecoveredApisEnabled, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("自动分析已验证接口："), gbc);
        gbc.gridx = 1;
        jsAnalysisAutoAnalyzeVerifiedApisEnabled = new JCheckBox("启用");
        panel.add(jsAnalysisAutoAnalyzeVerifiedApisEnabled, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("自动抓取引用脚本："), gbc);
        gbc.gridx = 1;
        jsAnalysisAutoFetchReferencedScriptsEnabled = new JCheckBox("启用");
        panel.add(jsAnalysisAutoFetchReferencedScriptsEnabled, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("恢复接口请求构造："), gbc);
        gbc.gridx = 1;
        jsRequestBuilderEnabled = new JCheckBox("启用");
        panel.add(jsRequestBuilderEnabled, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("参数补到 Query："), gbc);
        gbc.gridx = 1;
        jsRequestBuilderAppendParamsEnabled = new JCheckBox("启用");
        panel.add(jsRequestBuilderAppendParamsEnabled, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("写操作自动构造 Body："), gbc);
        gbc.gridx = 1;
        jsRequestBuilderBuildBodyEnabled = new JCheckBox("启用");
        panel.add(jsRequestBuilderBuildBodyEnabled, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("默认 Body 格式："), gbc);
        gbc.gridx = 1;
        jsRequestBuilderBodyFormatField = new JTextField(20);
        panel.add(jsRequestBuilderBodyFormatField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("参数占位值："), gbc);
        gbc.gridx = 1;
        jsRequestBuilderPlaceholderField = new JTextField(20);
        panel.add(jsRequestBuilderPlaceholderField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("复制 JS Header："), gbc);
        gbc.gridx = 1;
        jsRequestBuilderCopyHeadersEnabled = new JCheckBox("启用");
        panel.add(jsRequestBuilderCopyHeadersEnabled, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("复制认证信号 Header："), gbc);
        gbc.gridx = 1;
        jsRequestBuilderCopyAuthHeadersEnabled = new JCheckBox("启用");
        panel.add(jsRequestBuilderCopyAuthHeadersEnabled, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("最多补充参数数："), gbc);
        gbc.gridx = 1;
        jsRequestBuilderMaxParamsField = new JTextField(20);
        panel.add(jsRequestBuilderMaxParamsField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("最多复制 Header 数："), gbc);
        gbc.gridx = 1;
        jsRequestBuilderMaxHeadersField = new JTextField(20);
        panel.add(jsRequestBuilderMaxHeadersField, gbc);

        return panel;
    }

    private JPanel createStoragePanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseGbc();

        panel.add(new JLabel("最大历史记录数："), gbc);
        gbc.gridx = 1;
        maxHistoryField = new JTextField(20);
        panel.add(maxHistoryField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("缓存有效期（秒）："), gbc);
        gbc.gridx = 1;
        cacheTtlField = new JTextField(20);
        panel.add(cacheTtlField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("历史数据库路径："), gbc);
        gbc.gridx = 1;
        historyDbPathField = new JTextField(30);
        panel.add(historyDbPathField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("当前配置文件："), gbc);
        gbc.gridx = 1;
        activeConfigPathValueLabel = new JLabel("-");
        panel.add(activeConfigPathValueLabel, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("当前存储模式："), gbc);
        gbc.gridx = 1;
        historyStorageModeValueLabel = new JLabel("-");
        panel.add(historyStorageModeValueLabel, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("当前存储路径："), gbc);
        gbc.gridx = 1;
        historyStoragePathValueLabel = new JLabel("-");
        panel.add(historyStoragePathValueLabel, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("数据库测试："), gbc);
        gbc.gridx = 1;
        testHistoryDbButton = new JButton("测试数据库连接");
        testHistoryDbButton.addActionListener(e -> testHistoryDatabaseConnection());
        panel.add(testHistoryDbButton, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("危险操作："), gbc);
        gbc.gridx = 1;
        clearHistoryDbButton = new JButton("一键清空历史数据库");
        clearHistoryDbButton.setToolTipText("删除当前历史数据库中的所有历史记录，不删除配置文件和规则文件");
        clearHistoryDbButton.addActionListener(e -> clearHistoryDatabase());
        panel.add(clearHistoryDbButton, gbc);

        return panel;
    }

    private JPanel createVerificationPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(5, 5, 5, 5));
        GridBagConstraints gbc = baseGbc();

        panel.add(new JLabel("启用验证："), gbc);
        gbc.gridx = 1;
        verificationEnabled = new JCheckBox("启用");
        panel.add(verificationEnabled, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("单接口最大请求数："), gbc);
        gbc.gridx = 1;
        verificationMaxRequestsField = new JTextField(20);
        panel.add(verificationMaxRequestsField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("请求超时（秒）："), gbc);
        gbc.gridx = 1;
        verificationTimeoutField = new JTextField(20);
        panel.add(verificationTimeoutField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("最大 Payload 长度："), gbc);
        gbc.gridx = 1;
        verificationMaxPayloadLengthField = new JTextField(20);
        panel.add(verificationMaxPayloadLengthField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("主机白名单（逗号分隔）："), gbc);
        gbc.gridx = 1;
        verificationWhitelistField = new JTextField(30);
        panel.add(verificationWhitelistField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("允许影响性判断的动作："), gbc);
        gbc.gridx = 1;
        allowedInfluenceActionChecks = createActionChecks();
        panel.add(createActionCheckPanel(allowedInfluenceActionChecks), gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        panel.add(new JLabel("允许漏洞验证的动作："), gbc);
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
                    "配置尚未加载：" + e.getMessage());
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
        rateLimitField.setText(String.valueOf(config.getAi().getRateLimitPerMinute()));

        jsAnalysisEnabled.setSelected(config.getJsAnalysis().isEnabled());
        jsAnalysisBaseUrlField.setText(config.getJsAnalysis().getBaseUrl());
        jsAnalysisApiKeyField.setText(config.getJsAnalysis().getApiKey());
        jsAnalysisApiKeyHeaderField.setText(config.getJsAnalysis().getApiKeyHeader());
        jsAnalysisHealthPathField.setText(config.getJsAnalysis().getHealthPath());
        jsAnalysisAnalyzePathField.setText(config.getJsAnalysis().getAnalyzePath());
        String jsMode = config.getJsAnalysis().getMode() != null
                ? config.getJsAnalysis().getMode().trim().toLowerCase()
                : "";
        if (!"fast".equals(jsMode) && !"full".equals(jsMode)) {
            jsMode = config.getJsAnalysis().isFastMode() ? "fast" : "full";
        }
        jsAnalysisModeField.setText(jsMode);
        jsAnalysisFastModeEnabled.setSelected("fast".equals(jsMode));
        jsAnalysisSubmitAsyncEnabled.setSelected(config.getJsAnalysis().isSubmitAsync());
        jsAnalysisTaskPollIntervalField.setText(String.valueOf(config.getJsAnalysis().getTaskPollIntervalMs()));
        jsAnalysisTaskTimeoutField.setText(String.valueOf(config.getJsAnalysis().getTaskTimeoutMs()));
        jsAnalysisConnectTimeoutField.setText(String.valueOf(config.getJsAnalysis().getConnectTimeoutMs()));
        jsAnalysisReadTimeoutField.setText(String.valueOf(config.getJsAnalysis().getReadTimeoutMs()));
        jsAnalysisWriteTimeoutField.setText(String.valueOf(config.getJsAnalysis().getWriteTimeoutMs()));
        jsAnalysisMaxReferencedScriptsField.setText(String.valueOf(config.getJsAnalysis().getMaxReferencedScripts()));
        jsAnalysisMaxRecursiveDepthField.setText(String.valueOf(config.getJsAnalysis().getMaxRecursiveDepth()));
        jsAnalysisMaxVerifiedEndpointsField.setText(String.valueOf(config.getJsAnalysis().getMaxVerifiedEndpointsPerScript()));
        jsAnalysisAutoVerifyRecoveredApisEnabled.setSelected(config.getJsAnalysis().isAutoVerifyRecoveredApis());
        jsAnalysisAutoAnalyzeVerifiedApisEnabled.setSelected(config.getJsAnalysis().isAutoAnalyzeVerifiedApis());
        jsAnalysisAutoFetchReferencedScriptsEnabled.setSelected(config.getJsAnalysis().isAutoFetchReferencedScripts());
        AppConfig.RecoveredRequestBuilderConfig requestBuilder = config.getJsAnalysis().getRequestBuilder();
        jsRequestBuilderEnabled.setSelected(requestBuilder.isEnabled());
        jsRequestBuilderAppendParamsEnabled.setSelected(requestBuilder.isAppendParamsToQuery());
        jsRequestBuilderBuildBodyEnabled.setSelected(requestBuilder.isBuildBodyForUnsafeMethods());
        jsRequestBuilderBodyFormatField.setText(requestBuilder.getDefaultBodyFormat());
        jsRequestBuilderPlaceholderField.setText(requestBuilder.getPlaceholderValue());
        jsRequestBuilderCopyHeadersEnabled.setSelected(requestBuilder.isCopyJsHeaders());
        jsRequestBuilderCopyAuthHeadersEnabled.setSelected(requestBuilder.isCopyAuthSignalHeaders());
        jsRequestBuilderMaxParamsField.setText(String.valueOf(requestBuilder.getMaxParams()));
        jsRequestBuilderMaxHeadersField.setText(String.valueOf(requestBuilder.getMaxHeaders()));

        maxHistoryField.setText(String.valueOf(config.getStorage().getMaxHistory()));
        cacheTtlField.setText(String.valueOf(config.getStorage().getCacheTtlSeconds()));
        historyDbPathField.setText(config.getStorage().getHistoryDbPath());
        refreshHistoryStorageStatus();

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
            config.getAi().setRateLimitPerMinute(Integer.parseInt(rateLimitField.getText().trim()));

            config.getJsAnalysis().setEnabled(jsAnalysisEnabled.isSelected());
            config.getJsAnalysis().setBaseUrl(jsAnalysisBaseUrlField.getText().trim());
            config.getJsAnalysis().setApiKey(jsAnalysisApiKeyField.getText().trim());
            config.getJsAnalysis().setApiKeyHeader(jsAnalysisApiKeyHeaderField.getText().trim());
            config.getJsAnalysis().setHealthPath(jsAnalysisHealthPathField.getText().trim());
            config.getJsAnalysis().setAnalyzePath(jsAnalysisAnalyzePathField.getText().trim());
            String requestedMode = jsAnalysisModeField.getText() != null
                    ? jsAnalysisModeField.getText().trim().toLowerCase()
                    : "";
            if (!"fast".equals(requestedMode) && !"full".equals(requestedMode)) {
                requestedMode = jsAnalysisFastModeEnabled.isSelected() ? "fast" : "full";
            }
            config.getJsAnalysis().setMode(requestedMode);
            config.getJsAnalysis().setFastMode("fast".equals(requestedMode));
            config.getJsAnalysis().setSubmitAsync(jsAnalysisSubmitAsyncEnabled.isSelected());
            config.getJsAnalysis().setTaskPollIntervalMs(Integer.parseInt(jsAnalysisTaskPollIntervalField.getText().trim()));
            config.getJsAnalysis().setTaskTimeoutMs(Integer.parseInt(jsAnalysisTaskTimeoutField.getText().trim()));
            config.getJsAnalysis().setConnectTimeoutMs(Integer.parseInt(jsAnalysisConnectTimeoutField.getText().trim()));
            config.getJsAnalysis().setReadTimeoutMs(Integer.parseInt(jsAnalysisReadTimeoutField.getText().trim()));
            config.getJsAnalysis().setWriteTimeoutMs(Integer.parseInt(jsAnalysisWriteTimeoutField.getText().trim()));
            config.getJsAnalysis().setMaxReferencedScripts(Integer.parseInt(jsAnalysisMaxReferencedScriptsField.getText().trim()));
            config.getJsAnalysis().setMaxRecursiveDepth(Integer.parseInt(jsAnalysisMaxRecursiveDepthField.getText().trim()));
            config.getJsAnalysis().setMaxVerifiedEndpointsPerScript(Integer.parseInt(jsAnalysisMaxVerifiedEndpointsField.getText().trim()));
            config.getJsAnalysis().setAutoVerifyRecoveredApis(jsAnalysisAutoVerifyRecoveredApisEnabled.isSelected());
            config.getJsAnalysis().setAutoAnalyzeVerifiedApis(jsAnalysisAutoAnalyzeVerifiedApisEnabled.isSelected());
            config.getJsAnalysis().setAutoFetchReferencedScripts(jsAnalysisAutoFetchReferencedScriptsEnabled.isSelected());
            AppConfig.RecoveredRequestBuilderConfig requestBuilder = config.getJsAnalysis().getRequestBuilder();
            requestBuilder.setEnabled(jsRequestBuilderEnabled.isSelected());
            requestBuilder.setAppendParamsToQuery(jsRequestBuilderAppendParamsEnabled.isSelected());
            requestBuilder.setBuildBodyForUnsafeMethods(jsRequestBuilderBuildBodyEnabled.isSelected());
            requestBuilder.setDefaultBodyFormat(jsRequestBuilderBodyFormatField.getText().trim());
            requestBuilder.setPlaceholderValue(jsRequestBuilderPlaceholderField.getText());
            requestBuilder.setCopyJsHeaders(jsRequestBuilderCopyHeadersEnabled.isSelected());
            requestBuilder.setCopyAuthSignalHeaders(jsRequestBuilderCopyAuthHeadersEnabled.isSelected());
            requestBuilder.setMaxParams(Integer.parseInt(jsRequestBuilderMaxParamsField.getText().trim()));
            requestBuilder.setMaxHeaders(Integer.parseInt(jsRequestBuilderMaxHeadersField.getText().trim()));
            config.getJsAnalysis().setRequestBuilder(requestBuilder);

            config.getStorage().setMaxHistory(Integer.parseInt(maxHistoryField.getText().trim()));
            config.getStorage().setCacheTtlSeconds(Integer.parseInt(cacheTtlField.getText().trim()));
            config.getStorage().setHistoryDbPath(historyDbPathField.getText().trim());

            config.getVerification().setEnabled(verificationEnabled.isSelected());
            config.getVerification().setMaxRequestsPerEndpoint(Integer.parseInt(verificationMaxRequestsField.getText().trim()));
            config.getVerification().setRequestTimeoutSeconds(Integer.parseInt(verificationTimeoutField.getText().trim()));
            config.getVerification().setWhitelist(parseStringList(verificationWhitelistField.getText()));
            config.getVerification().setMaxPayloadLength(Integer.parseInt(verificationMaxPayloadLengthField.getText().trim()));
            config.getVerification().setAllowedInfluenceActions(selectedActions(allowedInfluenceActionChecks));
            config.getVerification().setAllowedVerificationActions(selectedActions(allowedVerificationActionChecks));

            configService.updateConfig(config);
            configService.save();
            if (reloadRuntimeResources != null) {
                reloadRuntimeResources.run();
            }
            loadSettings();
            PluginLogger.getInstance().info(
                    PluginLogger.Category.SYSTEM,
                    "Settings",
                    "设置已从配置目录应用：" + configService.getConfigFilePath());
            JOptionPane.showMessageDialog(this,
                    "设置已保存并应用。",
                    "成功",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "保存设置失败：" + e.getMessage(),
                    "错误",
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
                        "请输入配置目录路径。",
                        "错误",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
            configService.reloadFrom(Paths.get(path));
            if (reloadRuntimeResources != null) {
                reloadRuntimeResources.run();
            }
            loadSettings();
            JOptionPane.showMessageDialog(this,
                    "已加载配置目录：" + Paths.get(path).toAbsolutePath().normalize(),
                    "成功",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            String detail = e.getCause() != null && e.getCause().getMessage() != null
                    ? "\n\n原因：" + e.getCause().getMessage()
                    : "";
            JOptionPane.showMessageDialog(this,
                    "加载配置目录失败：" + e.getMessage() + detail,
                    "错误",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void refreshHistoryStorageStatus() {
        if (historyStorageModeValueLabel == null || historyService == null) {
            return;
        }
        Path configPath = configService.getConfigFilePath();
        if (activeConfigPathValueLabel != null) {
            activeConfigPathValueLabel.setText(configPath != null ? configPath.toString() : "-");
        }
        HistoryStorageStatus status = historyService.getStorageStatus();
        historyStorageModeValueLabel.setText(status != null ? status.getDescription() : "-");
        historyStoragePathValueLabel.setText(
                status != null && status.getDatabasePath() != null && !status.getDatabasePath().isBlank()
                        ? status.getDatabasePath()
                        : "-");
    }

    private void testHistoryDatabaseConnection() {
        if (testHistoryDbButton != null) {
            testHistoryDbButton.setEnabled(false);
            testHistoryDbButton.setText("测试中...");
        }
        try {
            AppConfig config = configService.getConfig();
            String configuredPath = historyDbPathField != null ? historyDbPathField.getText().trim() : "";
            Path dbPath;
            if (configuredPath != null && !configuredPath.isBlank()) {
                dbPath = Paths.get(configuredPath).toAbsolutePath().normalize();
            } else {
                Path homeDir = ExternalResourcePaths.homeDirOrNull();
                if (homeDir == null) {
                    throw new IllegalStateException("尚未选择配置目录");
                }
                dbPath = homeDir.resolve("data").resolve("history.db").toAbsolutePath().normalize();
            }

            HistoryStorageProbe.ProbeResult result = HistoryStorageProbe.testSqlite(dbPath);
            if (result.success()) {
                JOptionPane.showMessageDialog(this,
                        "数据库连接成功。\n\n路径：\n" + dbPath + "\n\n" + result.message(),
                        "历史数据库测试成功",
                        JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this,
                        "数据库连接失败。\n\n路径：\n" + dbPath + "\n\n" + result.message(),
                        "历史数据库测试失败",
                        JOptionPane.ERROR_MESSAGE);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "无法测试数据库连接：\n" + e.getMessage(),
                    "历史数据库测试失败",
                    JOptionPane.ERROR_MESSAGE);
        } finally {
            if (testHistoryDbButton != null) {
                testHistoryDbButton.setEnabled(true);
                testHistoryDbButton.setText("测试数据库连接");
            }
        }
    }

    private void clearHistoryDatabase() {
        if (historyService == null) {
            JOptionPane.showMessageDialog(this,
                    "历史服务尚未初始化，无法清空数据库。",
                    "清空失败",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }
        HistoryStorageStatus status = historyService.getStorageStatus();
        int existing = historyService.size();
        String dbPath = status != null && status.getDatabasePath() != null && !status.getDatabasePath().isBlank()
                ? status.getDatabasePath()
                : "内存存储或未知路径";
        int confirm = JOptionPane.showConfirmDialog(this,
                "将删除当前历史数据库中的全部记录。\n\n"
                        + "存储模式：" + (status != null ? status.getDescription() : "-") + "\n"
                        + "数据库路径：" + dbPath + "\n"
                        + "当前记录数：" + existing + "\n\n"
                        + "此操作不可撤销，是否继续？",
                "确认清空历史数据库",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) {
            return;
        }
        try {
            if (clearHistoryDbButton != null) {
                clearHistoryDbButton.setEnabled(false);
                clearHistoryDbButton.setText("清空中...");
            }
            historyService.clear();
            HistoryEventBus.getInstance().fireHistoryCleared();
            refreshHistoryStorageStatus();
            JOptionPane.showMessageDialog(this,
                    "历史数据库已清空。\n\n删除记录数：" + existing,
                    "清空完成",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "清空历史数据库失败：\n" + e.getMessage(),
                    "清空失败",
                    JOptionPane.ERROR_MESSAGE);
        } finally {
            if (clearHistoryDbButton != null) {
                clearHistoryDbButton.setEnabled(true);
                clearHistoryDbButton.setText("一键清空历史数据库");
            }
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
                    "确认将当前 application.yml 重置为默认配置？",
                    "确认",
                    JOptionPane.YES_NO_OPTION);
            if (confirm != JOptionPane.YES_OPTION) {
                return;
            }
            configService.updateConfig(new AppConfig());
            configService.save();
            loadSettings();
            JOptionPane.showMessageDialog(this,
                    "当前配置文件已重置为默认值。",
                    "提示",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "重置配置失败：" + e.getMessage(),
                    "错误",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void testLlmConfiguration() {
        if (testLlmButton != null) {
            testLlmButton.setEnabled(false);
            testLlmButton.setText("测试中...");
        }

        try {
            AppConfig testConfig = buildTestConfigFromFields();
            IAIProvider provider = AIProviderFactory.create(new StaticConfigService(testConfig));
            if (!provider.isAvailable()) {
                throw new IllegalStateException("LLM 配置不完整，请检查 API Key 或鉴权设置。");
            }

            String providerName = provider.getProviderName();
            String prompt = "这是 AI Burp Copilot 的连通性测试。\n"
                    + "请只返回单行 JSON。\n"
                    + "{\"ok\":true,\"message\":\"pong\",\"provider\":\"" + providerName + "\"}";

            PluginLogger.getInstance().info(
                    PluginLogger.Category.LLM,
                    "Settings",
                    "正在执行 LLM 连通性测试，provider=" + providerName
                            + ", model=" + testConfig.getLlm().getModel()
                            + ", url=" + testConfig.getLlm().getApiUrl());

            provider.classifyEndpoint("", prompt).whenComplete((response, throwable) ->
                    SwingUtilities.invokeLater(() -> {
                        if (testLlmButton != null) {
                            testLlmButton.setEnabled(true);
                            testLlmButton.setText("测试 LLM");
                        }
                        if (throwable != null) {
                            PluginLogger.getInstance().error(
                                    PluginLogger.Category.LLM,
                                    "Settings",
                                    "LLM 连通性测试失败：" + throwable.getMessage(),
                                    throwable instanceof Exception ? (Exception) throwable : new RuntimeException(throwable));
                            JOptionPane.showMessageDialog(this,
                                    "LLM 测试失败：\n" + throwable.getMessage(),
                                    "LLM 测试失败",
                                    JOptionPane.ERROR_MESSAGE);
                            return;
                        }

                        String normalized = response != null ? response.trim() : "";
                        String pretty = prettyJsonOrRaw(normalized);
                        PluginLogger.getInstance().info(
                                PluginLogger.Category.LLM,
                                "Settings",
                                "LLM 连通性测试成功：" + normalized);
                        JOptionPane.showMessageDialog(this,
                                "LLM 测试成功。\n\n服务商：" + providerName
                                        + "\n模型：" + testConfig.getLlm().getModel()
                                        + "\nAPI 地址：" + testConfig.getLlm().getApiUrl()
                                        + "\n\n响应：\n" + pretty,
                                "LLM 测试成功",
                                JOptionPane.INFORMATION_MESSAGE);
                    }));
        } catch (Exception ex) {
            if (testLlmButton != null) {
                testLlmButton.setEnabled(true);
                testLlmButton.setText("测试 LLM");
            }
            JOptionPane.showMessageDialog(this,
                    "无法执行 LLM 测试：\n" + ex.getMessage(),
                    "LLM 测试失败",
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
        copy.getAi().setRateLimitPerMinute(parseIntOrDefault(rateLimitField.getText(), copy.getAi().getRateLimitPerMinute()));
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
            throw new UnsupportedOperationException("测试配置服务不支持保存");
        }

        @Override
        public AppConfig getConfig() {
            return config;
        }

        @Override
        public void updateConfig(AppConfig config) {
            throw new UnsupportedOperationException("测试配置服务为只读");
        }

        @Override
        public void addChangeListener(ConfigChangeListener listener) {
        }
    }
}
