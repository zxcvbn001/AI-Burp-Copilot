package com.aiburpcopilot.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.core.discovery.ISiteDiscoveryService;
import com.aiburpcopilot.core.discovery.impl.InMemorySiteDiscoveryService;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.core.pipeline.HistoryEventBus;
import com.aiburpcopilot.core.verification.ManualVerificationService;
import com.aiburpcopilot.prompts.impl.FilePromptService;

import javax.swing.*;
import java.awt.*;

public class MainTab extends JPanel {

    private final HistoryPanel historyPanel;
    private final EndpointAnalysisPanel endpointPanel;
    private final ParameterInfluencePanel parameterInfluencePanel;
    private final VerificationPanel verificationPanel;
    private final StaticScanPanel staticScanPanel;
    private final SitePatternDiscoveryPanel sitePatternDiscoveryPanel;
    private final ConfirmedVulnerabilityPanel confirmedVulnerabilityPanel;
    private final ReportExportPanel reportExportPanel;
    private final LogPanel logPanel;
    private final SettingsPanel settingsPanel;
    private Timer refreshDebounceTimer;

    public MainTab(MontoyaApi api,
                   IHistoryService historyService,
                   IConfigService configService,
                   IAIProvider aiProvider,
                   ManualVerificationService manualVerificationService,
                   Runnable reloadRuntimeResources) {
        setLayout(new BorderLayout());

        this.historyPanel = new HistoryPanel(historyService);
        this.endpointPanel = new EndpointAnalysisPanel(api, historyService);
        this.parameterInfluencePanel = new ParameterInfluencePanel(
                api, historyService, manualVerificationService);
        this.verificationPanel = new VerificationPanel(api, historyService);
        this.staticScanPanel = new StaticScanPanel(api, historyService);
        ISiteDiscoveryService siteDiscoveryService = new InMemorySiteDiscoveryService(
                historyService,
                api,
                aiProvider,
                new FilePromptService(),
                configService);
        this.sitePatternDiscoveryPanel = new SitePatternDiscoveryPanel(api, siteDiscoveryService);
        this.reportExportPanel = new ReportExportPanel(historyService);
        this.confirmedVulnerabilityPanel = new ConfirmedVulnerabilityPanel(
                api, historyService, aiProvider, configService, reportExportPanel);
        this.logPanel = new LogPanel();
        this.settingsPanel = new SettingsPanel(configService, historyService, api, reloadRuntimeResources);

        JTabbedPane tabbedPane = new JTabbedPane();
        UiUtil.applyBurpFont(tabbedPane);
        tabbedPane.addTab("\u5386\u53f2", historyPanel);
        tabbedPane.addTab("Endpoint\u5206\u6790", endpointPanel);
        tabbedPane.addTab("\u53c2\u6570\u5206\u6790", parameterInfluencePanel);
        tabbedPane.addTab("\u6f0f\u6d1e\u9a8c\u8bc1\u8fc7\u7a0b", verificationPanel);
        tabbedPane.addTab("\u9759\u6001\u6587\u4ef6\u5206\u6790", staticScanPanel);
        tabbedPane.addTab("\u7ad9\u70b9\u89c4\u5f8b\u53d1\u73b0", sitePatternDiscoveryPanel);
        tabbedPane.addTab("\u6709\u6548\u6f0f\u6d1e", confirmedVulnerabilityPanel);
        tabbedPane.addTab("\u62a5\u544a\u5bfc\u51fa", reportExportPanel);
        tabbedPane.addTab("\u65e5\u5fd7", logPanel);
        tabbedPane.addTab("\u8bbe\u7f6e", settingsPanel);
        add(tabbedPane, BorderLayout.CENTER);

        HistoryEventBus.getInstance().subscribe(new HistoryEventBus.Listener() {
            @Override
            public void onHistoryAdded(HistoryEntry entry) {
                refreshAllPanels();
            }

            @Override
            public void onHistoryCleared() {
                refreshAllPanels();
            }

            @Override
            public void onRefreshNeeded() {
                refreshAllPanels();
            }
        });

        startFallbackRefresh();
    }

    public void refreshNow() {
        refreshAllPanels();
    }

    private void refreshAllPanels() {
        SwingUtilities.invokeLater(() -> {
            if (refreshDebounceTimer == null) {
                refreshDebounceTimer = new Timer(300, e -> doRefreshAllPanels());
                refreshDebounceTimer.setRepeats(false);
            }
            refreshDebounceTimer.restart();
        });
    }

    private void doRefreshAllPanels() {
        historyPanel.refresh();
        endpointPanel.refresh();
        parameterInfluencePanel.refresh();
        verificationPanel.refresh();
        staticScanPanel.refresh();
        sitePatternDiscoveryPanel.refresh();
        confirmedVulnerabilityPanel.refresh();
    }

    private void startFallbackRefresh() {
        Timer timer = new Timer(5000, e -> refreshAllPanels());
        timer.start();
    }
}
