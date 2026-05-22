package com.aiburpcopilot.burp.extender;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.aiburpcopilot.burp.contextmenu.SendToAiBurpCopilotMenu;
import com.aiburpcopilot.burp.proxy.ProxyTrafficHandler;
import com.aiburpcopilot.burp.ui.MainTab;
import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.ai.impl.AIProviderFactory;
import com.aiburpcopilot.core.cache.ICacheService;
import com.aiburpcopilot.core.cache.impl.MemoryCacheService;
import com.aiburpcopilot.core.context.AnalysisStatus;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.RiskLevel;
import com.aiburpcopilot.core.config.AppConfig;
import com.aiburpcopilot.core.config.ExternalResourcePaths;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.core.config.impl.YAMLConfigService;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.HistoryStorageStatus;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.core.history.impl.InMemoryHistoryService;
import com.aiburpcopilot.core.history.impl.SqliteHistoryService;
import com.aiburpcopilot.core.pipeline.AIAnalysisStage;
import com.aiburpcopilot.core.pipeline.AnalysisPipeline;
import com.aiburpcopilot.core.pipeline.EndpointDedupStage;
import com.aiburpcopilot.core.pipeline.EndpointClassificationStage;
import com.aiburpcopilot.core.pipeline.HistoryEventBus;
import com.aiburpcopilot.core.pipeline.HistoryStage;
import com.aiburpcopilot.core.pipeline.IPipeline;
import com.aiburpcopilot.core.pipeline.RiskEvaluatorStage;
import com.aiburpcopilot.core.pipeline.StaticScanStage;
import com.aiburpcopilot.core.pipeline.StatusCodeFilterStage;
import com.aiburpcopilot.core.pipeline.WorkflowVerificationStage;
import com.aiburpcopilot.core.verification.ManualVerificationService;
import com.aiburpcopilot.core.verification.capability.RuleCapabilityCatalog;
import com.aiburpcopilot.core.verification.candidate.ICandidateExtractor;
import com.aiburpcopilot.core.verification.candidate.impl.CandidateExtractor;
import com.aiburpcopilot.core.verification.execution.IRequestExecutionEngine;
import com.aiburpcopilot.core.verification.execution.impl.DefaultRequestExecutionEngine;
import com.aiburpcopilot.core.verification.execution.impl.InMemoryResponseCapture;
import com.aiburpcopilot.core.verification.influence.IInfluenceDiffEngine;
import com.aiburpcopilot.core.verification.influence.IInfluenceScorer;
import com.aiburpcopilot.core.verification.influence.IMinimalMutationEngine;
import com.aiburpcopilot.core.verification.influence.IParameterProfiler;
import com.aiburpcopilot.core.verification.influence.IReplayEngine;
import com.aiburpcopilot.core.verification.influence.IStrategyApprovalEngine;
import com.aiburpcopilot.core.verification.influence.impl.InfluenceDiffEngine;
import com.aiburpcopilot.core.verification.influence.impl.InfluenceScorer;
import com.aiburpcopilot.core.verification.influence.impl.MinimalMutationEngine;
import com.aiburpcopilot.core.verification.influence.impl.ParameterProfiler;
import com.aiburpcopilot.core.verification.influence.impl.ReplayEngine;
import com.aiburpcopilot.core.verification.influence.impl.StrategyApprovalEngine;
import com.aiburpcopilot.core.verification.mutation.impl.ParameterMutatorRegistry;
import com.aiburpcopilot.core.verification.payload.IPayloadRuleEngine;
import com.aiburpcopilot.core.verification.payload.impl.YamlPayloadRuleEngine;
import com.aiburpcopilot.core.verification.policy.IPolicyEngine;
import com.aiburpcopilot.core.verification.policy.impl.PolicyEngine;
import com.aiburpcopilot.core.verification.rate_limit.HostRateLimiter;
import com.aiburpcopilot.core.verification.safety.VerificationGuard;
import com.aiburpcopilot.core.verification.workflow.IWorkflowEngine;
import com.aiburpcopilot.core.verification.workflow.impl.WorkflowStepFactory;
import com.aiburpcopilot.prompts.IPromptService;
import com.aiburpcopilot.prompts.impl.FilePromptService;
import com.aiburpcopilot.scanner.endpoint.EndpointClassifier;
import com.aiburpcopilot.scanner.endpoint.IEndpointClassifier;
import com.aiburpcopilot.scanner.staticresource.IStaticScanner;
import com.aiburpcopilot.scanner.staticresource.StaticResourceScanner;
import com.aiburpcopilot.utils.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Burp Montoya extension entry point.
 * <p>
 * The initializer wires the external configuration, prompt service, LLM
 * provider, passive analysis pipeline, verification engine, proxy hook and UI.
 */
public class AIBurpCopilotExtension implements BurpExtension {

    private static final Logger log = LoggerFactory.getLogger(AIBurpCopilotExtension.class);

    private final Object runtimeLock = new Object();
    private final DelegatingAIProvider delegatingAiProvider = new DelegatingAIProvider();
    private final DelegatingManualVerificationService delegatingManualVerificationService =
            new DelegatingManualVerificationService();
    private final DelegatingPipeline delegatingPipeline = new DelegatingPipeline();
    private final DelegatingHistoryService delegatingHistoryService = new DelegatingHistoryService();

    private MontoyaApi api;
    private IConfigService configService;
    private IHistoryService historyService;
    private MainTab mainTab;
    private ProxyTrafficHandler proxyHandler;
    private RuntimeBundle runtimeBundle;

    private static final class NoopManualVerificationService extends ManualVerificationService {
        private NoopManualVerificationService() {
            super(new ParameterProfiler(), null, null, null, null);
        }

        @Override
        public java.util.List<com.aiburpcopilot.core.verification.model.VerificationResult> runAfterManualInfluence(
                com.aiburpcopilot.core.history.HistoryEntry entry,
                com.aiburpcopilot.core.verification.model.VerificationResult influenceResult) {
            return java.util.List.of();
        }
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("AI Burp Copilot");
        log.info("Starting AI Burp Copilot v2...");
        registerRuntimeConfigCandidates(api);

        configService = new YAMLConfigService();
        delegatingHistoryService.setDelegate(createHistoryService());
        historyService = delegatingHistoryService;
        mainTab = new MainTab(
                api,
                historyService,
                configService,
                delegatingAiProvider,
                delegatingManualVerificationService,
                this::reloadRuntimeServices);
        api.userInterface().registerSuiteTab("AI Burp Copilot", mainTab);
        log.info("UI registered");

        try {
            proxyHandler = new ProxyTrafficHandler(delegatingPipeline);
            api.http().registerHttpHandler(proxyHandler);
            log.info("Proxy handler registered");

            api.userInterface().registerContextMenuItemsProvider(new SendToAiBurpCopilotMenu(delegatingPipeline));
            log.info("Context menu provider registered");

            api.extension().registerUnloadingHandler(() -> {
                log.info("Extension unloading, shutting down runtime...");
                synchronized (runtimeLock) {
                    delegatingPipeline.setDelegate(null);
                    delegatingAiProvider.setDelegate(null);
                    delegatingManualVerificationService.setDelegate(new NoopManualVerificationService());
                    delegatingHistoryService.setDelegate(new InMemoryHistoryService());
                    if (runtimeBundle != null) {
                        runtimeBundle.shutdown();
                        runtimeBundle = null;
                    }
                }
                log.info("Extension shutdown complete");
            });

            if (ExternalResourcePaths.homeDirOrNull() == null) {
                log.warn("No config directory selected yet; UI is available for manual configuration.");
                api.logging().logToOutput(
                        "AI Burp Copilot: please open the Settings tab and choose a config directory.");
                return;
            }
            reloadRuntimeServices();
            log.info("AI Burp Copilot v2 initialized successfully");
        } catch (Exception e) {
            log.error("Failed to initialize AI Burp Copilot", e);
            api.logging().logToError("Initialization failed: " + e.getMessage());
        }
    }

    private void registerRuntimeConfigCandidates(MontoyaApi api) {
        List<Path> roots = new ArrayList<>();

        addExtensionJarDirectory(api, roots);
        addBurpUserDirectories(roots);
        addPathIfPresent(roots, Path.of("").toAbsolutePath().normalize());

        ExternalResourcePaths.setRuntimeCandidateRoots(roots);
        if (!roots.isEmpty()) {
            log.info("Runtime config candidate roots registered: {}", roots);
        }
    }

    private void addExtensionJarDirectory(MontoyaApi api, List<Path> roots) {
        try {
            String filename = api.extension().filename();
            if (filename == null || filename.isBlank()) {
                return;
            }
            Path extensionPath = Path.of(filename).toAbsolutePath().normalize();
            Path extensionDir = Files.isDirectory(extensionPath) ? extensionPath : extensionPath.getParent();
            addPathIfPresent(roots, extensionDir);
        } catch (Exception e) {
            log.debug("Unable to resolve extension jar directory", e);
        }
    }

    private void addBurpUserDirectories(List<Path> roots) {
        String userHome = System.getProperty("user.home");
        if (userHome != null && !userHome.isBlank()) {
            Path home = Path.of(userHome).toAbsolutePath().normalize();
            addPathIfPresent(roots, home.resolve("BurpSuite"));
            addPathIfPresent(roots, home.resolve(".BurpSuite"));
            addPathIfPresent(roots, home.resolve(".burp"));
            addPathIfPresent(roots, home);
        }

        String appData = System.getenv("APPDATA");
        if (appData != null && !appData.isBlank()) {
            addPathIfPresent(roots, Path.of(appData).resolve("BurpSuite"));
        }

        String localAppData = System.getenv("LOCALAPPDATA");
        if (localAppData != null && !localAppData.isBlank()) {
            addPathIfPresent(roots, Path.of(localAppData).resolve("BurpSuite"));
        }
    }

    private void addPathIfPresent(List<Path> paths, Path path) {
        if (path == null) {
            return;
        }
        try {
            Path normalized = path.toAbsolutePath().normalize();
            if (!paths.contains(normalized)) {
                paths.add(normalized);
            }
        } catch (Exception ignored) {
        }
    }

    public IPipeline getPipeline() {
        return delegatingPipeline;
    }

    private IHistoryService createHistoryService() {
        if (ExternalResourcePaths.homeDirOrNull() == null) {
            log.info("Config directory not selected; using in-memory history until runtime is loaded.");
            return new InMemoryHistoryService();
        }
        try {
            return new SqliteHistoryService(loadStorageConfigSafely());
        } catch (Exception e) {
            log.error("Failed to initialize SQLite history service, fallback to memory history", e);
            if (api != null) {
                api.logging().logToError("AI Burp Copilot: SQLite history unavailable, fallback to in-memory history. " + e.getMessage());
            }
            return new InMemoryHistoryService();
        }
    }

    private AppConfig.StorageConfig loadStorageConfigSafely() {
        try {
            if (ExternalResourcePaths.homeDirOrNull() != null) {
                configService.reload();
                return configService.getConfig().getStorage();
            }
        } catch (Exception e) {
            log.warn("Failed to load storage config during bootstrap, fallback to default SQLite settings", e);
        }
        return null;
    }

    private void reloadRuntimeServices() {
        synchronized (runtimeLock) {
            try {
                configService.reload();
                IHistoryService newHistoryService = createHistoryService();
                delegatingHistoryService.setDelegate(newHistoryService);
                RuntimeBundle newBundle = createRuntimeBundle();
                RuntimeBundle oldBundle = runtimeBundle;
                runtimeBundle = newBundle;
                delegatingAiProvider.setDelegate(newBundle.aiProvider);
                delegatingManualVerificationService.setDelegate(newBundle.manualVerificationService);
                delegatingPipeline.setDelegate(newBundle.pipeline);
                mainTab.refreshNow();
                if (oldBundle != null) {
                    oldBundle.shutdown();
                }
                HistoryStorageStatus storageStatus = newHistoryService.getStorageStatus();
                String storageText = storageStatus != null && storageStatus.getDatabasePath() != null
                        ? storageStatus.getDatabasePath()
                        : storageStatus != null ? storageStatus.getDescription() : "-";
                log.info("Runtime services loaded from configured directory; history storage={}", storageText);
                api.logging().logToOutput("AI Burp Copilot: runtime services loaded successfully. History DB: "
                        + storageText);
            } catch (Exception e) {
                log.error("Failed to load runtime services", e);
                api.logging().logToError("Runtime load failed: " + e.getMessage());
            }
        }
    }

    private RuntimeBundle createRuntimeBundle() {
        IPromptService promptService = new FilePromptService();
        promptService.reload();
        log.info("Prompt service initialized");

        IAIProvider aiProvider = AIProviderFactory.create(configService);
        log.info("AI provider initialized: {}", aiProvider.getProviderName());

        ICacheService cacheService = new MemoryCacheService(
                configService.getConfig().getStorage().getMaxCacheEntries(),
                configService.getConfig().getStorage().getCacheTtlSeconds()
        );
        log.info("Cache service initialized");

        IEndpointClassifier endpointClassifier = new EndpointClassifier(
                aiProvider, promptService, cacheService, configService);
        IStaticScanner staticScanner = new StaticResourceScanner(
                aiProvider, promptService, cacheService, configService,
                historyService, endpointClassifier, api);
        log.info("Scanner components initialized");

        VerificationGuard verificationGuard = new VerificationGuard(
                configService.getConfig().getVerification());
        IPayloadRuleEngine payloadEngine = new YamlPayloadRuleEngine();
        ParameterMutatorRegistry mutatorRegistry = new ParameterMutatorRegistry();
        HostRateLimiter hostRateLimiter = new HostRateLimiter(
                Constants.VERIFICATION_HOST_MAX_CONCURRENCY);
        InMemoryResponseCapture responseCapture = new InMemoryResponseCapture();

        IRequestExecutionEngine executionEngine = new DefaultRequestExecutionEngine(
                api, hostRateLimiter, verificationGuard,
                responseCapture, mutatorRegistry);
        log.info("Verification components initialized (enabled: {})",
                verificationGuard.isVerificationEnabled());

        IParameterProfiler parameterProfiler = new ParameterProfiler();
        IMinimalMutationEngine minimalMutationEngine = new MinimalMutationEngine();
        IReplayEngine replayEngine = new ReplayEngine(verificationGuard, executionEngine);
        IInfluenceDiffEngine influenceDiffEngine = new InfluenceDiffEngine();
        IInfluenceScorer influenceScorer = new InfluenceScorer();
        IStrategyApprovalEngine strategyApprovalEngine = new StrategyApprovalEngine();
        IPolicyEngine policyEngine = new PolicyEngine();

        RuleCapabilityCatalog capabilityCatalog = new RuleCapabilityCatalog(
                null, payloadEngine);
        ICandidateExtractor candidateExtractor = new CandidateExtractor(capabilityCatalog);

        WorkflowStepFactory workflowStepFactory = new WorkflowStepFactory(
                replayEngine, minimalMutationEngine, influenceDiffEngine,
                influenceScorer, strategyApprovalEngine);
        workflowStepFactory.setPayloadRuleEngine(payloadEngine);
        workflowStepFactory.setAiProvider(aiProvider);
        workflowStepFactory.setConfigService(configService);
        workflowStepFactory.setPolicyEngine(policyEngine);
        workflowStepFactory.setMaxPayloadLength(verificationGuard.getMaxPayloadLength());
        IWorkflowEngine workflowEngine = workflowStepFactory.createEngine();

        AnalysisPipeline pipeline = new AnalysisPipeline();
        pipeline.registerStage(new HistoryStage(historyService));
        pipeline.registerStage(new EndpointDedupStage());
        pipeline.registerStage(new StatusCodeFilterStage(configService));
        pipeline.registerStage(new EndpointClassificationStage(endpointClassifier));
        pipeline.registerStage(new StaticScanStage(staticScanner, historyService));
        pipeline.registerStage(new AIAnalysisStage(
                aiProvider, promptService, cacheService, configService, capabilityCatalog));
        pipeline.registerStage(new RiskEvaluatorStage());
        pipeline.registerStage(new WorkflowVerificationStage(
                candidateExtractor, parameterProfiler, workflowEngine,
                policyEngine, replayEngine, verificationGuard));
        pipeline.registerStage(new HistoryStage(historyService, true));
        pipeline.start();
        log.info("Pipeline initialized with {} stages", pipeline.getStageCount());

        ManualVerificationService manualVerificationService = new ManualVerificationService(
                parameterProfiler, workflowEngine, policyEngine, replayEngine,
                verificationGuard);

        return new RuntimeBundle(aiProvider, manualVerificationService, pipeline, executionEngine);
    }

    private static final class RuntimeBundle {
        private final IAIProvider aiProvider;
        private final ManualVerificationService manualVerificationService;
        private final IPipeline pipeline;
        private final IRequestExecutionEngine executionEngine;

        private RuntimeBundle(IAIProvider aiProvider,
                              ManualVerificationService manualVerificationService,
                              IPipeline pipeline,
                              IRequestExecutionEngine executionEngine) {
            this.aiProvider = aiProvider;
            this.manualVerificationService = manualVerificationService;
            this.pipeline = pipeline;
            this.executionEngine = executionEngine;
        }

        private void shutdown() {
            try {
                if (pipeline != null) {
                    pipeline.shutdown();
                }
            } finally {
                if (executionEngine != null) {
                    executionEngine.shutdown();
                }
            }
        }
    }

    private static final class DelegatingHistoryService implements IHistoryService {
        private final IHistoryService fallback = new InMemoryHistoryService();
        private volatile IHistoryService delegate = fallback;

        private void setDelegate(IHistoryService delegate) {
            this.delegate = delegate != null ? delegate : fallback;
            HistoryEventBus.getInstance().fireRefreshNeeded();
        }

        private IHistoryService current() {
            return delegate != null ? delegate : fallback;
        }

        @Override
        public HistoryStorageStatus getStorageStatus() {
            return current().getStorageStatus();
        }

        @Override
        public void add(HistoryEntry entry) {
            current().add(entry);
        }

        @Override
        public void update(HistoryEntry entry) {
            current().update(entry);
        }

        @Override
        public java.util.List<HistoryEntry> getAll() {
            return current().getAll();
        }

        @Override
        public java.util.List<HistoryEntry> searchAdvanced(String keyword,
                                                           String site,
                                                           EndpointType endpointType,
                                                           RiskLevel riskLevel,
                                                           AnalysisStatus status,
                                                           Long timeFrom,
                                                           Long timeTo,
                                                           int offset,
                                                           int limit) {
            return current().searchAdvanced(keyword, site, endpointType, riskLevel, status, timeFrom, timeTo, offset, limit);
        }

        @Override
        public HistoryEntry getById(String requestId) {
            return current().getById(requestId);
        }

        @Override
        public void clear() {
            current().clear();
        }

        @Override
        public int size() {
            return current().size();
        }

        @Override
        public int countAdvanced(String keyword,
                                 String site,
                                 EndpointType endpointType,
                                 RiskLevel riskLevel,
                                 AnalysisStatus status,
                                 Long timeFrom,
                                 Long timeTo) {
            return current().countAdvanced(keyword, site, endpointType, riskLevel, status, timeFrom, timeTo);
        }

        @Override
        public int clearAdvanced(String keyword,
                                 String site,
                                 EndpointType endpointType,
                                 RiskLevel riskLevel,
                                 AnalysisStatus status,
                                 Long timeFrom,
                                 Long timeTo) {
            return current().clearAdvanced(keyword, site, endpointType, riskLevel, status, timeFrom, timeTo);
        }
    }

    private static final class DelegatingPipeline implements IPipeline {
        private volatile IPipeline delegate;

        private void setDelegate(IPipeline delegate) {
            this.delegate = delegate;
        }

        @Override
        public void submit(HTTPContext context) {
            IPipeline current = delegate;
            if (current != null) {
                current.submit(context);
            }
        }

        @Override
        public void registerStage(com.aiburpcopilot.core.pipeline.IPipelineStage stage) {
            IPipeline current = delegate;
            if (current != null) {
                current.registerStage(stage);
            }
        }

        @Override
        public int getStageCount() {
            IPipeline current = delegate;
            return current != null ? current.getStageCount() : 0;
        }

        @Override
        public void start() {
            IPipeline current = delegate;
            if (current != null) {
                current.start();
            }
        }

        @Override
        public void shutdown() {
            IPipeline current = delegate;
            if (current != null) {
                current.shutdown();
            }
        }
    }

    private static final class DelegatingAIProvider implements IAIProvider {
        private volatile IAIProvider delegate;

        private void setDelegate(IAIProvider delegate) {
            this.delegate = delegate;
        }

        @Override
        public String getProviderName() {
            IAIProvider current = delegate;
            return current != null ? current.getProviderName() : "Unavailable";
        }

        @Override
        public java.util.concurrent.CompletableFuture<String> analyzeAttackSurface(
                com.aiburpcopilot.core.context.HTTPContext context,
                String systemPrompt,
                String userPrompt) {
            IAIProvider current = delegate;
            return current != null
                    ? current.analyzeAttackSurface(context, systemPrompt, userPrompt)
                    : unavailable("Attack surface analysis");
        }

        @Override
        public java.util.concurrent.CompletableFuture<String> classifyEndpoint(
                String aiSummary,
                String classifierPrompt) {
            IAIProvider current = delegate;
            return current != null
                    ? current.classifyEndpoint(aiSummary, classifierPrompt)
                    : unavailable("Endpoint classification");
        }

        @Override
        public java.util.concurrent.CompletableFuture<String> reviewStaticResource(
                String content,
                String reviewPrompt) {
            IAIProvider current = delegate;
            return current != null
                    ? current.reviewStaticResource(content, reviewPrompt)
                    : unavailable("Static resource review");
        }

        @Override
        public java.util.concurrent.CompletableFuture<String> analyzeDiff(String diffPrompt) {
            IAIProvider current = delegate;
            return current != null ? current.analyzeDiff(diffPrompt) : unavailable("Diff review");
        }

        @Override
        public boolean isAvailable() {
            IAIProvider current = delegate;
            return current != null && current.isAvailable();
        }

        private java.util.concurrent.CompletableFuture<String> unavailable(String action) {
            java.util.concurrent.CompletableFuture<String> future = new java.util.concurrent.CompletableFuture<>();
            future.completeExceptionally(new IllegalStateException(action + " is unavailable"));
            return future;
        }
    }

    private static final class DelegatingManualVerificationService extends ManualVerificationService {
        private volatile ManualVerificationService delegate;

        private DelegatingManualVerificationService() {
            super(new ParameterProfiler(), null, null, null, null);
            this.delegate = new NoopManualVerificationService();
        }

        private void setDelegate(ManualVerificationService delegate) {
            this.delegate = delegate != null ? delegate : new NoopManualVerificationService();
        }

        @Override
        public java.util.List<com.aiburpcopilot.core.verification.model.VerificationResult> runAfterManualInfluence(
                com.aiburpcopilot.core.history.HistoryEntry entry,
                com.aiburpcopilot.core.verification.model.VerificationResult influenceResult) {
            ManualVerificationService current = delegate;
            return current != null
                    ? current.runAfterManualInfluence(entry, influenceResult)
                    : java.util.List.of();
        }
    }
}
