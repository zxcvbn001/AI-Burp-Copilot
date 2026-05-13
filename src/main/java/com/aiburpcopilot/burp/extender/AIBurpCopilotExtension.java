package com.aiburpcopilot.burp.extender;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.aiburpcopilot.burp.proxy.ProxyTrafficHandler;
import com.aiburpcopilot.burp.ui.MainTab;
import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.ai.impl.AIProviderFactory;
import com.aiburpcopilot.core.cache.ICacheService;
import com.aiburpcopilot.core.cache.impl.MemoryCacheService;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.core.config.impl.YAMLConfigService;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.core.history.impl.InMemoryHistoryService;
import com.aiburpcopilot.core.pipeline.AIAnalysisStage;
import com.aiburpcopilot.core.pipeline.AnalysisPipeline;
import com.aiburpcopilot.core.pipeline.EndpointClassificationStage;
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
import com.aiburpcopilot.core.verification.plugins.impl.PluginRegistry;
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

/**
 * Burp Montoya extension entry point.
 * <p>
 * The initializer wires the external configuration, prompt service, LLM
 * provider, passive analysis pipeline, verification engine, proxy hook and UI.
 */
public class AIBurpCopilotExtension implements BurpExtension {

    private static final Logger log = LoggerFactory.getLogger(AIBurpCopilotExtension.class);

    private MontoyaApi api;
    private IConfigService configService;
    private IPromptService promptService;
    private IAIProvider aiProvider;
    private ICacheService cacheService;
    private IHistoryService historyService;
    private IPipeline pipeline;
    private MainTab mainTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("AI Burp Copilot");
        log.info("Starting AI Burp Copilot v2...");

        try {
            configService = new YAMLConfigService();
            configService.reload();
            log.info("Config service initialized");

            promptService = new FilePromptService();
            promptService.reload();
            log.info("Prompt service initialized");

            aiProvider = AIProviderFactory.create(configService);
            log.info("AI provider initialized: {}", aiProvider.getProviderName());

            cacheService = new MemoryCacheService(
                    configService.getConfig().getStorage().getMaxCacheEntries(),
                    configService.getConfig().getStorage().getCacheTtlSeconds()
            );
            log.info("Cache service initialized");

            historyService = new InMemoryHistoryService(
                    configService.getConfig().getStorage().getMaxHistory()
            );
            log.info("History service initialized");

            IEndpointClassifier endpointClassifier = new EndpointClassifier(
                    aiProvider, promptService, cacheService, configService);
            IStaticScanner staticScanner = new StaticResourceScanner(
                    aiProvider, promptService, cacheService, configService);
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

            PluginRegistry pluginRegistry = PluginRegistry.createDefault();
            RuleCapabilityCatalog capabilityCatalog = new RuleCapabilityCatalog(
                    pluginRegistry, payloadEngine);
            ICandidateExtractor candidateExtractor = new CandidateExtractor(capabilityCatalog);

            WorkflowStepFactory workflowStepFactory = new WorkflowStepFactory(
                    replayEngine, minimalMutationEngine, influenceDiffEngine,
                    influenceScorer, strategyApprovalEngine);
            workflowStepFactory.setPayloadRuleEngine(payloadEngine);
            workflowStepFactory.setPluginRegistry(pluginRegistry);
            workflowStepFactory.setAiProvider(aiProvider);
            workflowStepFactory.setPolicyEngine(policyEngine);
            workflowStepFactory.setMaxPayloadLength(verificationGuard.getMaxPayloadLength());
            configService.addChangeListener(newConfig -> {
                if (newConfig != null && newConfig.getVerification() != null) {
                    verificationGuard.updateConfig(newConfig.getVerification());
                    workflowStepFactory.setMaxPayloadLength(
                            newConfig.getVerification().getMaxPayloadLength());
                }
            });
            IWorkflowEngine workflowEngine = workflowStepFactory.createEngine();

            log.info("Phase 3 verification components initialized");

            pipeline = new AnalysisPipeline();
            pipeline.registerStage(new HistoryStage(historyService));
            pipeline.registerStage(new StatusCodeFilterStage(configService));
            pipeline.registerStage(new EndpointClassificationStage(endpointClassifier));
            pipeline.registerStage(new StaticScanStage(staticScanner));
            pipeline.registerStage(new AIAnalysisStage(
                    aiProvider, promptService, cacheService, configService, capabilityCatalog));
            pipeline.registerStage(new RiskEvaluatorStage());
            pipeline.registerStage(new WorkflowVerificationStage(
                    candidateExtractor, parameterProfiler, workflowEngine,
                    policyEngine, replayEngine, verificationGuard));
            pipeline.registerStage(new HistoryStage(historyService, true));
            pipeline.start();
            log.info("Pipeline initialized with {} stages", pipeline.getStageCount());

            ProxyTrafficHandler proxyHandler = new ProxyTrafficHandler(pipeline);
            api.http().registerHttpHandler(proxyHandler);
            log.info("Proxy handler registered");

            ManualVerificationService manualVerificationService = new ManualVerificationService(
                    parameterProfiler, workflowEngine, policyEngine, replayEngine,
                    verificationGuard);
            mainTab = new MainTab(api, historyService, configService, aiProvider, manualVerificationService);
            api.userInterface().registerSuiteTab("AI Burp Copilot", mainTab);
            log.info("UI registered");

            api.extension().registerUnloadingHandler(() -> {
                log.info("Extension unloading, shutting down pipeline...");
                pipeline.shutdown();
                executionEngine.shutdown();
                log.info("Extension shutdown complete");
            });

            log.info("AI Burp Copilot v2 initialized successfully");
        } catch (Exception e) {
            log.error("Failed to initialize AI Burp Copilot", e);
            api.logging().logToError("Initialization failed: " + e.getMessage());
        }
    }

    public IPipeline getPipeline() {
        return pipeline;
    }
}
