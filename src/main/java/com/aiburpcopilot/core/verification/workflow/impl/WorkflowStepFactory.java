package com.aiburpcopilot.core.verification.workflow.impl;

import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.influence.IInfluenceDiffEngine;
import com.aiburpcopilot.core.verification.influence.IInfluenceLlmAnalyzer;
import com.aiburpcopilot.core.verification.influence.IMinimalMutationEngine;
import com.aiburpcopilot.core.verification.influence.IInfluenceScorer;
import com.aiburpcopilot.core.verification.influence.IParameterRoleAnalyzer;
import com.aiburpcopilot.core.verification.influence.IReplayEngine;
import com.aiburpcopilot.core.verification.influence.IStrategyApprovalEngine;
import com.aiburpcopilot.core.verification.influence.impl.InfluenceLlmAnalyzer;
import com.aiburpcopilot.core.verification.influence.impl.ParameterRoleLlmAnalyzer;
import com.aiburpcopilot.core.verification.payload.IPayloadRuleEngine;
import com.aiburpcopilot.core.verification.policy.IPolicyEngine;
import com.aiburpcopilot.core.verification.plugins.impl.PluginRegistry;
import com.aiburpcopilot.core.verification.probe.IProbeRuleEngine;
import com.aiburpcopilot.core.verification.probe.ProbeOracleEngine;
import com.aiburpcopilot.core.verification.workflow.IWorkflowRegistry;
import com.aiburpcopilot.core.verification.workflow.VerificationStep;
import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Assembles deterministic workflow steps.
 * <p>
 * Payload verification is probe-only: every attack type is executed through
 * {@link GenericProbeStep}.
 */
public class WorkflowStepFactory {

    private static final Logger log = LoggerFactory.getLogger(WorkflowStepFactory.class);

    private IReplayEngine replayEngine;
    private IMinimalMutationEngine mutationEngine;
    private IInfluenceDiffEngine diffEngine;
    private IInfluenceScorer scorer;
    private IInfluenceLlmAnalyzer influenceLlmAnalyzer;
    private IParameterRoleAnalyzer parameterRoleAnalyzer;
    private IStrategyApprovalEngine approvalEngine;
    private IPayloadRuleEngine payloadRuleEngine;
    private IProbeRuleEngine probeRuleEngine;
    private PluginRegistry pluginRegistry;
    private IAIProvider aiProvider;
    private IPolicyEngine policyEngine;
    private double minInfluenceScore;
    private int maxPayloadLength = 128;

    public WorkflowStepFactory(IReplayEngine replayEngine,
                               IMinimalMutationEngine mutationEngine,
                               IInfluenceDiffEngine diffEngine,
                               IInfluenceScorer scorer,
                               IStrategyApprovalEngine approvalEngine) {
        this.replayEngine = replayEngine;
        this.mutationEngine = mutationEngine;
        this.diffEngine = diffEngine;
        this.scorer = scorer;
        this.approvalEngine = approvalEngine;
        this.minInfluenceScore = 0.1;
    }

    public WorkflowStepFactory(IReplayEngine replayEngine) {
        this(replayEngine, null, null, null, null);
    }

    public void setPayloadRuleEngine(IPayloadRuleEngine payloadRuleEngine) {
        this.payloadRuleEngine = payloadRuleEngine;
        if (payloadRuleEngine instanceof IProbeRuleEngine engine) {
            this.probeRuleEngine = engine;
        }
    }

    public void setProbeRuleEngine(IProbeRuleEngine probeRuleEngine) {
        this.probeRuleEngine = probeRuleEngine;
    }

    public void setPluginRegistry(PluginRegistry pluginRegistry) {
        this.pluginRegistry = pluginRegistry;
    }

    public void setAiProvider(IAIProvider aiProvider) {
        this.aiProvider = aiProvider;
        this.influenceLlmAnalyzer = new InfluenceLlmAnalyzer(aiProvider);
        this.parameterRoleAnalyzer = new ParameterRoleLlmAnalyzer(aiProvider);
    }

    public void setPolicyEngine(IPolicyEngine policyEngine) {
        this.policyEngine = policyEngine;
    }

    public void setMaxPayloadLength(int maxPayloadLength) {
        this.maxPayloadLength = maxPayloadLength;
    }

    public void setMinInfluenceScore(double minInfluenceScore) {
        this.minInfluenceScore = minInfluenceScore;
    }

    public WorkflowEngine createEngine() {
        IWorkflowRegistry registry = createRegistry();
        WorkflowEngine engine = new WorkflowEngine(registry);
        List<VerificationStep> steps = createAllSteps();
        for (VerificationStep step : steps) {
            engine.registerStep(step.getName(), step);
        }

        PluginLogger.getInstance().info("WorkflowStepFactory",
                "WorkflowEngine created: " + registry.getCount() + " workflows, "
                        + steps.size() + " steps registered");
        log.info("WorkflowEngine created with {} workflows and {} steps",
                registry.getCount(), steps.size());
        return engine;
    }

    public List<VerificationStep> createAllSteps() {
        List<VerificationStep> steps = new ArrayList<>();

        VerificationStep influenceStep = createInfluenceValidationStep();
        if (influenceStep != null) {
            steps.add(influenceStep);
        }

        addProbeStep(steps, GenericProbeStep.SQLI_STEP, AttackType.SQLI);
        addProbeStep(steps, GenericProbeStep.XSS_STEP, AttackType.XSS);
        addProbeStep(steps, GenericProbeStep.IDOR_STEP, AttackType.IDOR);
        addProbeStep(steps, GenericProbeStep.AUTH_STEP, AttackType.AUTH);
        addProbeStep(steps, GenericProbeStep.SSRF_STEP, AttackType.SSRF);
        addProbeStep(steps, GenericProbeStep.PATH_TRAVERSAL_STEP, AttackType.PATH_TRAVERSAL);

        PluginLogger.getInstance().info("WorkflowStepFactory",
                "Created " + steps.size() + " VerificationStep instances");
        return steps;
    }

    public VerificationStep createInfluenceValidationStep() {
        if (replayEngine == null || mutationEngine == null
                || diffEngine == null || scorer == null || approvalEngine == null) {
            log.warn("Skipping InfluenceValidationStep - missing dependencies: replay={}, mutation={}, diff={}, scorer={}, approval={}",
                    replayEngine != null, mutationEngine != null,
                    diffEngine != null, scorer != null, approvalEngine != null);
            return null;
        }
        return new InfluenceValidationStep(
                replayEngine, mutationEngine, diffEngine, scorer,
                influenceLlmAnalyzer, parameterRoleAnalyzer, approvalEngine, minInfluenceScore);
    }

    public VerificationStep createSqliProbeStep() {
        return createProbeStep(GenericProbeStep.SQLI_STEP, AttackType.SQLI);
    }

    public VerificationStep createXssProbeStep() {
        return createProbeStep(GenericProbeStep.XSS_STEP, AttackType.XSS);
    }

    public VerificationStep createPathTraversalProbeStep() {
        return createProbeStep(GenericProbeStep.PATH_TRAVERSAL_STEP, AttackType.PATH_TRAVERSAL);
    }

    private void addProbeStep(List<VerificationStep> steps, String stepName, AttackType attackType) {
        VerificationStep step = createProbeStep(stepName, attackType);
        if (step != null) {
            steps.add(step);
        }
    }

    private VerificationStep createProbeStep(String stepName, AttackType attackType) {
        if (replayEngine == null || probeRuleEngine == null) {
            log.warn("Skipping {} - replay={}, probe={}", stepName,
                    replayEngine != null, probeRuleEngine != null);
            return null;
        }
        return new GenericProbeStep(
                stepName,
                attackType,
                replayEngine,
                probeRuleEngine,
                new ProbeOracleEngine(diffEngine, aiProvider),
                policyEngine,
                maxPayloadLength);
    }

    public IWorkflowRegistry createRegistry() {
        if (pluginRegistry == null) {
            log.warn("No PluginRegistry configured; creating empty WorkflowRegistry");
            return new WorkflowRegistry();
        }
        return WorkflowRegistry.fromPlugins(pluginRegistry);
    }
}
