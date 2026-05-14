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
import com.aiburpcopilot.core.verification.probe.IProbeRuleEngine;
import com.aiburpcopilot.core.verification.probe.ProbeOracleEngine;
import com.aiburpcopilot.core.verification.workflow.IWorkflowRegistry;
import com.aiburpcopilot.core.verification.workflow.VerificationStep;
import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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

        PluginLogger.getInstance().info(PluginLogger.Category.VERIFICATION, "WorkflowStepFactory",
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

        Set<String> addedSteps = new HashSet<>();
        if (probeRuleEngine != null) {
            for (String attackTypeName : probeRuleEngine.getAttackTypeNames()) {
                addProbeStep(steps, addedSteps, probeStepName(attackTypeName), attackTypeName);
            }
        }

        PluginLogger.getInstance().info(PluginLogger.Category.VERIFICATION, "WorkflowStepFactory",
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
        addProbeStep(steps, new HashSet<>(), stepName, attackType != null ? attackType.name() : null);
    }

    private void addProbeStep(List<VerificationStep> steps,
                              Set<String> addedSteps,
                              String stepName,
                              String attackTypeName) {
        if (stepName == null || !addedSteps.add(stepName)) {
            return;
        }
        VerificationStep step = createProbeStep(stepName, attackTypeName);
        if (step != null) {
            steps.add(step);
        }
    }

    public static String probeStepName(AttackType attackType) {
        if (attackType == null) {
            return null;
        }
        return switch (attackType) {
            case SQLI -> GenericProbeStep.SQLI_STEP;
            case XSS -> GenericProbeStep.XSS_STEP;
            case IDOR -> GenericProbeStep.IDOR_STEP;
            case AUTH -> GenericProbeStep.AUTH_STEP;
            case SSRF -> GenericProbeStep.SSRF_STEP;
            case PATH_TRAVERSAL -> GenericProbeStep.PATH_TRAVERSAL_STEP;
            case OPEN_REDIRECT -> GenericProbeStep.OPEN_REDIRECT_STEP;
            case SSTI -> GenericProbeStep.SSTI_STEP;
        };
    }

    public static String probeStepName(String attackTypeName) {
        if (attackTypeName == null || attackTypeName.isBlank()) {
            return null;
        }
        return switch (attackTypeName.trim().toUpperCase()) {
            case "SQLI" -> GenericProbeStep.SQLI_STEP;
            case "XSS" -> GenericProbeStep.XSS_STEP;
            case "IDOR" -> GenericProbeStep.IDOR_STEP;
            case "AUTH" -> GenericProbeStep.AUTH_STEP;
            case "SSRF" -> GenericProbeStep.SSRF_STEP;
            case "PATH_TRAVERSAL" -> GenericProbeStep.PATH_TRAVERSAL_STEP;
            case "OPEN_REDIRECT" -> GenericProbeStep.OPEN_REDIRECT_STEP;
            case "SSTI" -> GenericProbeStep.SSTI_STEP;
            default -> attackTypeName.trim().toUpperCase().replaceAll("[^A-Z0-9_]", "_") + "Probes";
        };
    }

    private VerificationStep createProbeStep(String stepName, AttackType attackType) {
        return createProbeStep(stepName, attackType != null ? attackType.name() : null);
    }

    private VerificationStep createProbeStep(String stepName, String attackTypeName) {
        if (replayEngine == null || probeRuleEngine == null) {
            log.warn("Skipping {} - replay={}, probe={}", stepName,
                    replayEngine != null, probeRuleEngine != null);
            return null;
        }
        return new GenericProbeStep(
                stepName,
                attackTypeName,
                replayEngine,
                probeRuleEngine,
                new ProbeOracleEngine(diffEngine, aiProvider),
                policyEngine,
                maxPayloadLength);
    }

    public IWorkflowRegistry createRegistry() {
        return WorkflowRegistry.fromRules(payloadRuleEngine);
    }
}
