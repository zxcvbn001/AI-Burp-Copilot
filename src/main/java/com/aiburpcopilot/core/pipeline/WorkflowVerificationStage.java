package com.aiburpcopilot.core.pipeline;

import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.ParameterContext;
import com.aiburpcopilot.core.context.RiskLevel;
import com.aiburpcopilot.core.verification.finding.FindingAggregator;
import com.aiburpcopilot.core.verification.finding.VulnerabilityFinding;
import com.aiburpcopilot.core.verification.candidate.ICandidateExtractor;
import com.aiburpcopilot.core.verification.influence.IParameterProfiler;
import com.aiburpcopilot.core.verification.influence.IReplayEngine;
import com.aiburpcopilot.core.verification.model.CandidateParameter;
import com.aiburpcopilot.core.verification.model.FinalVerdicts;
import com.aiburpcopilot.core.verification.model.ParameterProfile;
import com.aiburpcopilot.core.verification.model.InfluenceResult;
import com.aiburpcopilot.core.verification.model.InfluenceStatus;
import com.aiburpcopilot.core.verification.model.ExchangeRecord;
import com.aiburpcopilot.core.verification.model.ReviewStatus;
import com.aiburpcopilot.core.verification.model.StepResult;
import com.aiburpcopilot.core.verification.model.VerificationResult;
import com.aiburpcopilot.core.verification.model.WorkflowResult;
import com.aiburpcopilot.core.verification.policy.IPolicyEngine;
import com.aiburpcopilot.core.verification.safety.VerificationGuard;
import com.aiburpcopilot.core.verification.workflow.IWorkflowEngine;
import com.aiburpcopilot.core.verification.workflow.WorkflowContext;
import com.aiburpcopilot.core.verification.workflow.impl.WorkflowEngine;
import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Phase 3 workflow-based verification stage.
 * <p>
 * This stage is intentionally thin: it extracts candidates, profiles the
 * parameter, and delegates deterministic verification to WorkflowEngine.
 */
public class WorkflowVerificationStage implements IPipelineStage {

    private static final Logger log = LoggerFactory.getLogger(WorkflowVerificationStage.class);
    private final PluginLogger pluginLog = PluginLogger.getInstance();

    private final ICandidateExtractor candidateExtractor;
    private final IParameterProfiler parameterProfiler;
    private final IWorkflowEngine workflowEngine;
    private final IPolicyEngine policyEngine;
    private final IReplayEngine replayEngine;
    private final VerificationGuard guard;
    private final FindingAggregator findingAggregator = new FindingAggregator();

    public WorkflowVerificationStage(ICandidateExtractor candidateExtractor,
                                     IParameterProfiler parameterProfiler,
                                     IWorkflowEngine workflowEngine,
                                     IPolicyEngine policyEngine,
                                     IReplayEngine replayEngine,
                                     VerificationGuard guard) {
        this.candidateExtractor = candidateExtractor;
        this.parameterProfiler = parameterProfiler;
        this.workflowEngine = workflowEngine;
        this.policyEngine = policyEngine;
        this.replayEngine = replayEngine;
        this.guard = guard;
    }

    @Override
    public String getName() {
        return "Workflow Verification";
    }

    @Override
    public boolean shouldProcess(HTTPContext context) {
        if (context == null) {
            return false;
        }
        if (context.getAnalysisStatus() == com.aiburpcopilot.core.context.AnalysisStatus.SKIPPED) {
            return false;
        }
        if (!guard.isVerificationEnabled()) {
            if (hasVerificationSignals(context)) {
                pluginLog.warn(PluginLogger.Category.VERIFICATION, "WorkflowVerification",
                        "Skip: verification.enabled=false, path=" + context.getPath());
            }
            return false;
        }
        if (context.getEndpointType() != EndpointType.ENDPOINT) {
            return false;
        }
        if (!guard.isHostAllowed(context.getUrl())) {
            pluginLog.warn(PluginLogger.Category.VERIFICATION,
                    "WorkflowVerification", "Skip host not allowed: " + context.getUrl());
            return false;
        }
        if (context.getAnalysisResult() == null || !context.getAnalysisResult().isSuccess()) {
            return false;
        }
        if (!hasVerificationSignals(context)) {
            pluginLog.debug(PluginLogger.Category.VERIFICATION, "WorkflowVerification",
                    "Skip: no verification signals from AI analysis, path=" + context.getPath());
            return false;
        }
        return true;
    }

    private boolean hasVerificationSignals(HTTPContext context) {
        if (context == null || context.getAnalysisResult() == null) {
            return false;
        }
        var result = context.getAnalysisResult();
        return (result.getHighValueParams() != null && !result.getHighValueParams().isEmpty())
                || (result.getRecommendedTechniques() != null && !result.getRecommendedTechniques().isEmpty())
                || (result.getPossibleVulnerabilities() != null && !result.getPossibleVulnerabilities().isEmpty());
    }

    @Override
    public void process(HTTPContext context) {
        long start = System.currentTimeMillis();
        List<CandidateParameter> candidates = candidateExtractor.extract(context);
        if (candidates.isEmpty()) {
            pluginLog.debug(PluginLogger.Category.VERIFICATION,
                    "WorkflowVerification", "No candidates: " + context.getPath());
            return;
        }

        if (!guard.isInfluenceActionAllowed(context) && !guard.isVerificationActionAllowed(context)) {
            pluginLog.warn(PluginLogger.Category.VERIFICATION, "WorkflowVerification",
                    "Skip unsafe endpoint action after candidate extraction: "
                            + guard.describeActionPolicy(context, false));
            return;
        }

        int maxParameters = policyEngine != null
                ? policyEngine.getMaxParameterTests()
                : guard.getMaxRequestsPerEndpoint();
        int processed = 0;
        List<VerificationResult> verificationResults = new ArrayList<>();
        Map<String, InfluenceResult> influenceCache = new LinkedHashMap<>();
        Set<String> workflowDedup = new HashSet<>();

        pluginLog.info(PluginLogger.Category.VERIFICATION, "WorkflowVerification", "Start: " + context.getPath()
                + " candidates=" + candidates.size());

        for (CandidateParameter candidate : candidates) {
            if (processed >= maxParameters) {
                pluginLog.warn(PluginLogger.Category.VERIFICATION,
                        "WorkflowVerification", "Parameter test limit reached: " + maxParameters);
                break;
            }
            if (!guard.isHostAllowed(context.getUrl())) {
                break;
            }

            try {
                String candidateKey = verificationDedupKey(context, candidate);
                if (!workflowDedup.add(candidateKey)) {
                    pluginLog.debug(PluginLogger.Category.VERIFICATION,
                            "WorkflowVerification", "Skip duplicate candidate: " + candidateKey);
                    continue;
                }
                WorkflowContext workflowContext = new WorkflowContext(context, candidate);
                workflowContext.setPolicyEngine(policyEngine);
                workflowContext.setReplayEngine(replayEngine);
                workflowContext.setPayloadVerificationAllowed(guard.isVerificationActionAllowed(context));
                boolean requiresInfluenceReplay = requiresInfluenceReplay(candidate);
                if (requiresInfluenceReplay && !guard.isInfluenceActionAllowed(context)) {
                    pluginLog.warn(PluginLogger.Category.VERIFICATION, "WorkflowVerification",
                            "Skip influence replay by action policy: "
                                    + guard.describeActionPolicy(context, true));
                    continue;
                }
                if (!workflowContext.isPayloadVerificationAllowed()) {
                    pluginLog.warn(PluginLogger.Category.VERIFICATION, "WorkflowVerification",
                            "Payload verification will be blocked by action policy: "
                                    + guard.describeActionPolicy(context, false));
                }
                workflowContext.setParameterProfile(profileCandidate(context, candidate));
                InfluenceResult cachedInfluence = influenceCache.get(influenceCacheKey(candidate));
                if (cachedInfluence != null) {
                    workflowContext.setInfluenceResult(cachedInfluence);
                    pluginLog.debug(PluginLogger.Category.VERIFICATION,
                            "WorkflowVerification", "Reuse influence result: param="
                            + candidate.getParameterName()
                            + " approved=" + cachedInfluence.isApproved());
                }

                WorkflowResult workflowResult = workflowEngine.execute(workflowContext);
                if (workflowContext.getInfluenceResult() != null) {
                    influenceCache.putIfAbsent(influenceCacheKey(candidate), workflowContext.getInfluenceResult());
                }
                verificationResults.addAll(toVerificationResults(context, workflowResult));
                processed++;
            } catch (Exception e) {
                log.warn("Workflow verification failed for param={} type={}",
                        candidate.getParameterName(), candidate.getAttackTypeName(), e);
                pluginLog.warn(PluginLogger.Category.VERIFICATION, "WorkflowVerification", "Candidate failed: "
                        + candidate.getParameterName() + " - " + e.getMessage());
            }
        }

        context.setVerificationResults(verificationResults);
        pluginLog.info(PluginLogger.Category.VERIFICATION, "WorkflowVerification", "Done: results=" + verificationResults.size()
                + " elapsed=" + (System.currentTimeMillis() - start) + "ms");
    }

    private String influenceCacheKey(CandidateParameter candidate) {
        return (candidate.getParameterType() != null ? candidate.getParameterType() : "UNKNOWN")
                + "|" + (candidate.getParameterName() != null ? candidate.getParameterName() : "")
                + "|" + (candidate.getAttackTypeName() != null ? candidate.getAttackTypeName() : "");
    }

    private boolean requiresInfluenceReplay(CandidateParameter candidate) {
        if (workflowEngine instanceof WorkflowEngine engine
                && candidate != null
                && candidate.getAttackTypeName() != null) {
            return engine.findWorkflow(candidate.getAttackTypeName())
                    .map(def -> def.isIncludeInfluenceStep() || def.isRequiresInfluenceApproval())
                    .orElse(true);
        }
        return true;
    }

    private ParameterProfile profileCandidate(HTTPContext context, CandidateParameter candidate) {
        String value = "";
        if (context.getParameters() != null) {
            for (ParameterContext parameter : context.getParameters()) {
                if (parameter.getName() != null
                        && parameter.getName().equals(candidate.getParameterName())) {
                    value = parameter.getValue();
                    break;
                }
            }
        }
        return parameterProfiler.profile(candidate.getParameterName(), value);
    }

    private List<VerificationResult> toVerificationResults(HTTPContext context, WorkflowResult workflowResult) {
        List<VerificationResult> results = new ArrayList<>();
        if (workflowResult.getStepResults() != null) {
            for (StepResult stepResult : workflowResult.getStepResults()) {
                VerificationResult result = toVerificationResult(context, workflowResult, stepResult);
                results.add(result);
            }
        }
        VulnerabilityFinding finding = findingAggregator.aggregate(
                context.getRequestId(), context.getUrl(), workflowResult);
        if (finding != null) {
            results.add(toFindingResult(finding));
        }
        if (results.isEmpty()) {
            results.add(toVerificationResult(context, workflowResult, null));
        }
        return results;
    }

    private VerificationResult toFindingResult(VulnerabilityFinding finding) {
        VerificationResult result = new VerificationResult();
        result.setAttackType(finding.getAttackType());
        result.setAttackTypeName(finding.getAttackTypeName());
        result.setParameter(finding.getParameter());
        result.setCandidateId(finding.getCandidateId());
        result.setTraceId(finding.getTraceId());
        result.setRequestId(finding.getRequestId());
        result.setUrl(finding.getUrl());
        result.setConfidence(finding.getConfidence());
        result.setRiskLevel(finding.getRiskLevel());
        result.setReasoning(finding.getReasoning());
        result.setResponseTimeMs(finding.getResponseTimeMs());
        result.setPhase("Finding");
        result.setPayload("aggregated evidence");
        result.setDiffResult(finding.getDiffResult());
        result.setBaselineRequestBytes(finding.getBaselineRequestBytes());
        result.setBaselineResponseBytes(finding.getBaselineResponseBytes());
        result.setMutatedRequestBytes(finding.getRequestBytes());
        result.setMutatedResponseBytes(finding.getResponseBytes());
        result.setResponseLength(finding.getResponseBytes() != null ? finding.getResponseBytes().length : 0);
        result.setExchangeTranscript(finding.getExchangeTranscript());
        result.setExchangeRecords(finding.getExchangeRecords());
        result.setEvidences(finding.getEvidences());
        result.setLlmReview(finding.getLlmReview());
        result.setFindingGenerated(true);
        result.setFindingConfidenceRaw(finding.getConfidence());
        result.setFindingThreshold(finding.getThreshold());
        result.setFindingDecisionReason(finding.getDecisionReason());
        result.setLocalMatched(finding.isLocalMatched());
        result.setLlmMatched(finding.getLlmMatched());
        result.setFinalDecision(finding.getFinalDecision());
        result.setDedupKey(finding.getDedupKey());
        result.setReviewStatus(ReviewStatus.PENDING);
        FinalVerdicts.recompute(result);
        return result;
    }

    private VerificationResult toVerificationResult(HTTPContext context,
                                                    WorkflowResult workflowResult,
                                                    StepResult stepResult) {
        VerificationResult result = new VerificationResult();
        result.setAttackType(workflowResult.getAttackType());
        result.setAttackTypeName(workflowResult.getAttackTypeName());
        result.setParameter(workflowResult.getParameterName());
        result.setCandidateId(workflowResult.getCandidateId());
        result.setTraceId(workflowResult.getTraceId());
        result.setWorkflowName(workflowResult.getWorkflowName());
        result.setCandidateSource(workflowResult.getCandidateSource());
        result.setCandidateReasoning(workflowResult.getCandidateReasoning());
        result.setCandidateConfidence(workflowResult.getCandidateConfidence());
        result.setRequestId(context.getRequestId());
        result.setUrl(context.getUrl());
        result.setBaselineRequestBytes(workflowResult.getBaselineRequestBytes());
        result.setBaselineResponseBytes(workflowResult.getBaselineResponseBytes());
        double confidence = stepResult != null
                ? stepResult.getConfidence()
                : workflowResult.getOverallConfidence();
        result.setConfidence(confidence);
        result.setRiskLevel(confidenceToRiskLevel(confidence));
        result.setReasoning(buildReasoning(workflowResult, stepResult));
        result.setResponseTimeMs(stepResult != null
                ? stepResult.getDurationMs()
                : workflowResult.getDurationMs());
        result.setFindingGenerated(workflowResult.isFindingGenerated());
        result.setFindingConfidenceRaw(workflowResult.getFindingConfidenceRaw());
        result.setFindingThreshold(workflowResult.getFindingThreshold());
        result.setFindingDecisionReason(workflowResult.getFindingDecisionReason());
        result.setLocalMatched(stepResult != null ? stepResult.isLocalMatched() : workflowResult.isLocalMatched());
        result.setLlmMatched(stepResult != null ? stepResult.getLlmMatched() : workflowResult.getLlmMatched());
        result.setFinalDecision(stepResult != null && stepResult.getDecision() != null
                ? stepResult.getDecision()
                : workflowResult.getFinalDecision());
        result.setRejectReason(workflowResult.getRejectReason());
        result.setDedupKey(stepResult != null && stepResult.getDedupKey() != null
                ? stepResult.getDedupKey()
                : workflowResult.getDedupKey());
        if (stepResult != null) {
            result.setPhase(stepResult.getPhase());
            result.setStrategyType(stepResult.getStrategyType());
            result.setStrategyName(stepResult.getStrategyName());
            result.setPayload(stepResult.getPayload());
            result.setDiffResult(stepResult.getDiffResult());
            result.setResponseLength(stepResult.getResponseLength());
            result.setBaselineRequestBytes(stepResult.getBaselineRequestBytes());
            result.setBaselineResponseBytes(stepResult.getBaselineResponseBytes());
            result.setMutatedRequestBytes(stepResult.getRequestBytes());
            result.setMutatedResponseBytes(stepResult.getResponseBytes());
            result.setExchangeTranscript(stepResult.getExchangeTranscript());
            result.setExchangeRecords(stepResult.getExchangeRecords());
            result.setLlmReview(stepResult.getLlmReview());
            result.setEvidences(stepResult.getEvidences());
            if ("Influence Gate".equalsIgnoreCase(stepResult.getPhase())) {
                result.setInfluenceStatus(parseInfluenceStatus(stepResult.getReasoning()));
            }
        }
        FinalVerdicts.recompute(result);
        return result;
    }

    private String verificationDedupKey(HTTPContext context, CandidateParameter candidate) {
        String method = context != null && context.getMethod() != null ? context.getMethod().toUpperCase() : "-";
        String path = context != null && context.getPath() != null ? context.getPath() : "-";
        String param = candidate != null && candidate.getParameterName() != null ? candidate.getParameterName() : "-";
        String paramType = candidate != null && candidate.getParameterType() != null ? candidate.getParameterType().toUpperCase() : "-";
        String attackType = candidate != null && candidate.getAttackTypeName() != null ? candidate.getAttackTypeName() : "-";
        return method + "|" + path + "|" + param + "|" + paramType + "|" + attackType;
    }

    private InfluenceStatus parseInfluenceStatus(String reasoning) {
        if (reasoning == null || reasoning.isBlank()) {
            return null;
        }
        for (InfluenceStatus status : InfluenceStatus.values()) {
            if (reasoning.contains("Influence status=" + status.name())) {
                return status;
            }
        }
        return null;
    }

    private String buildReasoning(WorkflowResult workflowResult, StepResult stepResult) {
        StringBuilder reasoning = new StringBuilder();
        if (stepResult != null) {
            reasoning.append("Phase=")
                    .append(stepResult.getPhase() != null ? stepResult.getPhase() : stepResult.getStepName())
                    .append(", step=")
                    .append(stepResult.getStepName())
                    .append(", success=")
                    .append(stepResult.isSuccess())
                    .append(", continue=")
                    .append(stepResult.isContinueWorkflow())
                    .append("\n")
                    .append(stepResult.getReasoning() != null ? stepResult.getReasoning() : "N/A")
                    .append("\n\n");
            if (stepResult.getLlmReview() != null && !stepResult.getLlmReview().isBlank()) {
                reasoning.append("LLM Review=")
                        .append(stepResult.getLlmReview())
                        .append("\n\n");
            }
        }
        reasoning.append("Workflow=")
                .append(workflowResult.getWorkflowName())
                .append(" completed=")
                .append(workflowResult.isCompleted())
                .append(", steps=")
                .append(workflowResult.getStepResults().size())
                .append(", evidence=")
                .append(workflowResult.getEvidence().size());
        if (workflowResult.getStopReason() != null) {
            reasoning.append(", stopReason=").append(workflowResult.getStopReason());
        }
        if (workflowResult.getFindingThreshold() > 0) {
            reasoning.append("\n\nFindingAggregation generated=")
                    .append(workflowResult.isFindingGenerated())
                    .append(", rawConfidence=")
                    .append(String.format("%.4f", workflowResult.getFindingConfidenceRaw()))
                    .append(", threshold=")
                    .append(String.format("%.4f", workflowResult.getFindingThreshold()));
            if (workflowResult.getFindingDecisionReason() != null && !workflowResult.getFindingDecisionReason().isBlank()) {
                reasoning.append("\n").append(workflowResult.getFindingDecisionReason());
            }
        }
        return reasoning.toString();
    }

    private RiskLevel confidenceToRiskLevel(double confidence) {
        if (confidence >= 0.90) return RiskLevel.CRITICAL;
        if (confidence >= 0.70) return RiskLevel.HIGH;
        if (confidence >= 0.50) return RiskLevel.MEDIUM;
        if (confidence >= 0.30) return RiskLevel.LOW;
        return RiskLevel.INFO;
    }
}
