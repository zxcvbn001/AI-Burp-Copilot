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
import com.aiburpcopilot.core.verification.model.ParameterProfile;
import com.aiburpcopilot.core.verification.model.InfluenceResult;
import com.aiburpcopilot.core.verification.model.InfluenceStatus;
import com.aiburpcopilot.core.verification.model.ReviewStatus;
import com.aiburpcopilot.core.verification.model.StepResult;
import com.aiburpcopilot.core.verification.model.VerificationResult;
import com.aiburpcopilot.core.verification.model.WorkflowResult;
import com.aiburpcopilot.core.verification.policy.IPolicyEngine;
import com.aiburpcopilot.core.verification.safety.VerificationGuard;
import com.aiburpcopilot.core.verification.workflow.IWorkflowEngine;
import com.aiburpcopilot.core.verification.workflow.WorkflowContext;
import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
                pluginLog.warn("WorkflowVerification",
                        "Skip: verification.enabled=false, path=" + context.getPath());
            }
            return false;
        }
        if (context.getEndpointType() != EndpointType.ENDPOINT) {
            return false;
        }
        if (!guard.isHostAllowed(context.getUrl())) {
            pluginLog.warn("WorkflowVerification", "Skip host not allowed: " + context.getUrl());
            return false;
        }
        if (!guard.isInfluenceActionAllowed(context) && !guard.isVerificationActionAllowed(context)) {
            pluginLog.warn("WorkflowVerification",
                    "Skip unsafe endpoint action: " + guard.describeActionPolicy(context, true));
            return false;
        }
        if (context.getAnalysisResult() == null || !context.getAnalysisResult().isSuccess()) {
            return false;
        }
        if (!hasVerificationSignals(context)) {
            pluginLog.debug("WorkflowVerification",
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
            pluginLog.debug("WorkflowVerification", "No candidates: " + context.getPath());
            return;
        }

        int maxParameters = policyEngine != null
                ? policyEngine.getMaxParameterTests()
                : guard.getMaxRequestsPerEndpoint();
        int processed = 0;
        List<VerificationResult> verificationResults = new ArrayList<>();
        Map<String, InfluenceResult> influenceCache = new LinkedHashMap<>();

        pluginLog.info("WorkflowVerification", "Start: " + context.getPath()
                + " candidates=" + candidates.size());

        for (CandidateParameter candidate : candidates) {
            if (processed >= maxParameters) {
                pluginLog.warn("WorkflowVerification", "Parameter test limit reached: " + maxParameters);
                break;
            }
            if (!guard.isHostAllowed(context.getUrl())) {
                break;
            }

            try {
                WorkflowContext workflowContext = new WorkflowContext(context, candidate);
                workflowContext.setPolicyEngine(policyEngine);
                workflowContext.setReplayEngine(replayEngine);
                workflowContext.setPayloadVerificationAllowed(guard.isVerificationActionAllowed(context));
                if (!guard.isInfluenceActionAllowed(context)) {
                    pluginLog.warn("WorkflowVerification",
                            "Skip influence replay by action policy: "
                                    + guard.describeActionPolicy(context, true));
                    continue;
                }
                if (!workflowContext.isPayloadVerificationAllowed()) {
                    pluginLog.warn("WorkflowVerification",
                            "Payload verification will be blocked by action policy: "
                                    + guard.describeActionPolicy(context, false));
                }
                workflowContext.setParameterProfile(profileCandidate(context, candidate));
                InfluenceResult cachedInfluence = influenceCache.get(influenceCacheKey(candidate));
                if (cachedInfluence != null) {
                    workflowContext.setInfluenceResult(cachedInfluence);
                    pluginLog.debug("WorkflowVerification", "Reuse influence result: param="
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
                        candidate.getParameterName(), candidate.getAttackType(), e);
                pluginLog.warn("WorkflowVerification", "Candidate failed: "
                        + candidate.getParameterName() + " - " + e.getMessage());
            }
        }

        context.setVerificationResults(verificationResults);
        pluginLog.info("WorkflowVerification", "Done: results=" + verificationResults.size()
                + " elapsed=" + (System.currentTimeMillis() - start) + "ms");
    }

    private String influenceCacheKey(CandidateParameter candidate) {
        return (candidate.getParameterType() != null ? candidate.getParameterType() : "UNKNOWN")
                + "|" + (candidate.getParameterName() != null ? candidate.getParameterName() : "");
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
        result.setParameter(finding.getParameter());
        result.setRequestId(finding.getRequestId());
        result.setUrl(finding.getUrl());
        result.setConfidence(finding.getConfidence());
        result.setRiskLevel(finding.getRiskLevel());
        result.setReasoning(finding.getReasoning());
        result.setResponseTimeMs(finding.getResponseTimeMs());
        result.setPhase("Finding");
        result.setPayload("aggregated evidence");
        result.setDiffResult(finding.getDiffResult());
        result.setMutatedRequestBytes(finding.getRequestBytes());
        result.setMutatedResponseBytes(finding.getResponseBytes());
        result.setResponseLength(finding.getResponseBytes() != null ? finding.getResponseBytes().length : 0);
        result.setExchangeTranscript(finding.getExchangeTranscript());
        result.setConfirmedVulnerability(true);
        result.setReviewStatus(ReviewStatus.PENDING);
        return result;
    }

    private VerificationResult toVerificationResult(HTTPContext context,
                                                    WorkflowResult workflowResult,
                                                    StepResult stepResult) {
        VerificationResult result = new VerificationResult();
        result.setAttackType(workflowResult.getAttackType());
        result.setParameter(workflowResult.getParameterName());
        result.setRequestId(context.getRequestId());
        result.setUrl(context.getUrl());
        double confidence = stepResult != null
                ? stepResult.getConfidence()
                : workflowResult.getOverallConfidence();
        result.setConfidence(confidence);
        result.setRiskLevel(confidenceToRiskLevel(confidence));
        result.setReasoning(buildReasoning(workflowResult, stepResult));
        result.setResponseTimeMs(stepResult != null
                ? stepResult.getDurationMs()
                : workflowResult.getDurationMs());
        if (stepResult != null) {
            result.setPhase(stepResult.getPhase());
            result.setStrategyType(stepResult.getStrategyType());
            result.setPayload(stepResult.getPayload());
            result.setDiffResult(stepResult.getDiffResult());
            result.setResponseLength(stepResult.getResponseLength());
            result.setMutatedRequestBytes(stepResult.getRequestBytes());
            result.setMutatedResponseBytes(stepResult.getResponseBytes());
            result.setExchangeTranscript(stepResult.getExchangeTranscript());
            result.setLlmReview(stepResult.getLlmReview());
            if ("Influence Gate".equalsIgnoreCase(stepResult.getPhase())) {
                result.setInfluenceStatus(parseInfluenceStatus(stepResult.getReasoning()));
            }
        }
        return result;
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
