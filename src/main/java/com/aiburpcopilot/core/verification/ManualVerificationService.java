package com.aiburpcopilot.core.verification;

import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.ParameterContext;
import com.aiburpcopilot.core.context.RiskLevel;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.verification.finding.FindingAggregator;
import com.aiburpcopilot.core.verification.finding.VulnerabilityFinding;
import com.aiburpcopilot.core.verification.influence.IParameterProfiler;
import com.aiburpcopilot.core.verification.influence.IReplayEngine;
import com.aiburpcopilot.core.verification.model.CandidateParameter;
import com.aiburpcopilot.core.verification.model.InfluenceResult;
import com.aiburpcopilot.core.verification.model.InfluenceStatus;
import com.aiburpcopilot.core.verification.model.ParameterProfile;
import com.aiburpcopilot.core.verification.model.ReviewStatus;
import com.aiburpcopilot.core.verification.model.StepResult;
import com.aiburpcopilot.core.verification.model.VerificationResult;
import com.aiburpcopilot.core.verification.model.WorkflowResult;
import com.aiburpcopilot.core.verification.policy.IPolicyEngine;
import com.aiburpcopilot.core.verification.safety.VerificationGuard;
import com.aiburpcopilot.core.verification.workflow.IWorkflowEngine;
import com.aiburpcopilot.core.verification.workflow.WorkflowContext;
import com.aiburpcopilot.utils.HttpUtil;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class ManualVerificationService {

    private final IParameterProfiler parameterProfiler;
    private final IWorkflowEngine workflowEngine;
    private final IPolicyEngine policyEngine;
    private final IReplayEngine replayEngine;
    private final VerificationGuard verificationGuard;
    private final FindingAggregator findingAggregator = new FindingAggregator();

    public ManualVerificationService(IParameterProfiler parameterProfiler,
                                     IWorkflowEngine workflowEngine,
                                     IPolicyEngine policyEngine,
                                     IReplayEngine replayEngine,
                                     VerificationGuard verificationGuard) {
        this.parameterProfiler = parameterProfiler;
        this.workflowEngine = workflowEngine;
        this.policyEngine = policyEngine;
        this.replayEngine = replayEngine;
        this.verificationGuard = verificationGuard;
    }

    public ManualVerificationService(IParameterProfiler parameterProfiler,
                                     IWorkflowEngine workflowEngine,
                                     IPolicyEngine policyEngine,
                                     IReplayEngine replayEngine) {
        this(parameterProfiler, workflowEngine, policyEngine, replayEngine, null);
    }

    public List<VerificationResult> runAfterManualInfluence(HistoryEntry entry,
                                                            VerificationResult influenceResult) {
        if (entry == null || influenceResult == null) {
            return List.of();
        }

        HTTPContext context = rebuildContext(entry);
        CandidateParameter candidate = new CandidateParameter();
        candidate.setParameterName(influenceResult.getParameter());
        candidate.setAttackType(influenceResult.getAttackType());
        candidate.setAttackTypeName(influenceResult.getAttackTypeName());
        candidate.setConfidence(Math.max(0.7, influenceResult.getConfidence()));
        candidate.setSource("MANUAL_INFLUENCE_OVERRIDE");

        WorkflowContext workflowContext = new WorkflowContext(context, candidate);
        workflowContext.setPolicyEngine(policyEngine);
        workflowContext.setReplayEngine(replayEngine);
        workflowContext.setParameterProfile(profile(context, candidate.getParameterName()));
        workflowContext.setInfluenceResult(approvedInfluence(candidate.getParameterName()));
        workflowContext.setBaselineResponse(entry.getRawResponse());

        WorkflowResult workflowResult = workflowEngine.execute(workflowContext);
        List<VerificationResult> results = toVerificationResults(context, workflowResult);
        results.removeIf(result -> "Influence Gate".equalsIgnoreCase(result.getPhase()));
        return results;
    }

    private HTTPContext rebuildContext(HistoryEntry entry) {
        HTTPContext context = new HTTPContext();
        context.setRequestId(entry.getRequestId());
        context.setTimestamp(entry.getTimestamp());
        context.setMethod(entry.getMethod());
        context.setUrl(entry.getUrl());
        context.setPath(entry.getPath());
        context.setStatusCode(entry.getStatusCode());
        context.setContentType(entry.getContentType());
        context.setEndpointType(entry.getEndpointType());
        context.setRiskLevel(entry.getRiskLevel());
        context.setAnalysisStatus(entry.getAnalysisStatus());
        context.setRawRequest(entry.getRawRequest());
        context.setRawResponse(entry.getRawResponse());
        if (entry.getRequestBody() != null) {
            context.setRequestBody(entry.getRequestBody().getBytes(StandardCharsets.UTF_8));
        }
        if (entry.getResponseBody() != null) {
            context.setResponseBody(entry.getResponseBody().getBytes(StandardCharsets.UTF_8));
        }
        extractParameters(context, entry);
        return context;
    }

    private void extractParameters(HTTPContext context, HistoryEntry entry) {
        String url = entry.getUrl();
        if (url != null) {
            int queryIndex = url.indexOf('?');
            if (queryIndex >= 0 && queryIndex < url.length() - 1) {
                context.setQuery(url.substring(queryIndex + 1));
                HttpUtil.parseQueryParams(context.getQuery()).forEach(context::addParameter);
            }
        }
        if (entry.getRequestBody() != null) {
            if (HttpUtil.isFormContent(entry.getContentType())) {
                HttpUtil.parseFormBodyParams(entry.getRequestBody()).forEach(context::addParameter);
            } else if (HttpUtil.isJsonContent(entry.getContentType())) {
                HttpUtil.parseJsonBodyParams(entry.getRequestBody()).forEach(context::addParameter);
            }
        }
    }

    private ParameterProfile profile(HTTPContext context, String parameterName) {
        String value = "";
        for (ParameterContext parameter : context.getParameters()) {
            if (parameter.getName() != null && parameter.getName().equals(parameterName)) {
                value = parameter.getValue();
                break;
            }
        }
        return parameterProfiler.profile(parameterName, value);
    }

    private InfluenceResult approvedInfluence(String parameterName) {
        InfluenceResult result = new InfluenceResult();
        result.setParameterName(parameterName);
        result.setInfluenceScore(1.0);
        result.setApproved(true);
        result.setStatus(InfluenceStatus.INFLUENTIAL);
        result.setReplaySuccess(true);
        result.setApprovalReason("Manual override: parameter marked as influential");
        return result;
    }

    private List<VerificationResult> toVerificationResults(HTTPContext context, WorkflowResult workflowResult) {
        List<VerificationResult> results = new ArrayList<>();
        if (workflowResult.getStepResults() != null) {
            for (StepResult stepResult : workflowResult.getStepResults()) {
                results.add(toVerificationResult(context, workflowResult, stepResult));
            }
        }
        VulnerabilityFinding finding = findingAggregator.aggregate(
                context.getRequestId(), context.getUrl(), workflowResult);
        if (finding != null) {
            results.add(toFindingResult(finding));
        }
        return results;
    }

    private VerificationResult toFindingResult(VulnerabilityFinding finding) {
        VerificationResult result = new VerificationResult();
        result.setAttackType(finding.getAttackType());
        result.setAttackTypeName(finding.getAttackTypeName());
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
        result.setAttackTypeName(workflowResult.getAttackTypeName());
        result.setParameter(workflowResult.getParameterName());
        result.setRequestId(context.getRequestId());
        result.setUrl(context.getUrl());
        result.setConfidence(stepResult != null ? stepResult.getConfidence() : workflowResult.getOverallConfidence());
        result.setRiskLevel(confidenceToRiskLevel(result.getConfidence()));
        result.setReasoning(stepResult != null ? stepResult.getReasoning() : workflowResult.getStopReason());
        result.setResponseTimeMs(stepResult != null ? stepResult.getDurationMs() : workflowResult.getDurationMs());
        if (stepResult != null) {
            result.setPhase(stepResult.getPhase());
            result.setStrategyType(stepResult.getStrategyType());
            result.setStrategyName(stepResult.getStrategyName());
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
            if (stepResult.getLlmReview() != null && !stepResult.getLlmReview().isBlank()) {
                result.setReasoning((result.getReasoning() != null ? result.getReasoning() : "")
                        + "\n\nLLM Review=" + stepResult.getLlmReview());
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

    private RiskLevel confidenceToRiskLevel(double confidence) {
        if (confidence >= 0.90) return RiskLevel.CRITICAL;
        if (confidence >= 0.70) return RiskLevel.HIGH;
        if (confidence >= 0.50) return RiskLevel.MEDIUM;
        if (confidence >= 0.30) return RiskLevel.LOW;
        return RiskLevel.INFO;
    }
}
