package com.aiburpcopilot.core.verification;

import com.aiburpcopilot.core.context.AttackType;
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

    public List<VerificationResult> runManualVerification(HistoryEntry entry,
                                                          String parameterName,
                                                          AttackType attackType) {
        if (entry == null || parameterName == null || parameterName.isBlank() || attackType == null) {
            return List.of();
        }

        HTTPContext context = rebuildContext(entry);
        VerificationResult preflightFailure = preflightManualRun(context, parameterName, attackType);
        if (preflightFailure != null) {
            return List.of(preflightFailure);
        }

        CandidateParameter candidate = new CandidateParameter();
        candidate.setParameterName(parameterName);
        candidate.setAttackType(attackType);
        candidate.setConfidence(1.0);
        candidate.setSource("MANUAL_WORKBENCH");

        WorkflowContext workflowContext = new WorkflowContext(context, candidate);
        workflowContext.setPolicyEngine(policyEngine);
        workflowContext.setReplayEngine(replayEngine);
        workflowContext.setParameterProfile(profile(context, parameterName));
        workflowContext.setInfluenceResult(approvedInfluence(parameterName));
        workflowContext.setBaselineResponse(entry.getRawResponse());

        WorkflowResult workflowResult = workflowEngine.execute(workflowContext);
        List<VerificationResult> results = toVerificationResults(context, workflowResult);
        results.removeIf(result -> "Influence Gate".equalsIgnoreCase(result.getPhase()));
        if (results.isEmpty()) {
            results.add(toDiagnosticResult(context, parameterName, attackType,
                    workflowResult != null ? workflowResult.getStopReason() : null,
                    "\u624b\u52a8\u9a8c\u8bc1\u5df2\u542f\u52a8\uff0c\u4f46 Workflow \u6ca1\u6709\u4ea7\u751f\u53ef\u5c55\u793a\u7684\u6b65\u9aa4\u7ed3\u679c\u3002"));
        }
        return results;
    }

    private VerificationResult preflightManualRun(HTTPContext context,
                                                  String parameterName,
                                                  AttackType attackType) {
        if (context == null || context.getRawRequest() == null || context.getRawRequest().length == 0) {
            return toDiagnosticResult(context, parameterName, attackType, null,
                    "\u539f\u59cb\u8bf7\u6c42\u5b57\u8282\u4e0d\u5b58\u5728\uff0c\u65e0\u6cd5\u91cd\u653e\u9a8c\u8bc1\u3002");
        }
        if (context.getUrl() == null || context.getUrl().isBlank()) {
            return toDiagnosticResult(context, parameterName, attackType, null,
                    "URL \u4e0d\u5b58\u5728\uff0c\u65e0\u6cd5\u5224\u65ad\u76ee\u6807 Host\u3002");
        }
        if (verificationGuard != null && !verificationGuard.isHostAllowed(context.getUrl())) {
            return toDiagnosticResult(context, parameterName, attackType, null,
                    "\u672a\u53d1\u5305\uff1a\u76ee\u6807 Host \u4e0d\u5728 verification.whitelist \u4e2d\u3002\n"
                            + "\u76ee\u6807: " + context.getUrl() + "\n"
                            + "\u5f53\u524d\u767d\u540d\u5355: " + verificationGuard.getWhitelist() + "\n"
                            + "\u8bf7\u5728\u8bbe\u7f6e\u91cc\u628a\u76ee\u6807 Host \u52a0\u5165\u767d\u540d\u5355\uff0c"
                            + "\u4f8b\u5982: 192.0.2.10\uff0c\u7136\u540e\u91cd\u8bd5\u3002");
        }
        return null;
    }

    private VerificationResult toDiagnosticResult(HTTPContext context,
                                                  String parameterName,
                                                  AttackType attackType,
                                                  String stopReason,
                                                  String message) {
        VerificationResult result = new VerificationResult();
        result.setAttackType(attackType);
        result.setParameter(parameterName);
        result.setRequestId(context != null ? context.getRequestId() : null);
        result.setUrl(context != null ? context.getUrl() : null);
        result.setRiskLevel(RiskLevel.INFO);
        result.setConfidence(0.0);
        result.setPhase("\u624b\u52a8\u9a8c\u8bc1\u9884\u68c0");
        result.setPayload("-");
        result.setReasoning(message + (stopReason != null && !stopReason.isBlank()
                ? "\nWorkflow stopReason: " + stopReason
                : ""));
        return result;
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
        result.setLlmReview(finding.getLlmReview());
        result.setConfirmedVulnerability(true);
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
        result.setConfidence(stepResult != null ? stepResult.getConfidence() : workflowResult.getOverallConfidence());
        result.setRiskLevel(confidenceToRiskLevel(result.getConfidence()));
        result.setReasoning(stepResult != null ? stepResult.getReasoning() : workflowResult.getStopReason());
        result.setResponseTimeMs(stepResult != null ? stepResult.getDurationMs() : workflowResult.getDurationMs());
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
