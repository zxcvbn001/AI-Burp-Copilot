package com.aiburpcopilot.core.verification.finding;

import com.aiburpcopilot.core.context.RiskLevel;
import com.aiburpcopilot.core.verification.model.Evidence;
import com.aiburpcopilot.core.verification.model.StepResult;
import com.aiburpcopilot.core.verification.model.WorkflowResult;

public class FindingAggregator {

    private static final double MIN_FINDING_CONFIDENCE = 0.55;

    public VulnerabilityFinding aggregate(String requestId, String url, WorkflowResult workflowResult) {
        if (workflowResult == null || workflowResult.getAttackType() == null) {
            return null;
        }

        double confidence = 0.0;
        int evidenceCount = 0;
        StepResult representative = null;

        for (StepResult stepResult : workflowResult.getStepResults()) {
            if (stepResult == null || !stepResult.isSuccess()) {
                continue;
            }
            confidence = combine(confidence, stepResult.getConfidence());
            if (stepResult.getEvidences() != null) {
                evidenceCount += stepResult.getEvidences().size();
            }
            if (isBetterRepresentative(stepResult, representative)) {
                representative = stepResult;
            }
        }

        if (confidence < MIN_FINDING_CONFIDENCE || representative == null) {
            return null;
        }

        VulnerabilityFinding finding = new VulnerabilityFinding();
        finding.setAttackType(workflowResult.getAttackType());
        finding.setParameter(workflowResult.getParameterName());
        finding.setRequestId(requestId);
        finding.setUrl(url);
        finding.setConfidence(confidence);
        finding.setRiskLevel(confidenceToRiskLevel(confidence));
        finding.setEvidences(workflowResult.getEvidence());
        finding.setReasoning(buildReasoning(workflowResult, confidence, evidenceCount));
        finding.setDiffResult(representative.getDiffResult());
        finding.setRequestBytes(representative.getRequestBytes());
        finding.setResponseBytes(representative.getResponseBytes());
        finding.setResponseTimeMs(representative.getDurationMs());
        finding.setExchangeTranscript(buildTranscript(workflowResult));
        finding.setLlmReview(representative.getLlmReview());
        return finding;
    }

    private String buildReasoning(WorkflowResult workflowResult, double confidence, int evidenceCount) {
        StringBuilder builder = new StringBuilder();
        builder.append("漏洞类型聚合结论：")
                .append(workflowResult.getAttackType())
                .append("\n参数：")
                .append(workflowResult.getParameterName())
                .append("\n置信度：")
                .append(String.format("%.2f", confidence))
                .append("\n证据数量：")
                .append(evidenceCount)
                .append("\n证据来源：");
        for (Evidence evidence : workflowResult.getEvidence()) {
            builder.append("\n- ")
                    .append(evidence.getEvidenceType())
                    .append(": ")
                    .append(evidence.getDescription());
        }
        return builder.toString();
    }

    private String buildTranscript(WorkflowResult workflowResult) {
        StringBuilder builder = new StringBuilder();
        for (StepResult stepResult : workflowResult.getStepResults()) {
            if (stepResult == null || stepResult.getExchangeTranscript() == null
                    || stepResult.getExchangeTranscript().isBlank()) {
                continue;
            }
            builder.append("########## Step: ")
                    .append(stepResult.getStepName())
                    .append(" ##########\n\n")
                    .append(stepResult.getExchangeTranscript())
                    .append("\n");
        }
        return builder.toString();
    }

    private boolean isBetterRepresentative(StepResult candidate, StepResult current) {
        if (current == null) {
            return true;
        }
        boolean candidateHasDiff = candidate.getDiffResult() != null;
        boolean currentHasDiff = current.getDiffResult() != null;
        if (candidateHasDiff != currentHasDiff) {
            return candidateHasDiff;
        }
        boolean candidateHasExchange = candidate.getExchangeTranscript() != null
                && !candidate.getExchangeTranscript().isBlank();
        boolean currentHasExchange = current.getExchangeTranscript() != null
                && !current.getExchangeTranscript().isBlank();
        if (candidateHasExchange != currentHasExchange) {
            return candidateHasExchange;
        }
        return candidate.getConfidence() > current.getConfidence();
    }

    private double combine(double current, double next) {
        return Math.min(1.0, 1.0 - ((1.0 - current) * (1.0 - next)));
    }

    private RiskLevel confidenceToRiskLevel(double confidence) {
        if (confidence >= 0.90) return RiskLevel.CRITICAL;
        if (confidence >= 0.70) return RiskLevel.HIGH;
        if (confidence >= 0.50) return RiskLevel.MEDIUM;
        if (confidence >= 0.30) return RiskLevel.LOW;
        return RiskLevel.INFO;
    }
}
