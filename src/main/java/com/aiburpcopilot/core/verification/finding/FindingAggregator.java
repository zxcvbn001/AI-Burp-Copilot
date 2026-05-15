package com.aiburpcopilot.core.verification.finding;

import com.aiburpcopilot.core.context.RiskLevel;
import com.aiburpcopilot.core.verification.model.Evidence;
import com.aiburpcopilot.core.verification.model.StepResult;
import com.aiburpcopilot.core.verification.model.WorkflowResult;

import java.util.ArrayList;
import java.util.List;

public class FindingAggregator {

    private static final double MIN_FINDING_CONFIDENCE = 0.55;
    private static final double FINDING_CONFIDENCE_EPSILON = 0.001;
    private static final String PAYLOAD_VERIFICATION_PHASE = "Payload Verification";

    public VulnerabilityFinding aggregate(String requestId, String url, WorkflowResult workflowResult) {
        if (workflowResult == null || workflowResult.getAttackTypeName() == null) {
            return null;
        }

        double confidence = 0.0;
        int evidenceCount = 0;
        StepResult representative = null;
        List<Evidence> vulnerabilityEvidence = new ArrayList<>();

        for (StepResult stepResult : workflowResult.getStepResults()) {
            if (!isVulnerabilityProofStep(stepResult)) {
                continue;
            }
            confidence = combine(confidence, stepResult.getConfidence());
            if (stepResult.getEvidences() != null) {
                evidenceCount += stepResult.getEvidences().size();
                vulnerabilityEvidence.addAll(stepResult.getEvidences());
            }
            if (isBetterRepresentative(stepResult, representative)) {
                representative = stepResult;
            }
        }

        workflowResult.setFindingThreshold(MIN_FINDING_CONFIDENCE);
        workflowResult.setFindingConfidenceRaw(confidence);

        if (representative == null) {
            workflowResult.setFindingGenerated(false);
            workflowResult.setFindingDecisionReason("No payload verification step produced usable evidence.");
            workflowResult.setRejectReason(workflowResult.getFindingDecisionReason());
            workflowResult.setFinalDecision("NO_EVIDENCE");
            return null;
        }
        if (vulnerabilityEvidence.isEmpty()) {
            workflowResult.setFindingGenerated(false);
            workflowResult.setFindingDecisionReason("Payload verification succeeded but produced no evidence snapshots.");
            workflowResult.setRejectReason(workflowResult.getFindingDecisionReason());
            workflowResult.setFinalDecision("NO_EVIDENCE");
            return null;
        }
        if (!passesThreshold(confidence, MIN_FINDING_CONFIDENCE)) {
            workflowResult.setFindingGenerated(false);
            workflowResult.setFindingDecisionReason("Finding not generated: raw confidence="
                    + String.format("%.4f", confidence)
                    + " < threshold=" + String.format("%.4f", MIN_FINDING_CONFIDENCE));
            workflowResult.setRejectReason(workflowResult.getFindingDecisionReason());
            workflowResult.setFinalDecision("BELOW_THRESHOLD");
            return null;
        }

        VulnerabilityFinding finding = new VulnerabilityFinding();
        finding.setAttackTypeName(workflowResult.getAttackTypeName());
        finding.setAttackType(workflowResult.getAttackType());
        finding.setParameter(workflowResult.getParameterName());
        finding.setCandidateId(workflowResult.getCandidateId());
        finding.setTraceId(workflowResult.getTraceId());
        finding.setRequestId(requestId);
        finding.setUrl(url);
        finding.setConfidence(confidence);
        finding.setRiskLevel(confidenceToRiskLevel(confidence));
        finding.setEvidences(vulnerabilityEvidence);
        finding.setReasoning(buildReasoning(workflowResult, vulnerabilityEvidence, confidence, evidenceCount));
        finding.setDiffResult(representative.getDiffResult());
        finding.setBaselineRequestBytes(workflowResult.getBaselineRequestBytes());
        finding.setBaselineResponseBytes(workflowResult.getBaselineResponseBytes());
        finding.setRequestBytes(representative.getRequestBytes());
        finding.setResponseBytes(representative.getResponseBytes());
        finding.setResponseTimeMs(representative.getDurationMs());
        finding.setExchangeTranscript(buildTranscript(workflowResult));
        finding.setExchangeRecords(new ArrayList<>(workflowResult.getExchangeRecords()));
        finding.setThreshold(MIN_FINDING_CONFIDENCE);
        finding.setLocalMatched(workflowResult.isLocalMatched());
        finding.setLlmMatched(null);
        finding.setFinalDecision("CONFIRMED");
        finding.setDedupKey(workflowResult.getDedupKey());
        finding.setDecisionReason("Finding generated: raw confidence="
                + String.format("%.4f", confidence)
                + ", threshold=" + String.format("%.4f", MIN_FINDING_CONFIDENCE));
        workflowResult.setFindingGenerated(true);
        workflowResult.setFindingDecisionReason(finding.getDecisionReason());
        workflowResult.setFinalDecision("CONFIRMED");
        return finding;
    }

    private boolean passesThreshold(double value, double threshold) {
        return value + FINDING_CONFIDENCE_EPSILON >= threshold;
    }

    private boolean isVulnerabilityProofStep(StepResult stepResult) {
        return stepResult != null
                && stepResult.isSuccess()
                && PAYLOAD_VERIFICATION_PHASE.equalsIgnoreCase(stepResult.getPhase())
                && stepResult.getEvidences() != null
                && !stepResult.getEvidences().isEmpty();
    }

    private String buildReasoning(WorkflowResult workflowResult,
                                  List<Evidence> vulnerabilityEvidence,
                                  double confidence,
                                  int evidenceCount) {
        StringBuilder builder = new StringBuilder();
        builder.append("漏洞类型聚合结论：")
                .append(workflowResult.getAttackTypeName())
                .append("\n参数：")
                .append(workflowResult.getParameterName())
                .append("\n置信度：")
                .append(String.format("%.2f", confidence))
                .append("\n证据数量：")
                .append(evidenceCount)
                .append("\n证据来源：");
        for (Evidence evidence : vulnerabilityEvidence) {
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
