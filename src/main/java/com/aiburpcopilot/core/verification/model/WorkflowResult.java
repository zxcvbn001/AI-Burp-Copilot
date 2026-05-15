package com.aiburpcopilot.core.verification.model;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.util.RuleKeyUtil;

import java.util.ArrayList;
import java.util.List;

/**
 * Workflow 执行结果。
 * <p>
 * 封装整个 Workflow 的完整执行结果，包含所有步骤结果和证据。
 */
public class WorkflowResult {

    /** 关联的攻击类型 */
    private AttackType attackType;
    private String attackTypeName;

    /** 参数名 */
    private String parameterName;
    private String candidateId;
    private String traceId;
    private String requestId;
    private String url;
    private String candidateSource;
    private String candidateReasoning;
    private double candidateConfidence;

    /** 工作流是否完整执行成功 */
    private boolean completed;

    /** 工作流名称 */
    private String workflowName;

    /** 各步骤执行结果 */
    private List<StepResult> stepResults;

    /** 合并后的所有证据 */
    private List<Evidence> evidence;

    /** 总体置信度 */
    private double overallConfidence;

    /** 工作流执行耗时（毫秒） */
    private long durationMs;

    /** 停止原因（如果未完成） */
    private String stopReason;

    /** 停止步骤索引 */
    private int stoppedAtStep;
    private boolean findingGenerated;
    private double findingConfidenceRaw;
    private double findingThreshold;
    private String findingDecisionReason;
    private boolean localMatched;
    private Boolean llmMatched;
    private String finalDecision;
    private String rejectReason;
    private byte[] baselineRequestBytes;
    private byte[] baselineResponseBytes;
    private String dedupKey;
    private List<ExchangeRecord> exchangeRecords;

    public WorkflowResult() {
        this.stepResults = new ArrayList<>();
        this.evidence = new ArrayList<>();
        this.exchangeRecords = new ArrayList<>();
    }

    /**
     * 从步骤结果收集所有证据。
     */
    public void collectEvidence() {
        evidence.clear();
        exchangeRecords.clear();
        for (StepResult sr : stepResults) {
            if (sr.getEvidences() != null) {
                evidence.addAll(sr.getEvidences());
            }
            if (sr.getExchangeRecords() != null) {
                exchangeRecords.addAll(sr.getExchangeRecords());
            }
        }
    }

    // ---------- Getters & Setters ----------

    public AttackType getAttackType() { return attackType; }
    public void setAttackType(AttackType attackType) {
        this.attackType = attackType;
        if (attackType != null) {
            this.attackTypeName = attackType.name();
        }
    }

    public String getAttackTypeName() {
        return attackTypeName != null ? attackTypeName : RuleKeyUtil.attackTypeName(attackType);
    }

    public void setAttackTypeName(String attackTypeName) {
        this.attackTypeName = RuleKeyUtil.normalize(attackTypeName);
        this.attackType = RuleKeyUtil.toAttackType(this.attackTypeName).orElse(null);
    }

    public String getParameterName() { return parameterName; }
    public void setParameterName(String parameterName) { this.parameterName = parameterName; }

    public String getCandidateId() { return candidateId; }
    public void setCandidateId(String candidateId) { this.candidateId = candidateId; }

    public String getTraceId() { return traceId; }
    public void setTraceId(String traceId) { this.traceId = traceId; }

    public String getRequestId() { return requestId; }
    public void setRequestId(String requestId) { this.requestId = requestId; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getCandidateSource() { return candidateSource; }
    public void setCandidateSource(String candidateSource) { this.candidateSource = candidateSource; }

    public String getCandidateReasoning() { return candidateReasoning; }
    public void setCandidateReasoning(String candidateReasoning) { this.candidateReasoning = candidateReasoning; }

    public double getCandidateConfidence() { return candidateConfidence; }
    public void setCandidateConfidence(double candidateConfidence) {
        this.candidateConfidence = Math.max(0.0, Math.min(1.0, candidateConfidence));
    }

    public boolean isCompleted() { return completed; }
    public void setCompleted(boolean completed) { this.completed = completed; }

    public String getWorkflowName() { return workflowName; }
    public void setWorkflowName(String workflowName) { this.workflowName = workflowName; }

    public List<StepResult> getStepResults() { return stepResults; }
    public void setStepResults(List<StepResult> stepResults) {
        this.stepResults = stepResults != null ? stepResults : new ArrayList<>();
    }

    public List<Evidence> getEvidence() { return evidence; }
    public void setEvidence(List<Evidence> evidence) {
        this.evidence = evidence != null ? evidence : new ArrayList<>();
    }

    public double getOverallConfidence() { return overallConfidence; }
    public void setOverallConfidence(double overallConfidence) {
        this.overallConfidence = Math.max(0.0, Math.min(1.0, overallConfidence));
    }

    public long getDurationMs() { return durationMs; }
    public void setDurationMs(long durationMs) { this.durationMs = durationMs; }

    public String getStopReason() { return stopReason; }
    public void setStopReason(String stopReason) { this.stopReason = stopReason; }

    public int getStoppedAtStep() { return stoppedAtStep; }
    public void setStoppedAtStep(int stoppedAtStep) { this.stoppedAtStep = stoppedAtStep; }

    public boolean isFindingGenerated() { return findingGenerated; }
    public void setFindingGenerated(boolean findingGenerated) { this.findingGenerated = findingGenerated; }

    public double getFindingConfidenceRaw() { return findingConfidenceRaw; }
    public void setFindingConfidenceRaw(double findingConfidenceRaw) {
        this.findingConfidenceRaw = Math.max(0.0, Math.min(1.0, findingConfidenceRaw));
    }

    public double getFindingThreshold() { return findingThreshold; }
    public void setFindingThreshold(double findingThreshold) {
        this.findingThreshold = Math.max(0.0, Math.min(1.0, findingThreshold));
    }

    public String getFindingDecisionReason() { return findingDecisionReason; }
    public void setFindingDecisionReason(String findingDecisionReason) { this.findingDecisionReason = findingDecisionReason; }

    public boolean isLocalMatched() { return localMatched; }
    public void setLocalMatched(boolean localMatched) { this.localMatched = localMatched; }

    public Boolean getLlmMatched() { return llmMatched; }
    public void setLlmMatched(Boolean llmMatched) { this.llmMatched = llmMatched; }

    public String getFinalDecision() { return finalDecision; }
    public void setFinalDecision(String finalDecision) { this.finalDecision = finalDecision; }

    public String getRejectReason() { return rejectReason; }
    public void setRejectReason(String rejectReason) { this.rejectReason = rejectReason; }

    public byte[] getBaselineRequestBytes() { return baselineRequestBytes; }
    public void setBaselineRequestBytes(byte[] baselineRequestBytes) { this.baselineRequestBytes = baselineRequestBytes; }

    public byte[] getBaselineResponseBytes() { return baselineResponseBytes; }
    public void setBaselineResponseBytes(byte[] baselineResponseBytes) { this.baselineResponseBytes = baselineResponseBytes; }

    public String getDedupKey() { return dedupKey; }
    public void setDedupKey(String dedupKey) { this.dedupKey = dedupKey; }

    public List<ExchangeRecord> getExchangeRecords() { return exchangeRecords; }
    public void setExchangeRecords(List<ExchangeRecord> exchangeRecords) {
        this.exchangeRecords = exchangeRecords != null ? exchangeRecords : new ArrayList<>();
    }

    @Override
    public String toString() {
        return "WorkflowResult{" +
                "attackType=" + attackType +
                ", attackTypeName='" + getAttackTypeName() + '\'' +
                ", parameterName='" + parameterName + '\'' +
                ", candidateId='" + candidateId + '\'' +
                ", traceId='" + traceId + '\'' +
                ", completed=" + completed +
                ", overallConfidence=" + overallConfidence +
                ", finalDecision='" + finalDecision + '\'' +
                ", evidence=" + evidence.size() +
                '}';
    }
}
