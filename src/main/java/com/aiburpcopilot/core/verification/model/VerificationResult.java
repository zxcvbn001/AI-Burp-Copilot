package com.aiburpcopilot.core.verification.model;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.context.RiskLevel;
import com.aiburpcopilot.core.verification.util.RuleKeyUtil;

/**
 * 验证结果。
 * <p>
 * 封装一次安全验证的完整结果：
 * 攻击类型、目标参数、重评估的风险等级、
 * 置信度、Diff 结果以及推理说明。
 */
public class VerificationResult {

    /** 攻击类型 */
    private AttackType attackType;
    private String attackTypeName;

    /** 目标参数名 */
    private String parameter;

    /** 重新评估后的风险等级 */
    private RiskLevel riskLevel;

    /** 置信度 (0.0 ~ 1.0) */
    private double confidence;

    /** 响应差异分析结果 */
    private DiffResult diffResult;

    /** 推理说明 */
    private String reasoning;

    /** 结果生成时间 */
    private long timestamp;

    /** 使用的 payload */
    private String payload;

    /** 使用的策略类型 */
    private StrategyType strategyType;

    /** 关联的原始请求 ID */
    private String requestId;

    /** 被测试的 URL */
    private String url;

    /** 响应体长度（字节数） */
    private int responseLength;

    /** 请求耗时（毫秒） */
    private long responseTimeMs;

    /** 修改后的 HTTP 请求字节（含 payload） */
    private byte[] mutatedRequestBytes;

    /** 修改后请求的 HTTP 响应字节 */
    private byte[] mutatedResponseBytes;

    private String phase;
    private boolean manualInfluenceOverride;
    private boolean confirmedVulnerability;
    private String llmReview;
    private ReviewStatus reviewStatus = ReviewStatus.NOT_REQUIRED;
    private String exchangeTranscript;
    private InfluenceStatus influenceStatus;

    public VerificationResult() {
        this.timestamp = System.currentTimeMillis();
        this.riskLevel = RiskLevel.INFO;
        this.confidence = 0.0;
        this.responseLength = 0;
        this.responseTimeMs = 0;
    }

    /**
     * 生成可读的单行摘要。
     *
     * @return 格式化的摘要字符串
     */
    public String toSummaryString() {
        StringBuilder sb = new StringBuilder();
        sb.append(attackType != null ? attackType.getDisplayName() : (getAttackTypeName() != null ? getAttackTypeName() : "Unknown"));
        sb.append(" on '").append(parameter).append("'");
        sb.append(" [").append(riskLevel).append("]");
        sb.append(" conf=").append(String.format("%.2f", confidence));
        if (diffResult != null && diffResult.isSignificant()) {
            sb.append(" DIFF:");
            if (diffResult.isStatusChanged()) sb.append(" status");
            if (diffResult.isLengthChanged()) sb.append(" length");
            if (diffResult.isKeywordChanged()) sb.append(" keyword");
            sb.append(" sim=").append(String.format("%.2f", diffResult.getSimilarity()));
        }
        return sb.toString();
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

    public String getParameter() { return parameter; }
    public void setParameter(String parameter) { this.parameter = parameter; }

    public RiskLevel getRiskLevel() { return riskLevel; }
    public void setRiskLevel(RiskLevel riskLevel) { this.riskLevel = riskLevel; }

    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = Math.max(0.0, Math.min(1.0, confidence)); }

    public DiffResult getDiffResult() { return diffResult; }
    public void setDiffResult(DiffResult diffResult) { this.diffResult = diffResult; }

    public String getReasoning() { return reasoning; }
    public void setReasoning(String reasoning) { this.reasoning = reasoning; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }

    public StrategyType getStrategyType() { return strategyType; }
    public void setStrategyType(StrategyType strategyType) { this.strategyType = strategyType; }

    public String getRequestId() { return requestId; }
    public void setRequestId(String requestId) { this.requestId = requestId; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public int getResponseLength() { return responseLength; }
    public void setResponseLength(int responseLength) { this.responseLength = responseLength; }

    public long getResponseTimeMs() { return responseTimeMs; }
    public void setResponseTimeMs(long responseTimeMs) { this.responseTimeMs = responseTimeMs; }

    public byte[] getMutatedRequestBytes() { return mutatedRequestBytes; }
    public void setMutatedRequestBytes(byte[] mutatedRequestBytes) { this.mutatedRequestBytes = mutatedRequestBytes; }

    public byte[] getMutatedResponseBytes() { return mutatedResponseBytes; }
    public void setMutatedResponseBytes(byte[] mutatedResponseBytes) { this.mutatedResponseBytes = mutatedResponseBytes; }

    public String getPhase() { return phase; }
    public void setPhase(String phase) { this.phase = phase; }

    public boolean isManualInfluenceOverride() { return manualInfluenceOverride; }
    public void setManualInfluenceOverride(boolean manualInfluenceOverride) {
        this.manualInfluenceOverride = manualInfluenceOverride;
    }

    public boolean isConfirmedVulnerability() { return confirmedVulnerability; }
    public void setConfirmedVulnerability(boolean confirmedVulnerability) {
        this.confirmedVulnerability = confirmedVulnerability;
    }

    public String getLlmReview() { return llmReview; }
    public void setLlmReview(String llmReview) { this.llmReview = llmReview; }

    public ReviewStatus getReviewStatus() { return reviewStatus; }
    public void setReviewStatus(ReviewStatus reviewStatus) {
        this.reviewStatus = reviewStatus != null ? reviewStatus : ReviewStatus.NOT_REQUIRED;
    }

    public String getExchangeTranscript() { return exchangeTranscript; }
    public void setExchangeTranscript(String exchangeTranscript) { this.exchangeTranscript = exchangeTranscript; }

    public InfluenceStatus getInfluenceStatus() { return influenceStatus; }
    public void setInfluenceStatus(InfluenceStatus influenceStatus) { this.influenceStatus = influenceStatus; }

    @Override
    public String toString() {
        return toSummaryString();
    }
}
