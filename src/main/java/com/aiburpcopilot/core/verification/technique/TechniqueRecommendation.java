package com.aiburpcopilot.core.verification.technique;

import com.aiburpcopilot.core.context.AttackType;

/**
 * 技术推荐。
 * <p>
 * AI 分析结果中针对特定参数和攻击类型的验证技术建议。
 * 包含技术名称、AI 置信度和推理说明。
 * <p>
 * 该模型是 AI 输出与 VerificationTechnique 之间的桥接：
 * AI 推荐"对 userId 参数使用布尔盲注技术验证 SQLI"，
 * Strategy Engine 将其转换为 TestStrategy。
 * <p>
 * 注意：parameterName 和 attackType 是必须的上下文信息，
 * 否则推荐无法关联到具体的目标参数。
 */
public class TechniqueRecommendation {

    /** 目标参数名 */
    private String parameterName;

    /** 攻击类型 */
    private AttackType attackType;

    /** 推荐的技术 */
    private VerificationTechnique technique;

    /** AI 置信度 (0.0 ~ 1.0) */
    private double confidence;

    /** AI 推理说明（中文或英文） */
    private String reasoning;

    public TechniqueRecommendation() {
        this.confidence = 0.5;
    }

    public TechniqueRecommendation(String parameterName, AttackType attackType,
                                   VerificationTechnique technique, double confidence,
                                   String reasoning) {
        this.parameterName = parameterName;
        this.attackType = attackType;
        this.technique = technique;
        this.confidence = Math.max(0.0, Math.min(1.0, confidence));
        this.reasoning = reasoning;
    }

    // ---------- Getters & Setters ----------

    public String getParameterName() { return parameterName; }
    public void setParameterName(String parameterName) { this.parameterName = parameterName; }

    public AttackType getAttackType() { return attackType; }
    public void setAttackType(AttackType attackType) { this.attackType = attackType; }

    public VerificationTechnique getTechnique() { return technique; }
    public void setTechnique(VerificationTechnique technique) { this.technique = technique; }

    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = Math.max(0.0, Math.min(1.0, confidence)); }

    public String getReasoning() { return reasoning; }
    public void setReasoning(String reasoning) { this.reasoning = reasoning; }

    /**
     * 判断此推荐是否完整有效（所有必要字段均已填充）。
     */
    public boolean isValid() {
        return parameterName != null && !parameterName.isBlank()
                && attackType != null
                && technique != null;
    }

    @Override
    public String toString() {
        return "TechniqueRecommendation{" +
                "param='" + parameterName + '\'' +
                ", attackType=" + attackType +
                ", technique=" + technique +
                ", confidence=" + String.format("%.2f", confidence) +
                '}';
    }
}
