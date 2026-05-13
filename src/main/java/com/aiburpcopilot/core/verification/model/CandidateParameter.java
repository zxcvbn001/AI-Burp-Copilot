package com.aiburpcopilot.core.verification.model;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;
import com.aiburpcopilot.core.verification.util.RuleKeyUtil;

import java.util.ArrayList;
import java.util.List;

/**
 * Candidate 参数模型。
 * <p>
 * AI 分析识别出的候选验证参数，描述"哪些参数值得验证"。
 * 由 CandidateExtractor 从 AnalysisResult 中提取并规范化。
 * <p>
 * 与 HighValueParam 的区别：CandidateParameter 是验证引擎的内部模型，
 * 包含完整的 technique 推荐和溯源信息，而 HighValueParam 是 AI 的原始输出。
 */
public class CandidateParameter {

    /** 参数名 */
    private String parameterName;

    /** 参数类型（QUERY/BODY/HEADER/COOKIE/PATH） */
    private String parameterType;

    /** 攻击类型 */
    private AttackType attackType;
    private String attackTypeName;

    /** AI 置信度 (0.0 ~ 1.0) */
    private double confidence;

    /** AI 推理说明 */
    private String reasoning;

    /** 来源：AI_RECOMMENDATION / RULE_SUPPLEMENT / HEURISTIC_FALLBACK */
    private String source;

    /** 推荐的验证技术列表 */
    private List<VerificationTechnique> recommendedTechniques;

    public CandidateParameter() {
        this.recommendedTechniques = new ArrayList<>();
        this.confidence = 0.5;
    }

    public CandidateParameter(String parameterName, String parameterType, AttackType attackType,
                              double confidence, String reasoning, String source,
                              List<VerificationTechnique> recommendedTechniques) {
        this.parameterName = parameterName;
        this.parameterType = parameterType;
        setAttackType(attackType);
        this.confidence = confidence;
        this.reasoning = reasoning;
        this.source = source;
        this.recommendedTechniques = recommendedTechniques != null ? recommendedTechniques : new ArrayList<>();
    }

    // ---------- Getters & Setters ----------

    public String getParameterName() { return parameterName; }
    public void setParameterName(String parameterName) { this.parameterName = parameterName; }

    public String getParameterType() { return parameterType; }
    public void setParameterType(String parameterType) { this.parameterType = parameterType; }

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

    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = Math.max(0.0, Math.min(1.0, confidence)); }

    public String getReasoning() { return reasoning; }
    public void setReasoning(String reasoning) { this.reasoning = reasoning; }

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }

    public List<VerificationTechnique> getRecommendedTechniques() { return recommendedTechniques; }
    public void setRecommendedTechniques(List<VerificationTechnique> recommendedTechniques) {
        this.recommendedTechniques = recommendedTechniques != null ? recommendedTechniques : new ArrayList<>();
    }

    @Override
    public String toString() {
        return "CandidateParameter{" +
                "parameterName='" + parameterName + '\'' +
                ", parameterType='" + parameterType + '\'' +
                ", attackType=" + attackType +
                ", attackTypeName='" + getAttackTypeName() + '\'' +
                ", confidence=" + confidence +
                ", source='" + source + '\'' +
                ", techniques=" + recommendedTechniques +
                '}';
    }
}
