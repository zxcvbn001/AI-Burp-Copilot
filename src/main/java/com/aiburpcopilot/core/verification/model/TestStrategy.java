package com.aiburpcopilot.core.verification.model;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;

import java.util.ArrayList;
import java.util.List;

/**
 * 测试策略。
 * <p>
 * Technique mapper model generated from AI recommendations,
 * 描述"如何测试"特定参数而不生成具体 payload。
 * <p>
 * 架构修正后新增 {@code technique} 字段：
 * AI 推荐 VerificationTechnique → ITechniqueMapper 映射到 StrategyType →
 * Payload 引擎生成具体 payload。
 * <p>
 * 关系链：
 * <pre>
 *   AttackType → VerificationTechnique → StrategyType → Payload
 * </pre>
 */
public class TestStrategy {

    /** 攻击类型 */
    private AttackType attackType;

    /** 目标参数名 */
    private String parameterName;

    /** 验证技术（Phase 2 架构修正新增） */
    private VerificationTechnique technique;

    /** 推荐的测试策略列表（向后兼容，通常从 technique 映射得到） */
    private List<StrategyType> strategies;

    /** AI 对该策略的置信度 (0.0 ~ 1.0) */
    private double confidence;

    /** AI 的推理说明 */
    private String reasoning;

    public TestStrategy() {
        this.strategies = new ArrayList<>();
        this.confidence = 0.5;
    }

    /**
     * 创建测试策略（无 technique，向后兼容）。
     */
    public TestStrategy(AttackType attackType, String parameterName,
                        List<StrategyType> strategies, double confidence,
                        String reasoning) {
        this.attackType = attackType;
        this.parameterName = parameterName;
        this.technique = null;
        this.strategies = strategies != null ? strategies : new ArrayList<>();
        this.confidence = confidence;
        this.reasoning = reasoning;
    }

    /**
     * 创建测试策略（带 technique，Phase 2 架构修正推荐）。
     */
    public TestStrategy(AttackType attackType, String parameterName,
                        VerificationTechnique technique, List<StrategyType> strategies,
                        double confidence, String reasoning) {
        this.attackType = attackType;
        this.parameterName = parameterName;
        this.technique = technique;
        this.strategies = strategies != null ? strategies : new ArrayList<>();
        this.confidence = confidence;
        this.reasoning = reasoning;
    }

    // ---------- Getters & Setters ----------

    public AttackType getAttackType() { return attackType; }
    public void setAttackType(AttackType attackType) { this.attackType = attackType; }

    public String getParameterName() { return parameterName; }
    public void setParameterName(String parameterName) { this.parameterName = parameterName; }

    public VerificationTechnique getTechnique() { return technique; }
    public void setTechnique(VerificationTechnique technique) { this.technique = technique; }

    public List<StrategyType> getStrategies() { return strategies; }
    public void setStrategies(List<StrategyType> strategies) { this.strategies = strategies; }

    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = Math.max(0.0, Math.min(1.0, confidence)); }

    public String getReasoning() { return reasoning; }
    public void setReasoning(String reasoning) { this.reasoning = reasoning; }

    /**
     * 获取主策略类型（取列表第一个，兼容旧代码）。
     *
     * @return 主 StrategyType，若列表为空返回 BOOLEAN_BASED_MINIMAL
     */
    public StrategyType getPrimaryStrategy() {
        return strategies != null && !strategies.isEmpty()
                ? strategies.get(0)
                : StrategyType.BOOLEAN_BASED_MINIMAL;
    }

    @Override
    public String toString() {
        return "TestStrategy{" +
                "attackType=" + attackType +
                ", parameterName='" + parameterName + '\'' +
                ", technique=" + technique +
                ", strategies=" + strategies +
                ", confidence=" + confidence +
                ", reasoning='" + reasoning + '\'' +
                '}';
    }
}
