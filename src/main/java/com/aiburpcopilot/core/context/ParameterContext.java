package com.aiburpcopilot.core.context;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * 参数上下文。
 * <p>
 * 描述 HTTP 请求中的单个参数的详细信息。
 * 包括参数名称、样本值、位置类型、AI 分析后的语义含义、
 * 风险等级以及推荐的测试方向。
 * <p>
 * 该类在 Phase 1 由 AI 攻击面分析填充语义信息，
 * Phase 2 将由 TestStrategyGenerator 填充 possibleTests。
 */
public class ParameterContext {

    /** 参数名称 */
    private String name;

    /** 参数样本值（脱敏处理后的值，不包含敏感 Cookie/Token） */
    private String value;

    /** 参数位置类型 */
    private ParameterType type;

    /** AI 分析的参数语义含义，例如："用户ID"、"搜索关键词"、"回调URL" */
    private String semanticMeaning;

    /** AI 评估的风险等级 */
    private RiskLevel riskLevel;

    /** 推荐的测试方向列表，例如：["SQL注入", "IDOR", "XSS"] */
    private List<String> possibleTests;

    public ParameterContext() {
        this.riskLevel = RiskLevel.INFO;
        this.possibleTests = new ArrayList<>();
    }

    public ParameterContext(String name, String value, ParameterType type) {
        this();
        this.name = name;
        this.value = value;
        this.type = type;
    }

    // ---------- Getters & Setters ----------

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public ParameterType getType() {
        return type;
    }

    public void setType(ParameterType type) {
        this.type = type;
    }

    public String getSemanticMeaning() {
        return semanticMeaning;
    }

    public void setSemanticMeaning(String semanticMeaning) {
        this.semanticMeaning = semanticMeaning;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(RiskLevel riskLevel) {
        this.riskLevel = riskLevel;
    }

    public List<String> getPossibleTests() {
        return possibleTests;
    }

    public void setPossibleTests(List<String> possibleTests) {
        this.possibleTests = possibleTests;
    }

    public void addPossibleTest(String test) {
        this.possibleTests.add(test);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ParameterContext that = (ParameterContext) o;
        return Objects.equals(name, that.name) && type == that.type;
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, type);
    }

    @Override
    public String toString() {
        return "ParameterContext{" +
                "name='" + name + '\'' +
                ", type=" + type +
                ", riskLevel=" + riskLevel +
                ", semanticMeaning='" + semanticMeaning + '\'' +
                '}';
    }
}
