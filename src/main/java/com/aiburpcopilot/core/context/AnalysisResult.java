package com.aiburpcopilot.core.context;

import com.aiburpcopilot.core.verification.technique.TechniqueRecommendation;

import java.util.ArrayList;
import java.util.List;

/**
 * AI 分析结果。
 * <p>
 * AI 攻击面分析的输出内容。
 * 包含攻击面类型、高价值参数、可疑漏洞类型和推荐测试思路。
 * <p>
 * 该类只记录"分析结论"，不做任何自动决策。
 * 所有结果仅供人工参考确认。
 */
public class AnalysisResult {

    /** 攻击面类型列表，例如：["参数注入", "权限绕过", "信息泄露"] */
    private List<String> attackSurface;

    /** 高价值参数列表，记录参数名及原因 */
    private List<HighValueParam> highValueParams;

    /** 可疑的漏洞类型列表，例如：["SQLI", "IDOR", "SSRF"] */
    private List<String> possibleVulnerabilities;

    /** 推荐的测试思路列表 */
    private List<String> recommendedTests;

    /** AI 分析总结 */
    private String summary;

    /** AI 推荐的结构化验证技术列表（Phase 2 架构修正新增） */
    private List<TechniqueRecommendation> recommendedTechniques;

    /** AI 原始返回（用于调试和审计） */
    private String rawResponse;

    /** AI 调用耗时（毫秒） */
    private long aiCallDurationMs;

    /** 分析错误信息（如有） */
    private String errorMessage;

    public AnalysisResult() {
        this.attackSurface = new ArrayList<>();
        this.highValueParams = new ArrayList<>();
        this.possibleVulnerabilities = new ArrayList<>();
        this.recommendedTests = new ArrayList<>();
        this.recommendedTechniques = new ArrayList<>();
    }

    // ---------- Nested Types ----------

    /**
     * 高价值参数记录。
     * 记录 AI 识别出的值得深入测试的参数及其原因。
     */
    public static class HighValueParam {
        private String paramName;
        private String reason;
        private RiskLevel riskLevel;

        public HighValueParam() {
            this.riskLevel = RiskLevel.MEDIUM;
        }

        public HighValueParam(String paramName, String reason, RiskLevel riskLevel) {
            this.paramName = paramName;
            this.reason = reason;
            this.riskLevel = riskLevel;
        }

        public String getParamName() {
            return paramName;
        }

        public void setParamName(String paramName) {
            this.paramName = paramName;
        }

        public String getReason() {
            return reason;
        }

        public void setReason(String reason) {
            this.reason = reason;
        }

        public RiskLevel getRiskLevel() {
            return riskLevel;
        }

        public void setRiskLevel(RiskLevel riskLevel) {
            this.riskLevel = riskLevel;
        }

        @Override
        public String toString() {
            return "HighValueParam{" +
                    "paramName='" + paramName + '\'' +
                    ", reason='" + reason + '\'' +
                    ", riskLevel=" + riskLevel +
                    '}';
        }
    }

    // ---------- Getters & Setters ----------

    public List<String> getAttackSurface() {
        return attackSurface;
    }

    public void setAttackSurface(List<String> attackSurface) {
        this.attackSurface = attackSurface;
    }

    public List<HighValueParam> getHighValueParams() {
        return highValueParams;
    }

    public void setHighValueParams(List<HighValueParam> highValueParams) {
        this.highValueParams = highValueParams;
    }

    public List<String> getPossibleVulnerabilities() {
        return possibleVulnerabilities;
    }

    public void setPossibleVulnerabilities(List<String> possibleVulnerabilities) {
        this.possibleVulnerabilities = possibleVulnerabilities;
    }

    public List<String> getRecommendedTests() {
        return recommendedTests;
    }

    public void setRecommendedTests(List<String> recommendedTests) {
        this.recommendedTests = recommendedTests;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public List<TechniqueRecommendation> getRecommendedTechniques() {
        return recommendedTechniques;
    }

    public void setRecommendedTechniques(List<TechniqueRecommendation> recommendedTechniques) {
        this.recommendedTechniques = recommendedTechniques != null ? recommendedTechniques : new ArrayList<>();
    }

    public String getRawResponse() {
        return rawResponse;
    }

    public void setRawResponse(String rawResponse) {
        this.rawResponse = rawResponse;
    }

    public long getAiCallDurationMs() {
        return aiCallDurationMs;
    }

    public void setAiCallDurationMs(long aiCallDurationMs) {
        this.aiCallDurationMs = aiCallDurationMs;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    /**
     * 判断 AI 分析是否成功完成。
     */
    public boolean isSuccess() {
        return errorMessage == null || errorMessage.isEmpty();
    }

    @Override
    public String toString() {
        return "AnalysisResult{" +
                "attackSurface=" + attackSurface +
                ", highValueParams=" + highValueParams +
                ", possibleVulnerabilities=" + possibleVulnerabilities +
                ", recommendedTechniques=" + recommendedTechniques +
                ", summary='" + summary + '\'' +
                '}';
    }
}
