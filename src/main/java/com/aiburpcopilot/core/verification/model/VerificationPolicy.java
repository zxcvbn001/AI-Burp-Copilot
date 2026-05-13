package com.aiburpcopilot.core.verification.model;

/**
 * 验证策略配置。
 * <p>
 * 控制哪些验证行为允许执行。策略是全局的运行时配置，
 * 由 PolicyEngine 加载和管理。
 */
public class VerificationPolicy {

    /** 是否允许基于时间的验证（TIME_BASED） */
    private boolean allowTimeBased = false;

    /** 是否允许联合查询验证（UNION_BASED） */
    private boolean allowUnionBased = false;

    /** 是否允许基于错误的验证（ERROR_BASED） */
    private boolean allowErrorBased = true;

    /** 最大重放请求数（每个端点） */
    private int maxReplayRequests = 5;

    /** 最大参数测试数（每个端点） */
    private int maxParameterTests = 20;

    /** 最小影响性评分阈值（低于此值跳过验证） */
    private double minInfluenceScore = 0.1;

    /** 是否启用验证 */
    private boolean enabled = true;

    /** 请求超时时间（毫秒） */
    private int requestTimeoutMs = 5000;

    /** 最大 payload 长度 */
    private int maxPayloadLength = 128;

    /** URL 白名单（允许验证的主机列表） */
    private java.util.List<String> whitelist = new java.util.ArrayList<>();

    // ---------- Getters & Setters ----------

    public boolean isAllowTimeBased() { return allowTimeBased; }
    public void setAllowTimeBased(boolean allowTimeBased) { this.allowTimeBased = allowTimeBased; }

    public boolean isAllowUnionBased() { return allowUnionBased; }
    public void setAllowUnionBased(boolean allowUnionBased) { this.allowUnionBased = allowUnionBased; }

    public boolean isAllowErrorBased() { return allowErrorBased; }
    public void setAllowErrorBased(boolean allowErrorBased) { this.allowErrorBased = allowErrorBased; }

    public int getMaxReplayRequests() { return maxReplayRequests; }
    public void setMaxReplayRequests(int maxReplayRequests) { this.maxReplayRequests = maxReplayRequests; }

    public int getMaxParameterTests() { return maxParameterTests; }
    public void setMaxParameterTests(int maxParameterTests) { this.maxParameterTests = maxParameterTests; }

    public double getMinInfluenceScore() { return minInfluenceScore; }
    public void setMinInfluenceScore(double minInfluenceScore) {
        this.minInfluenceScore = Math.max(0.0, Math.min(1.0, minInfluenceScore));
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public int getRequestTimeoutMs() { return requestTimeoutMs; }
    public void setRequestTimeoutMs(int requestTimeoutMs) { this.requestTimeoutMs = requestTimeoutMs; }

    public int getMaxPayloadLength() { return maxPayloadLength; }
    public void setMaxPayloadLength(int maxPayloadLength) { this.maxPayloadLength = maxPayloadLength; }

    public java.util.List<String> getWhitelist() { return whitelist; }
    public void setWhitelist(java.util.List<String> whitelist) {
        this.whitelist = whitelist != null ? whitelist : new java.util.ArrayList<>();
    }

    @Override
    public String toString() {
        return "VerificationPolicy{" +
                "enabled=" + enabled +
                ", allowTimeBased=" + allowTimeBased +
                ", allowUnionBased=" + allowUnionBased +
                ", allowErrorBased=" + allowErrorBased +
                ", maxReplayRequests=" + maxReplayRequests +
                ", maxParameterTests=" + maxParameterTests +
                ", minInfluenceScore=" + minInfluenceScore +
                ", whitelisted hosts=" + (whitelist != null ? whitelist.size() : 0) +
                '}';
    }
}
