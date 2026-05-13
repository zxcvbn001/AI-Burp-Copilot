package com.aiburpcopilot.core.verification.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Influence 验证结果。
 * <p>
 * 封装 Influence Layer 的完整验证结果：
 * 参数影响性评分、重放状态、Diff 分析摘要等。
 */
public class InfluenceResult {

    /** 参数名 */
    private String parameterName;

    /** 影响性评分 (0.0 ~ 1.0) */
    private double influenceScore;

    /** 是否通过批准（可否进入后续 Technique 验证） */
    private boolean approved;
    private InfluenceStatus status = InfluenceStatus.NOT_INFLUENTIAL;

    /** 批准/拒绝原因 */
    private String approvalReason;

    /** 重放是否成功 */
    private boolean replaySuccess;

    /** Diff 分析结果 */
    private DiffResult diffResult;

    /** 参数类型特征 */
    private ParameterProfile parameterProfile;

    /** 使用的变异值列表 */
    private List<String> mutationValues;

    /** 验证详情 */
    private List<String> details;

    public InfluenceResult() {
        this.influenceScore = 0.0;
        this.approved = false;
        this.replaySuccess = false;
        this.mutationValues = new ArrayList<>();
        this.details = new ArrayList<>();
    }

    /**
     * 判断参数是否有影响性。
     * influenceScore >= 0.1 视为有影响。
     */
    public boolean hasInfluence() {
        return status == InfluenceStatus.INFLUENTIAL
                || status == InfluenceStatus.UNCERTAIN
                || influenceScore >= 0.1;
    }

    // ---------- Getters & Setters ----------

    public String getParameterName() { return parameterName; }
    public void setParameterName(String parameterName) { this.parameterName = parameterName; }

    public double getInfluenceScore() { return influenceScore; }
    public void setInfluenceScore(double influenceScore) {
        this.influenceScore = Math.max(0.0, Math.min(1.0, influenceScore));
    }

    public boolean isApproved() { return approved; }
    public void setApproved(boolean approved) { this.approved = approved; }

    public InfluenceStatus getStatus() { return status; }
    public void setStatus(InfluenceStatus status) {
        this.status = status != null ? status : InfluenceStatus.NOT_INFLUENTIAL;
    }

    public boolean isUncertain() { return status == InfluenceStatus.UNCERTAIN; }

    public String getApprovalReason() { return approvalReason; }
    public void setApprovalReason(String approvalReason) { this.approvalReason = approvalReason; }

    public boolean isReplaySuccess() { return replaySuccess; }
    public void setReplaySuccess(boolean replaySuccess) { this.replaySuccess = replaySuccess; }

    public DiffResult getDiffResult() { return diffResult; }
    public void setDiffResult(DiffResult diffResult) { this.diffResult = diffResult; }

    public ParameterProfile getParameterProfile() { return parameterProfile; }
    public void setParameterProfile(ParameterProfile parameterProfile) { this.parameterProfile = parameterProfile; }

    public List<String> getMutationValues() { return mutationValues; }
    public void setMutationValues(List<String> mutationValues) {
        this.mutationValues = mutationValues != null ? mutationValues : new ArrayList<>();
    }

    public List<String> getDetails() { return details; }
    public void setDetails(List<String> details) {
        this.details = details != null ? details : new ArrayList<>();
    }

    @Override
    public String toString() {
        return "InfluenceResult{" +
                "parameterName='" + parameterName + '\'' +
                ", influenceScore=" + influenceScore +
                ", approved=" + approved +
                ", replaySuccess=" + replaySuccess +
                '}';
    }
}
