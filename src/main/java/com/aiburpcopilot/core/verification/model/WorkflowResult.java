package com.aiburpcopilot.core.verification.model;

import com.aiburpcopilot.core.context.AttackType;

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

    /** 参数名 */
    private String parameterName;

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

    public WorkflowResult() {
        this.stepResults = new ArrayList<>();
        this.evidence = new ArrayList<>();
    }

    /**
     * 从步骤结果收集所有证据。
     */
    public void collectEvidence() {
        for (StepResult sr : stepResults) {
            if (sr.getEvidences() != null) {
                evidence.addAll(sr.getEvidences());
            }
        }
    }

    // ---------- Getters & Setters ----------

    public AttackType getAttackType() { return attackType; }
    public void setAttackType(AttackType attackType) { this.attackType = attackType; }

    public String getParameterName() { return parameterName; }
    public void setParameterName(String parameterName) { this.parameterName = parameterName; }

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

    @Override
    public String toString() {
        return "WorkflowResult{" +
                "attackType=" + attackType +
                ", parameterName='" + parameterName + '\'' +
                ", completed=" + completed +
                ", overallConfidence=" + overallConfidence +
                ", evidence=" + evidence.size() +
                '}';
    }
}
