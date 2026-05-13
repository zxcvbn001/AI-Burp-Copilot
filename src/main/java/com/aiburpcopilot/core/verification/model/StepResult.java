package com.aiburpcopilot.core.verification.model;

import java.util.ArrayList;
import java.util.List;

/**
 * VerificationStep 执行结果。
 * <p>
 * 每个 VerificationStep 执行后返回 StepResult，
 * Workflow Engine 根据 StepResult 决定是否继续下一步。
 */
public class StepResult {

    /** 步骤是否成功执行 */
    private boolean success;

    /** 步骤置信度 (0.0 ~ 1.0) */
    private double confidence;

    /** 是否继续工作流 */
    private boolean continueWorkflow;

    /** 收集到的证据列表 */
    private List<Evidence> evidences;

    /** 步骤推理说明 */
    private String reasoning;

    /** 步骤名称 */
    private String stepName;

    /** 步骤执行耗时（毫秒） */
    private long durationMs;

    /** 附加数据（可选） */
    private Object data;

    private String phase;
    private String payload;
    private StrategyType strategyType;
    private DiffResult diffResult;
    private int responseLength;
    private byte[] requestBytes;
    private byte[] responseBytes;
    private String exchangeTranscript;
    private String llmReview;

    public StepResult() {
        this.evidences = new ArrayList<>();
        this.continueWorkflow = true;
    }

    public StepResult(boolean success, double confidence, boolean continueWorkflow,
                      String stepName, String reasoning) {
        this();
        this.success = success;
        this.confidence = confidence;
        this.continueWorkflow = continueWorkflow;
        this.stepName = stepName;
        this.reasoning = reasoning;
    }

    /**
     * 创建成功结果。
     */
    public static StepResult success(String stepName, String reasoning) {
        return new StepResult(true, 0.8, true, stepName, reasoning);
    }

    /**
     * 创建失败但可继续的结果。
     */
    public static StepResult softFail(String stepName, String reasoning) {
        return new StepResult(false, 0.3, true, stepName, reasoning);
    }

    /**
     * 创建失败且停止工作流的结果。
     */
    public static StepResult hardFail(String stepName, String reasoning) {
        return new StepResult(false, 0.0, false, stepName, reasoning);
    }

    /**
     * 添加证据。
     */
    public StepResult addEvidence(Evidence evidence) {
        this.evidences.add(evidence);
        return this;
    }

    // ---------- Getters & Setters ----------

    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }

    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = Math.max(0.0, Math.min(1.0, confidence)); }

    public boolean isContinueWorkflow() { return continueWorkflow; }
    public void setContinueWorkflow(boolean continueWorkflow) { this.continueWorkflow = continueWorkflow; }

    public List<Evidence> getEvidences() { return evidences; }
    public void setEvidences(List<Evidence> evidences) {
        this.evidences = evidences != null ? evidences : new ArrayList<>();
    }

    public String getReasoning() { return reasoning; }
    public void setReasoning(String reasoning) { this.reasoning = reasoning; }

    public String getStepName() { return stepName; }
    public void setStepName(String stepName) { this.stepName = stepName; }

    public long getDurationMs() { return durationMs; }
    public void setDurationMs(long durationMs) { this.durationMs = durationMs; }

    public Object getData() { return data; }
    public void setData(Object data) { this.data = data; }

    public String getPhase() { return phase; }
    public void setPhase(String phase) { this.phase = phase; }

    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }

    public StrategyType getStrategyType() { return strategyType; }
    public void setStrategyType(StrategyType strategyType) { this.strategyType = strategyType; }

    public DiffResult getDiffResult() { return diffResult; }
    public void setDiffResult(DiffResult diffResult) { this.diffResult = diffResult; }

    public int getResponseLength() { return responseLength; }
    public void setResponseLength(int responseLength) { this.responseLength = responseLength; }

    public byte[] getRequestBytes() { return requestBytes; }
    public void setRequestBytes(byte[] requestBytes) { this.requestBytes = requestBytes; }

    public byte[] getResponseBytes() { return responseBytes; }
    public void setResponseBytes(byte[] responseBytes) { this.responseBytes = responseBytes; }

    public String getExchangeTranscript() { return exchangeTranscript; }
    public void setExchangeTranscript(String exchangeTranscript) { this.exchangeTranscript = exchangeTranscript; }

    public String getLlmReview() { return llmReview; }
    public void setLlmReview(String llmReview) { this.llmReview = llmReview; }

    @Override
    public String toString() {
        return "StepResult{" +
                "step='" + stepName + '\'' +
                ", success=" + success +
                ", confidence=" + confidence +
                ", continueWorkflow=" + continueWorkflow +
                ", evidences=" + evidences.size() +
                '}';
    }
}
