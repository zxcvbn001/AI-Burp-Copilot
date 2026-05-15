package com.aiburpcopilot.core.verification.workflow;

import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.verification.model.*;
import com.aiburpcopilot.core.verification.policy.IPolicyEngine;
import com.aiburpcopilot.core.verification.influence.IReplayEngine;

import java.util.ArrayList;
import java.util.List;

/**
 * Workflow 上下文。
 * <p>
 * 在 Workflow 执行过程中传递共享数据。
 */
public class WorkflowContext {

    /** 原始 HTTP 上下文 */
    private final HTTPContext httpContext;

    /** 候选参数 */
    private final CandidateParameter candidate;
    private final String traceId;

    /** 参数特征 */
    private ParameterProfile parameterProfile;

    /** Influence 验证结果 */
    private InfluenceResult influenceResult;

    /** 策略引擎（用于查询允许的验证行为） */
    private IPolicyEngine policyEngine;

    /** Replay 引擎 */
    private IReplayEngine replayEngine;

    private boolean payloadVerificationAllowed = true;

    /** 收集到的所有证据 */
    private final List<Evidence> allEvidences = new ArrayList<>();

    /** 当前执行的工作流定义 */
    private WorkflowDefinition workflowDefinition;

    /** 原始请求/响应（基线） */
    private byte[] baselineRequest;
    private byte[] baselineResponse;

    /** 当前步骤索引 */
    private int currentStepIndex = 0;

    /** 是否已停止 */
    private boolean stopped = false;

    /** 停止原因 */
    private String stopReason;

    /** 最后的 Diff 结果 */
    private DiffResult lastDiffResult;

    /** 最后的变异值 */
    private String lastMutationValue;

    /** 最近一个 Step 的真实执行结果 */
    private StepResult lastStepResult;

    /** 工作流开始时间 */
    private final long startTime;

    public WorkflowContext(HTTPContext httpContext, CandidateParameter candidate) {
        this.httpContext = httpContext;
        this.candidate = candidate;
        this.traceId = buildTraceId(httpContext, candidate);
        this.baselineRequest = httpContext != null ? httpContext.getRawRequest() : null;
        this.baselineResponse = httpContext != null ? httpContext.getRawResponse() : null;
        this.startTime = System.currentTimeMillis();
    }

    /**
     * 添加证据。
     */
    public void addEvidence(Evidence evidence) {
        this.allEvidences.add(evidence);
    }

    /**
     * 停止工作流。
     */
    public void stop(String reason) {
        this.stopped = true;
        this.stopReason = reason;
    }

    /**
     * 获取工作流已运行时间（毫秒）。
     */
    public long getElapsedMs() {
        return System.currentTimeMillis() - startTime;
    }

    // ---------- Getters & Setters ----------

    public HTTPContext getHttpContext() { return httpContext; }
    public CandidateParameter getCandidate() { return candidate; }
    public String getTraceId() { return traceId; }

    public ParameterProfile getParameterProfile() { return parameterProfile; }
    public void setParameterProfile(ParameterProfile parameterProfile) { this.parameterProfile = parameterProfile; }

    public InfluenceResult getInfluenceResult() { return influenceResult; }
    public void setInfluenceResult(InfluenceResult influenceResult) { this.influenceResult = influenceResult; }

    public IPolicyEngine getPolicyEngine() { return policyEngine; }
    public void setPolicyEngine(IPolicyEngine policyEngine) { this.policyEngine = policyEngine; }

    public IReplayEngine getReplayEngine() { return replayEngine; }
    public void setReplayEngine(IReplayEngine replayEngine) { this.replayEngine = replayEngine; }

    public boolean isPayloadVerificationAllowed() { return payloadVerificationAllowed; }
    public void setPayloadVerificationAllowed(boolean payloadVerificationAllowed) {
        this.payloadVerificationAllowed = payloadVerificationAllowed;
    }

    public List<Evidence> getAllEvidences() { return allEvidences; }

    public WorkflowDefinition getWorkflowDefinition() { return workflowDefinition; }
    public void setWorkflowDefinition(WorkflowDefinition workflowDefinition) { this.workflowDefinition = workflowDefinition; }

    public byte[] getBaselineRequest() { return baselineRequest; }
    public void setBaselineRequest(byte[] baselineRequest) { this.baselineRequest = baselineRequest; }

    public byte[] getBaselineResponse() { return baselineResponse; }
    public void setBaselineResponse(byte[] baselineResponse) { this.baselineResponse = baselineResponse; }

    public int getCurrentStepIndex() { return currentStepIndex; }
    public void setCurrentStepIndex(int currentStepIndex) { this.currentStepIndex = currentStepIndex; }

    public boolean isStopped() { return stopped; }
    public String getStopReason() { return stopReason; }

    public DiffResult getLastDiffResult() { return lastDiffResult; }
    public void setLastDiffResult(DiffResult lastDiffResult) { this.lastDiffResult = lastDiffResult; }

    public String getLastMutationValue() { return lastMutationValue; }
    public void setLastMutationValue(String lastMutationValue) { this.lastMutationValue = lastMutationValue; }

    public StepResult getLastStepResult() { return lastStepResult; }
    public void setLastStepResult(StepResult lastStepResult) { this.lastStepResult = lastStepResult; }

    public long getStartTime() { return startTime; }

    private String buildTraceId(HTTPContext httpContext, CandidateParameter candidate) {
        String requestId = httpContext != null && httpContext.getRequestId() != null
                ? httpContext.getRequestId()
                : "no-request";
        String attackTypeName = candidate != null && candidate.getAttackTypeName() != null
                ? candidate.getAttackTypeName()
                : "UNKNOWN";
        String parameterName = candidate != null && candidate.getParameterName() != null
                ? candidate.getParameterName()
                : "endpoint";
        return requestId + "|" + attackTypeName + "|" + parameterName;
    }
}
