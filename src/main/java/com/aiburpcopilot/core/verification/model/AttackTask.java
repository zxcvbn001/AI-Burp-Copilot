package com.aiburpcopilot.core.verification.model;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.context.HTTPContext;

import java.util.UUID;

/**
 * 攻击验证任务。
 * <p>
 * 封装一次安全验证请求的完整信息：
 * 原始 HTTP 上下文、攻击类型、目标参数、
 * 测试策略以及具体 payload。
 * <p>
 * Legacy task model used by mutators and the execution engine compatibility API.
 */
public class AttackTask {

    /** 任务唯一标识 */
    private UUID taskId;

    /** 原始 HTTP 请求上下文（包含完整请求/响应信息） */
    private HTTPContext baseRequest;

    /** 攻击类型 */
    private AttackType attackType;

    /** 目标参数名 */
    private String parameterName;

    /** 测试策略类型 */
    private StrategyType strategyType;

    /** 具体 payload */
    private String payload;

    /** 任务创建时间 */
    private long createdAt;

    public AttackTask() {
        this.taskId = UUID.randomUUID();
        this.createdAt = System.currentTimeMillis();
    }

    public AttackTask(HTTPContext baseRequest, AttackType attackType,
                      String parameterName, StrategyType strategyType,
                      String payload) {
        this();
        this.baseRequest = baseRequest;
        this.attackType = attackType;
        this.parameterName = parameterName;
        this.strategyType = strategyType;
        this.payload = payload;
    }

    // ---------- Getters & Setters ----------

    public UUID getTaskId() { return taskId; }
    public void setTaskId(UUID taskId) { this.taskId = taskId; }

    public HTTPContext getBaseRequest() { return baseRequest; }
    public void setBaseRequest(HTTPContext baseRequest) { this.baseRequest = baseRequest; }

    public AttackType getAttackType() { return attackType; }
    public void setAttackType(AttackType attackType) { this.attackType = attackType; }

    public String getParameterName() { return parameterName; }
    public void setParameterName(String parameterName) { this.parameterName = parameterName; }

    public StrategyType getStrategyType() { return strategyType; }
    public void setStrategyType(StrategyType strategyType) { this.strategyType = strategyType; }

    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }

    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }

    @Override
    public String toString() {
        return "AttackTask{" +
                "taskId=" + taskId +
                ", attackType=" + attackType +
                ", parameter='" + parameterName + '\'' +
                ", strategyType=" + strategyType +
                ", payload='" + payload + '\'' +
                '}';
    }
}
