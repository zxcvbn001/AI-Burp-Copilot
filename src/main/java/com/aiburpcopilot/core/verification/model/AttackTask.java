package com.aiburpcopilot.core.verification.model;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.verification.util.RuleKeyUtil;

import java.util.UUID;

public class AttackTask {

    private UUID taskId;
    private HTTPContext baseRequest;
    private AttackType attackType;
    private String attackTypeName;
    private String parameterName;
    private StrategyType strategyType;
    private String payload;
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
        setAttackType(attackType);
        this.parameterName = parameterName;
        this.strategyType = strategyType;
        this.payload = payload;
    }

    public UUID getTaskId() { return taskId; }
    public void setTaskId(UUID taskId) { this.taskId = taskId; }

    public HTTPContext getBaseRequest() { return baseRequest; }
    public void setBaseRequest(HTTPContext baseRequest) { this.baseRequest = baseRequest; }

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
                ", attackTypeName='" + getAttackTypeName() + '\'' +
                ", parameter='" + parameterName + '\'' +
                ", strategyType=" + strategyType +
                ", payload='" + payload + '\'' +
                '}';
    }
}
