package com.aiburpcopilot.core.verification.model;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;

import java.util.ArrayList;
import java.util.List;

/**
 * Workflow 定义。
 * <p>
 * 定义某个 AttackType 的完整验证工作流：
 * 包含一系列 VerificationStep 的有序列表。
 * <p>
 * 设计原则：新增漏洞只需新增 WorkflowDefinition，不修改核心引擎。
 */
public class WorkflowDefinition {

    /** Workflow 关联的攻击类型 */
    private AttackType attackType;

    /** Workflow 名称 */
    private String name;

    /** Workflow 描述 */
    private String description;

    /** 步骤名称链（按顺序执行） */
    private List<String> stepNames;

    /** 是否需要在 Influence 验证通过后才执行 */
    private boolean requiresInfluenceApproval;

    /** 最大并发步骤数 */
    private int maxConcurrentSteps;

    public WorkflowDefinition() {
        this.stepNames = new ArrayList<>();
        this.requiresInfluenceApproval = true;
        this.maxConcurrentSteps = 1;
    }

    public WorkflowDefinition(AttackType attackType, String name, String description,
                              List<String> stepNames, boolean requiresInfluenceApproval) {
        this();
        this.attackType = attackType;
        this.name = name;
        this.description = description;
        this.stepNames = stepNames != null ? stepNames : new ArrayList<>();
        this.requiresInfluenceApproval = requiresInfluenceApproval;
    }

    // ---------- Getters & Setters ----------

    public AttackType getAttackType() { return attackType; }
    public void setAttackType(AttackType attackType) { this.attackType = attackType; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public List<String> getStepNames() { return stepNames; }
    public void setStepNames(List<String> stepNames) {
        this.stepNames = stepNames != null ? stepNames : new ArrayList<>();
    }

    public boolean isRequiresInfluenceApproval() { return requiresInfluenceApproval; }
    public void setRequiresInfluenceApproval(boolean requiresInfluenceApproval) {
        this.requiresInfluenceApproval = requiresInfluenceApproval;
    }

    public int getMaxConcurrentSteps() { return maxConcurrentSteps; }
    public void setMaxConcurrentSteps(int maxConcurrentSteps) {
        this.maxConcurrentSteps = Math.max(1, maxConcurrentSteps);
    }

    @Override
    public String toString() {
        return "WorkflowDefinition{" +
                "attackType=" + attackType +
                ", name='" + name + '\'' +
                ", steps=" + stepNames +
                ", requiresInfluenceApproval=" + requiresInfluenceApproval +
                '}';
    }
}
