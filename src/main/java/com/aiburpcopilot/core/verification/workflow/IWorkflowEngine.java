package com.aiburpcopilot.core.verification.workflow;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.WorkflowResult;

/**
 * Workflow 引擎接口。
 * <p>
 * 负责组织验证步骤、控制顺序、Step Gate、停止条件、Evidence Merge。
 * <p>
 * Workflow Engine 是通用引擎，不针对特定漏洞类型。
 */
public interface IWorkflowEngine {

    /**
     * 执行指定攻击类型的完整工作流。
     *
     * @param context Workflow 上下文
     * @return 工作流执行结果
     */
    WorkflowResult execute(WorkflowContext context);

    /**
     * 执行工作流中的单个步骤。
     *
     * @param context   Workflow 上下文
     * @param stepName  步骤名称
     * @param step      步骤实现
     * @return 步骤执行结果
     */
    WorkflowContext executeStep(WorkflowContext context, String stepName, VerificationStep step);

    /**
     * 停止指定上下文的工作流。
     */
    void stop(WorkflowContext context);

    /**
     * 注册 VerificationStep 实现。
     *
     * @param stepName 步骤名称
     * @param step     步骤实现
     */
    void registerStep(String stepName, VerificationStep step);

    /**
     * 根据名称查找步骤。
     */
    VerificationStep findStep(String stepName);
}
