package com.aiburpcopilot.core.verification.workflow;

import com.aiburpcopilot.core.verification.model.StepResult;

/**
 * VerificationStep 接口。
 * <p>
 * 所有漏洞验证必须基于 VerificationStep 实现。
 * 每个 Step 执行一个独立的验证操作。
 */
public interface VerificationStep {

    /**
     * 执行验证步骤。
     *
     * @param context Workflow 上下文
     * @return 步骤执行结果
     */
    StepResult execute(WorkflowContext context);

    /**
     * 获取步骤名称。
     */
    String getName();
}
