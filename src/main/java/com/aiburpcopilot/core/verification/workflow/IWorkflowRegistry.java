package com.aiburpcopilot.core.verification.workflow;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.WorkflowDefinition;

import java.util.Optional;

/**
 * Workflow 注册中心接口。
 * <p>
 * 管理所有 WorkflowDefinition，按 AttackType 查找对应的工作流。
 */
public interface IWorkflowRegistry {

    /**
     * 注册一个 Workflow。
     */
    void register(WorkflowDefinition workflow);

    /**
     * 根据攻击类型查找对应的 Workflow。
     */
    Optional<WorkflowDefinition> findWorkflow(AttackType attackType);

    /**
     * 获取已注册的 Workflow 数量。
     */
    int getCount();
}
