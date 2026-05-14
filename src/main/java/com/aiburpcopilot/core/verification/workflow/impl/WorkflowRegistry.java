package com.aiburpcopilot.core.verification.workflow.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.WorkflowDefinition;
import com.aiburpcopilot.core.verification.payload.IPayloadRuleEngine;
import com.aiburpcopilot.core.verification.payload.RuleWorkflowConfig;
import com.aiburpcopilot.core.verification.util.RuleKeyUtil;
import com.aiburpcopilot.core.verification.workflow.IWorkflowRegistry;
import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe workflow registry. It only stores workflow definitions; built-in
 * workflows are generated from YAML rules, not hard-coded in the engine.
 */
public class WorkflowRegistry implements IWorkflowRegistry {

    private static final Logger log = LoggerFactory.getLogger(WorkflowRegistry.class);

    private final Map<String, WorkflowDefinition> registry = new ConcurrentHashMap<>();

    @Override
    public void register(WorkflowDefinition workflow) {
        String key = workflow != null ? RuleKeyUtil.normalize(workflow.getAttackTypeName()) : null;
        if (workflow == null || key == null) {
            log.warn("WorkflowRegistry refused to register null workflow or null attackTypeName");
            PluginLogger.getInstance().warn(PluginLogger.Category.VERIFICATION,
                    "WorkflowRegistry", "Refused to register null workflow");
            return;
        }

        WorkflowDefinition previous = registry.put(key, workflow);
        PluginLogger.getInstance().info(PluginLogger.Category.VERIFICATION, "WorkflowRegistry",
                "Registered workflow: " + workflow.getName()
                        + " for " + key
                        + " | steps=" + (workflow.getStepNames() != null ? workflow.getStepNames().size() : 0)
                        + (previous != null ? " (replaced: " + previous.getName() + ")" : "")
                        + " | total=" + registry.size());
    }

    @Override
    public Optional<WorkflowDefinition> findWorkflow(String attackTypeName) {
        String key = RuleKeyUtil.normalize(attackTypeName);
        return key != null ? Optional.ofNullable(registry.get(key)) : Optional.empty();
    }

    @Override
    public int getCount() {
        return registry.size();
    }

    public static WorkflowRegistry fromRules(IPayloadRuleEngine payloadRuleEngine) {
        WorkflowRegistry registry = new WorkflowRegistry();
        if (payloadRuleEngine != null) {
            for (String attackTypeName : payloadRuleEngine.getRuleCapabilityNames().keySet()) {
                registry.register(createRuleWorkflow(payloadRuleEngine, attackTypeName));
            }
        }
        return registry;
    }

    private static WorkflowDefinition createRuleWorkflow(IPayloadRuleEngine payloadRuleEngine,
                                                         AttackType attackType) {
        return createRuleWorkflow(payloadRuleEngine, attackType != null ? attackType.name() : null);
    }

    private static WorkflowDefinition createRuleWorkflow(IPayloadRuleEngine payloadRuleEngine,
                                                         String attackTypeName) {
        RuleWorkflowConfig config = payloadRuleEngine.getWorkflowConfig(attackTypeName);
        java.util.List<String> steps = new java.util.ArrayList<>();
        if (config.isIncludeInfluenceStep()) {
            steps.add(InfluenceValidationStep.STEP_NAME);
        }
        steps.add(WorkflowStepFactory.probeStepName(attackTypeName));
        WorkflowDefinition workflow = new WorkflowDefinition();
        workflow.setAttackTypeName(attackTypeName);
        workflow.setName(config.getName() != null ? config.getName() : attackTypeName + " Verification");
        workflow.setDescription(config.getDescription() != null ? config.getDescription() : "Rule-driven verification loaded from payload YAML");
        workflow.setStepNames(steps);
        workflow.setRequiresInfluenceApproval(config.isRequiresInfluenceApproval());
        workflow.setIncludeInfluenceStep(config.isIncludeInfluenceStep());
        return workflow;
    }
}
