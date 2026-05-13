package com.aiburpcopilot.core.verification.workflow.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.WorkflowDefinition;
import com.aiburpcopilot.core.verification.plugins.impl.PluginRegistry;
import com.aiburpcopilot.core.verification.workflow.IWorkflowRegistry;
import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe workflow registry. It only stores workflow definitions; built-in
 * workflows are provided by PluginRegistry, not hard-coded in the engine.
 */
public class WorkflowRegistry implements IWorkflowRegistry {

    private static final Logger log = LoggerFactory.getLogger(WorkflowRegistry.class);

    private final Map<AttackType, WorkflowDefinition> registry = new ConcurrentHashMap<>();

    @Override
    public void register(WorkflowDefinition workflow) {
        if (workflow == null || workflow.getAttackType() == null) {
            log.warn("WorkflowRegistry refused to register null workflow or null attackType");
            PluginLogger.getInstance().warn("WorkflowRegistry", "Refused to register null workflow");
            return;
        }

        AttackType key = workflow.getAttackType();
        WorkflowDefinition previous = registry.put(key, workflow);
        PluginLogger.getInstance().info("WorkflowRegistry",
                "Registered workflow: " + workflow.getName()
                        + " for " + key
                        + " | steps=" + (workflow.getStepNames() != null ? workflow.getStepNames().size() : 0)
                        + (previous != null ? " (replaced: " + previous.getName() + ")" : "")
                        + " | total=" + registry.size());
    }

    @Override
    public Optional<WorkflowDefinition> findWorkflow(AttackType attackType) {
        if (attackType == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(registry.get(attackType));
    }

    @Override
    public int getCount() {
        return registry.size();
    }

    public static WorkflowRegistry fromPlugins(PluginRegistry pluginRegistry) {
        WorkflowRegistry registry = new WorkflowRegistry();
        if (pluginRegistry == null) {
            return registry;
        }
        for (WorkflowDefinition workflow : pluginRegistry.getAllWorkflows()) {
            registry.register(workflow);
        }
        return registry;
    }
}
