package com.aiburpcopilot.core.verification.plugins.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.WorkflowDefinition;
import com.aiburpcopilot.core.verification.plugins.IPlugin;
import com.aiburpcopilot.core.verification.workflow.VerificationStep;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * XSS verification plugin.
 * <p>
 * Built-in plugins own workflow metadata only. Executable steps are assembled
 * by WorkflowStepFactory so placeholders cannot override real deterministic
 * verification steps.
 */
public class XssPlugin implements IPlugin {

    private boolean enabled = true;

    @Override
    public String getPluginId() { return "xss"; }

    @Override
    public String getName() { return "Cross-Site Scripting"; }

    @Override
    public String getDescription() { return "Verifies reflected XSS using deterministic replay and reflection evidence"; }

    @Override
    public List<VerificationStep> getSteps() {
        return Collections.emptyList();
    }

    @Override
    public WorkflowDefinition getWorkflow() {
        return new WorkflowDefinition(
                AttackType.XSS,
                "XSS Verification",
                "Validates reflected XSS by aggregating harmless reflection probes",
                Arrays.asList("InfluenceValidation", "XSSProbes"),
                true
        );
    }

    @Override
    public boolean isEnabled() { return enabled; }

    @Override
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
}
