package com.aiburpcopilot.core.verification.plugins.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.WorkflowDefinition;
import com.aiburpcopilot.core.verification.plugins.IPlugin;
import com.aiburpcopilot.core.verification.workflow.VerificationStep;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * IDOR (Insecure Direct Object Reference) verification plugin.
 * <p>
 * Provides a workflow definition. Probe execution is handled by GenericProbeStep.
 */
public class IdorPlugin implements IPlugin {

    private boolean enabled = true;

    @Override
    public String getPluginId() { return "idor"; }

    @Override
    public String getName() { return "IDOR"; }

    @Override
    public String getDescription() { return "Verifies IDOR vulnerabilities using numeric increment, UUID swap, and auth context checks"; }

    @Override
    public List<VerificationStep> getSteps() {
        return Collections.emptyList();
    }

    @Override
    public WorkflowDefinition getWorkflow() {
        return new WorkflowDefinition(
                AttackType.IDOR,
                "IDOR Verification",
                "Validates IDOR by attempting resource access with modified identifiers",
                Arrays.asList("InfluenceValidation", "IDORProbes"),
                true
        );
    }

    @Override
    public boolean isEnabled() { return enabled; }

    @Override
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
}
