package com.aiburpcopilot.core.verification.plugins.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.WorkflowDefinition;
import com.aiburpcopilot.core.verification.plugins.IPlugin;
import com.aiburpcopilot.core.verification.workflow.VerificationStep;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class PathTraversalPlugin implements IPlugin {

    private boolean enabled = true;

    @Override
    public String getPluginId() { return "path_traversal"; }

    @Override
    public String getName() { return "Path Traversal"; }

    @Override
    public String getDescription() { return "Verifies path traversal using local YAML payload rules"; }

    @Override
    public List<VerificationStep> getSteps() {
        return Collections.emptyList();
    }

    @Override
    public WorkflowDefinition getWorkflow() {
        return new WorkflowDefinition(
                AttackType.PATH_TRAVERSAL,
                "Path Traversal Verification",
                "Validates path traversal by replaying local file path payload rules",
                Arrays.asList("InfluenceValidation", "PathTraversalProbes"),
                true
        );
    }

    @Override
    public boolean isEnabled() { return enabled; }

    @Override
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
}
