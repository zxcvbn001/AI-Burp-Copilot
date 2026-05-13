package com.aiburpcopilot.core.verification.plugins.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.WorkflowDefinition;
import com.aiburpcopilot.core.verification.plugins.IPlugin;
import com.aiburpcopilot.core.verification.workflow.VerificationStep;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * SQL Injection verification plugin.
 * <p>
 * Provides a workflow definition. Probe execution is handled by GenericProbeStep.
 */
public class SqliPlugin implements IPlugin {

    private boolean enabled = true;

    @Override
    public String getPluginId() { return "sqli"; }

    @Override
    public String getName() { return "SQL Injection"; }

    @Override
    public String getDescription() { return "Verifies SQL injection vulnerabilities using boolean and error-based techniques"; }

    @Override
    public List<VerificationStep> getSteps() {
        return Collections.emptyList();
    }

    @Override
    public WorkflowDefinition getWorkflow() {
        return new WorkflowDefinition(
                AttackType.SQLI,
                "SQL Injection Verification",
                "Validates SQL injection by aggregating minimal probe evidence",
                Arrays.asList("InfluenceValidation", "SQLIProbes"),
                true
        );
    }

    @Override
    public boolean isEnabled() { return enabled; }

    @Override
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
}
