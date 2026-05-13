package com.aiburpcopilot.core.verification.plugins;

import com.aiburpcopilot.core.verification.workflow.VerificationStep;
import com.aiburpcopilot.core.verification.model.WorkflowDefinition;

import java.util.List;

/**
 * Plugin interface for verification plugins.
 * <p>
 * All verification plugins must implement this interface. Each plugin
 * provides a set of VerificationSteps and a WorkflowDefinition that
 * describes how those steps are composed into a verification workflow
 * for a specific attack type.
 */
public interface IPlugin {

    /**
     * Returns the unique plugin identifier (e.g. "sqli", "idor").
     */
    String getPluginId();

    /**
     * Returns the human-readable display name of this plugin.
     */
    String getName();

    /**
     * Returns a description of what this plugin verifies.
     */
    String getDescription();

    /**
     * Returns all VerificationSteps provided by this plugin.
     */
    List<VerificationStep> getSteps();

    /**
     * Returns the WorkflowDefinition that composes this plugin's steps
     * into a complete verification workflow.
     */
    WorkflowDefinition getWorkflow();

    /**
     * Returns whether this plugin is currently enabled.
     */
    boolean isEnabled();

    /**
     * Enables or disables this plugin.
     */
    void setEnabled(boolean enabled);
}
