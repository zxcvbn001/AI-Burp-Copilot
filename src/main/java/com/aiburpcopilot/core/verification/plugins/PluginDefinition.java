package com.aiburpcopilot.core.verification.plugins;

import java.util.ArrayList;
import java.util.List;

/**
 * Model/POJO for a verification plugin definition.
 * <p>
 * Describes a verification plugin's metadata: its unique ID, display name,
 * description, enabled state, and the steps/workflow it provides.
 */
public class PluginDefinition {

    /** Unique plugin ID, e.g. "sqli", "idor" */
    private String pluginId;

    /** Human-readable display name */
    private String name;

    /** Plugin description */
    private String description;

    /** Whether the plugin is currently enabled */
    private boolean enabled;

    /** Step names this plugin provides */
    private List<String> providedSteps;

    /** Optional workflow name */
    private String workflowName;

    public PluginDefinition() {
        this.providedSteps = new ArrayList<>();
        this.enabled = true;
    }

    public PluginDefinition(String pluginId, String name, String description,
                            boolean enabled, List<String> providedSteps, String workflowName) {
        this.pluginId = pluginId;
        this.name = name;
        this.description = description;
        this.enabled = enabled;
        this.providedSteps = providedSteps != null ? providedSteps : new ArrayList<>();
        this.workflowName = workflowName;
    }

    // ---------- Getters & Setters ----------

    public String getPluginId() { return pluginId; }
    public void setPluginId(String pluginId) { this.pluginId = pluginId; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public List<String> getProvidedSteps() { return providedSteps; }
    public void setProvidedSteps(List<String> providedSteps) {
        this.providedSteps = providedSteps != null ? providedSteps : new ArrayList<>();
    }

    public String getWorkflowName() { return workflowName; }
    public void setWorkflowName(String workflowName) { this.workflowName = workflowName; }

    @Override
    public String toString() {
        return "PluginDefinition{" +
                "pluginId='" + pluginId + '\'' +
                ", name='" + name + '\'' +
                ", enabled=" + enabled +
                ", steps=" + providedSteps +
                ", workflow='" + workflowName + '\'' +
                '}';
    }
}
