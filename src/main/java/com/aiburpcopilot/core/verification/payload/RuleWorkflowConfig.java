package com.aiburpcopilot.core.verification.payload;

public class RuleWorkflowConfig {

    private String name;
    private String description;
    private boolean includeInfluenceStep = true;
    private boolean requiresInfluenceApproval = true;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isIncludeInfluenceStep() {
        return includeInfluenceStep;
    }

    public void setIncludeInfluenceStep(boolean includeInfluenceStep) {
        this.includeInfluenceStep = includeInfluenceStep;
    }

    public boolean isRequiresInfluenceApproval() {
        return requiresInfluenceApproval;
    }

    public void setRequiresInfluenceApproval(boolean requiresInfluenceApproval) {
        this.requiresInfluenceApproval = requiresInfluenceApproval;
    }
}
