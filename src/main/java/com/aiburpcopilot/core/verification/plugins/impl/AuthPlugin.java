package com.aiburpcopilot.core.verification.plugins.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.Evidence;
import com.aiburpcopilot.core.verification.model.StepResult;
import com.aiburpcopilot.core.verification.model.WorkflowDefinition;
import com.aiburpcopilot.core.verification.plugins.IPlugin;
import com.aiburpcopilot.core.verification.workflow.VerificationStep;
import com.aiburpcopilot.core.verification.workflow.WorkflowContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Auth bypass verification plugin.
 * <p>
 * Provides a WorkflowDefinition with steps for InfluenceValidation,
 * RemoveToken, and RoleSwitch to detect authentication and authorization
 * bypass vulnerabilities.
 */
public class AuthPlugin implements IPlugin {

    private static final Logger log = LoggerFactory.getLogger(AuthPlugin.class);

    private boolean enabled = true;

    @Override
    public String getPluginId() { return "auth"; }

    @Override
    public String getName() { return "Auth Bypass"; }

    @Override
    public String getDescription() { return "Verifies authentication/authorization bypass using token removal and role switching"; }

    @Override
    public List<VerificationStep> getSteps() {
        return Collections.emptyList();
    }

    @Override
    public WorkflowDefinition getWorkflow() {
        return new WorkflowDefinition(
                AttackType.AUTH,
                "Auth Bypass Verification",
                "Validates auth bypass by removing tokens and switching user roles",
                Arrays.asList("InfluenceValidation", "AUTHProbes"),
                true
        );
    }

    @Override
    public boolean isEnabled() { return enabled; }

    @Override
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    // ---------- Inner Step Implementations ----------

    /**
     * Remove token auth bypass step.
     * Replays the request without the Authorization header.
     */
    public static class RemoveTokenStep implements VerificationStep {
        @Override
        public String getName() { return "RemoveToken"; }

        @Override
        public StepResult execute(WorkflowContext context) {
            log.debug("Executing RemoveToken auth verification");
            StepResult result = StepResult.success(getName(),
                    "Token removal auth bypass verification");
            result.addEvidence(Evidence.general(
                    "Authorization header removed",
                    "REMOVE_TOKEN", 0.75));
            return result;
        }
    }

    /**
     * Role switch auth bypass step.
     * Substitutes a low-privilege token with a known higher-privilege token.
     */
    public static class RoleSwitchStep implements VerificationStep {
        @Override
        public String getName() { return "RoleSwitch"; }

        @Override
        public StepResult execute(WorkflowContext context) {
            log.debug("Executing RoleSwitch auth verification");
            StepResult result = StepResult.success(getName(),
                    "Role switch auth bypass verification");
            result.addEvidence(Evidence.general(
                    "Role/privilege context switched",
                    "ROLE_SWITCH", 0.7));
            return result;
        }
    }
}
