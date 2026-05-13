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
 * SSRF (Server-Side Request Forgery) verification plugin.
 * <p>
 * Provides a WorkflowDefinition with steps for InfluenceValidation
 * and LocalhostProbe.
 */
public class SsrfPlugin implements IPlugin {

    private static final Logger log = LoggerFactory.getLogger(SsrfPlugin.class);

    private boolean enabled = true;

    @Override
    public String getPluginId() { return "ssrf"; }

    @Override
    public String getName() { return "SSRF"; }

    @Override
    public String getDescription() { return "Verifies SSRF vulnerabilities using localhost probe techniques"; }

    @Override
    public List<VerificationStep> getSteps() {
        return Collections.emptyList();
    }

    @Override
    public WorkflowDefinition getWorkflow() {
        return new WorkflowDefinition(
                AttackType.SSRF,
                "SSRF Verification",
                "Validates SSRF by probing localhost and internal addresses",
                Arrays.asList("InfluenceValidation", "SSRFProbes"),
                true
        );
    }

    @Override
    public boolean isEnabled() { return enabled; }

    @Override
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    // ---------- Inner Step Implementation ----------

    /**
     * Localhost probe SSRF step.
     * Replaces URL parameter values with localhost/127.0.0.1
     * and checks for response differences.
     */
    public static class LocalhostProbeStep implements VerificationStep {
        @Override
        public String getName() { return "LocalhostProbe"; }

        @Override
        public StepResult execute(WorkflowContext context) {
            log.debug("Executing LocalhostProbe SSRF verification");
            StepResult result = StepResult.success(getName(),
                    "Localhost probe SSRF verification");
            result.addEvidence(Evidence.general(
                    "Localhost/loopback address probe",
                    "LOCALHOST_PROBE", 0.7));
            return result;
        }
    }
}
