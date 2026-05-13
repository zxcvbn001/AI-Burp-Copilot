package com.aiburpcopilot.core.verification.registry;

import com.aiburpcopilot.core.verification.workflow.VerificationStep;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Registry that manages VerificationStep registrations by name.
 * <p>
 * Central lookup for all VerificationStep implementations. Steps are
 * registered by name and can be retrieved by the Workflow Engine when
 * executing workflows.
 */
public class StepRegistry {

    private static final Logger log = LoggerFactory.getLogger(StepRegistry.class);

    private final Map<String, VerificationStep> steps = new LinkedHashMap<>();

    /**
     * Register a VerificationStep by name.
     *
     * @param name the step name (must match the name used in WorkflowDefinition.getStepNames())
     * @param step the VerificationStep implementation
     */
    public void register(String name, VerificationStep step) {
        if (name == null || name.isBlank()) {
            log.warn("Attempted to register step with null/blank name");
            return;
        }
        if (step == null) {
            log.warn("Attempted to register null step for name: {}", name);
            return;
        }
        steps.put(name, step);
        log.debug("Registered VerificationStep: {}", name);
    }

    /**
     * Look up a VerificationStep by name.
     *
     * @param name the step name
     * @return the VerificationStep implementation, or null if not found
     */
    public VerificationStep getStep(String name) {
        return steps.get(name);
    }

    /**
     * Returns all registered step names.
     *
     * @return unmodifiable set of step names
     */
    public Set<String> getAllStepNames() {
        return Collections.unmodifiableSet(steps.keySet());
    }

    /**
     * Returns the number of registered steps.
     */
    public int getCount() {
        return steps.size();
    }
}
