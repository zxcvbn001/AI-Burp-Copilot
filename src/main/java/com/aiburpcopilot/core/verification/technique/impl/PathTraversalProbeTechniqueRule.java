package com.aiburpcopilot.core.verification.technique.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.technique.TechniqueRule;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;

public class PathTraversalProbeTechniqueRule implements TechniqueRule {

    @Override
    public boolean supports(AttackType attackType, VerificationTechnique technique) {
        return attackType == AttackType.PATH_TRAVERSAL
                && technique == VerificationTechnique.PATH_TRAVERSAL_PROBE;
    }

    @Override
    public StrategyType getStrategyType() {
        return StrategyType.PATH_TRAVERSAL_PROBE;
    }

    @Override
    public String getDescription() {
        return "Path Traversal Probe -> PATH_TRAVERSAL_PROBE";
    }
}
