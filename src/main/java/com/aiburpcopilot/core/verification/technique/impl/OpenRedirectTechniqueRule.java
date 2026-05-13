package com.aiburpcopilot.core.verification.technique.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.technique.TechniqueRule;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;

public class OpenRedirectTechniqueRule implements TechniqueRule {

    @Override
    public boolean supports(AttackType attackType, VerificationTechnique technique) {
        return attackType == AttackType.OPEN_REDIRECT
                && technique == VerificationTechnique.OPEN_REDIRECT;
    }

    @Override
    public StrategyType getStrategyType() {
        return StrategyType.OPEN_REDIRECT_PROBE;
    }

    @Override
    public String getDescription() {
        return "Open Redirect -> OPEN_REDIRECT_PROBE";
    }
}
