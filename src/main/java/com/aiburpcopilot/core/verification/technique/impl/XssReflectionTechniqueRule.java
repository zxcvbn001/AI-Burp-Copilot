package com.aiburpcopilot.core.verification.technique.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.technique.TechniqueRule;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;

public class XssReflectionTechniqueRule implements TechniqueRule {

    @Override
    public boolean supports(AttackType attackType, VerificationTechnique technique) {
        return attackType == AttackType.XSS && technique == VerificationTechnique.REFLECTION;
    }

    @Override
    public StrategyType getStrategyType() {
        return StrategyType.BOOLEAN_BASED_MINIMAL;
    }

    @Override
    public String getDescription() {
        return "XSS Reflection -> BOOLEAN_BASED_MINIMAL";
    }
}
