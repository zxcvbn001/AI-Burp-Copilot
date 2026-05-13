package com.aiburpcopilot.core.verification.technique.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.technique.TechniqueRule;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;

public class SstiTemplateExpressionTechniqueRule implements TechniqueRule {

    @Override
    public boolean supports(AttackType attackType, VerificationTechnique technique) {
        return attackType == AttackType.SSTI
                && technique == VerificationTechnique.TEMPLATE_EXPRESSION;
    }

    @Override
    public StrategyType getStrategyType() {
        return StrategyType.TEMPLATE_EXPRESSION;
    }

    @Override
    public String getDescription() {
        return "SSTI Template Expression -> TEMPLATE_EXPRESSION";
    }
}
