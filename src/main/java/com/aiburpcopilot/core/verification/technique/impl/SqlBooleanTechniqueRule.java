package com.aiburpcopilot.core.verification.technique.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.technique.TechniqueRule;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;

/**
 * SQLI Boolean-Based 技术规则。
 * <p>
 * 映射：AttackType.SQLI + BOOLEAN_BASED → BOOLEAN_BASED_MINIMAL
 * <p>
 * 使用 1=1/1=2 等最小化布尔 payload，
 * 对比 true/false 响应差异来判断 SQL 注入。
 */
public class SqlBooleanTechniqueRule implements TechniqueRule {

    @Override
    public boolean supports(AttackType attackType, VerificationTechnique technique) {
        return attackType == AttackType.SQLI && technique == VerificationTechnique.BOOLEAN_BASED;
    }

    @Override
    public StrategyType getStrategyType() {
        return StrategyType.BOOLEAN_BASED_MINIMAL;
    }

    @Override
    public String getDescription() {
        return "SQLI Boolean-Based → BOOLEAN_BASED_MINIMAL (1=1/1=2 contrast)";
    }
}
