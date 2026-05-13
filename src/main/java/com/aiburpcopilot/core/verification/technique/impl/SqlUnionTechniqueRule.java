package com.aiburpcopilot.core.verification.technique.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.technique.TechniqueRule;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;

/**
 * SQLI Union-Based 技术规则。
 * <p>
 * 映射：AttackType.SQLI + UNION_BASED → UNION_BASED
 * <p>
 * 使用 UNION SELECT payload 探测列数。
 * Phase 2 默认禁用（DangerousPayloadFilter 拦截 UNION payload）。
 */
public class SqlUnionTechniqueRule implements TechniqueRule {

    @Override
    public boolean supports(AttackType attackType, VerificationTechnique technique) {
        return attackType == AttackType.SQLI && technique == VerificationTechnique.UNION_BASED;
    }

    @Override
    public StrategyType getStrategyType() {
        return StrategyType.UNION_BASED;
    }

    @Override
    public String getDescription() {
        return "SQLI Union-Based → UNION_BASED (UNION SELECT probe) - disabled by default";
    }
}
