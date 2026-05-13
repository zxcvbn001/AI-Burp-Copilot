package com.aiburpcopilot.core.verification.technique.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.technique.TechniqueRule;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;

/**
 * IDOR 数字递增技术规则。
 * <p>
 * 映射：AttackType.IDOR + NUMERIC_INCREMENT → NUMERIC_INCREMENT
 * <p>
 * 将数字 ID 参数值 +1（如 1001 → 1002），
 * 验证是否存在水平越权。
 */
public class IdorNumericIncrementTechniqueRule implements TechniqueRule {

    @Override
    public boolean supports(AttackType attackType, VerificationTechnique technique) {
        return attackType == AttackType.IDOR && technique == VerificationTechnique.NUMERIC_INCREMENT;
    }

    @Override
    public StrategyType getStrategyType() {
        return StrategyType.NUMERIC_INCREMENT;
    }

    @Override
    public String getDescription() {
        return "IDOR Numeric Increment → NUMERIC_INCREMENT (id+1 probe)";
    }
}
