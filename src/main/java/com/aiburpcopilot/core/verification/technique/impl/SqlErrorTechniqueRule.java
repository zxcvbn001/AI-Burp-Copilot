package com.aiburpcopilot.core.verification.technique.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.technique.TechniqueRule;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;

/**
 * SQLI Error-Based 技术规则。
 * <p>
 * 映射：AttackType.SQLI + ERROR_BASED → ERROR_BASED
 * <p>
 * 使用单引号/双引号等误差 payload，
 * 观察是否触发数据库错误信息泄露。
 */
public class SqlErrorTechniqueRule implements TechniqueRule {

    @Override
    public boolean supports(AttackType attackType, VerificationTechnique technique) {
        return attackType == AttackType.SQLI && technique == VerificationTechnique.ERROR_BASED;
    }

    @Override
    public StrategyType getStrategyType() {
        return StrategyType.ERROR_BASED;
    }

    @Override
    public String getDescription() {
        return "SQLI Error-Based → ERROR_BASED (trigger DB error messages)";
    }
}
