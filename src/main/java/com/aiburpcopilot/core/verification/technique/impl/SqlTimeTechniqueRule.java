package com.aiburpcopilot.core.verification.technique.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.technique.TechniqueRule;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;

/**
 * SQLI Time-Based 技术规则。
 * <p>
 * 映射：AttackType.SQLI + TIME_BASED → TIME_BASED
 * <p>
 * 使用数据库 sleep 函数观察响应时间差异。
 * Phase 2 默认禁用（DangerousPayloadFilter 拦截 SLEEP/BENCHMARK payload）。
 */
public class SqlTimeTechniqueRule implements TechniqueRule {

    @Override
    public boolean supports(AttackType attackType, VerificationTechnique technique) {
        return attackType == AttackType.SQLI && technique == VerificationTechnique.TIME_BASED;
    }

    @Override
    public StrategyType getStrategyType() {
        return StrategyType.TIME_BASED;
    }

    @Override
    public String getDescription() {
        return "SQLI Time-Based → TIME_BASED (observe response delay)";
    }
}
