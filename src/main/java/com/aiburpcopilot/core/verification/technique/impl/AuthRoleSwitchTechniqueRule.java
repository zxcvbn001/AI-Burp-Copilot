package com.aiburpcopilot.core.verification.technique.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.technique.TechniqueRule;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;

/**
 * AUTH 角色切换技术规则。
 * <p>
 * 映射：AttackType.AUTH + ROLE_SWITCH → ROLE_SWITCH
 * <p>
 * 将当前用户的 Token 替换为低权限用户的 Token，
 * 验证是否存在垂直越权。
 */
public class AuthRoleSwitchTechniqueRule implements TechniqueRule {

    @Override
    public boolean supports(AttackType attackType, VerificationTechnique technique) {
        return attackType == AttackType.AUTH && technique == VerificationTechnique.ROLE_SWITCH;
    }

    @Override
    public StrategyType getStrategyType() {
        return StrategyType.ROLE_SWITCH;
    }

    @Override
    public String getDescription() {
        return "AUTH Role Switch → ROLE_SWITCH (swap to lower-privilege token)";
    }
}
