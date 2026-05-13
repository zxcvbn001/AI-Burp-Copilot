package com.aiburpcopilot.core.verification.technique.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.technique.TechniqueRule;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;

/**
 * AUTH 移除 Token 技术规则。
 * <p>
 * 映射：AttackType.AUTH + REMOVE_TOKEN → REMOVE_TOKEN
 * <p>
 * 删除 Authorization Header 后重新发送请求，
 * 验证是否存在身份认证绕过。
 */
public class AuthRemoveTokenTechniqueRule implements TechniqueRule {

    @Override
    public boolean supports(AttackType attackType, VerificationTechnique technique) {
        return attackType == AttackType.AUTH && technique == VerificationTechnique.REMOVE_TOKEN;
    }

    @Override
    public StrategyType getStrategyType() {
        return StrategyType.REMOVE_TOKEN;
    }

    @Override
    public String getDescription() {
        return "AUTH Remove Token → REMOVE_TOKEN (strip Authorization header)";
    }
}
