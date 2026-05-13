package com.aiburpcopilot.core.verification.technique.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.technique.TechniqueRule;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;

/**
 * IDOR UUID 替换技术规则。
 * <p>
 * 映射：AttackType.IDOR + UUID_SWAP → UUID_SWAP
 * <p>
 * 将 UUID 参数值替换为另一个已知 UUID，
 * 验证是否存在水平越权。
 */
public class IdorUuidSwapTechniqueRule implements TechniqueRule {

    @Override
    public boolean supports(AttackType attackType, VerificationTechnique technique) {
        return attackType == AttackType.IDOR && technique == VerificationTechnique.UUID_SWAP;
    }

    @Override
    public StrategyType getStrategyType() {
        return StrategyType.UUID_SWAP;
    }

    @Override
    public String getDescription() {
        return "IDOR UUID Swap → UUID_SWAP (replace with another UUID)";
    }
}
