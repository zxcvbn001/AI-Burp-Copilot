package com.aiburpcopilot.core.verification.technique.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.technique.TechniqueRule;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;

/**
 * SSRF 本地回环探测技术规则。
 * <p>
 * 映射：AttackType.SSRF + LOCALHOST_PROBE → LOCALHOST_PROBE
 * <p>
 * 将 URL 参数值替换为 http://127.0.0.1/ 或 http://localhost/，
 * 验证是否存在 SSRF 漏洞。
 */
public class SsrfLocalhostProbeTechniqueRule implements TechniqueRule {

    @Override
    public boolean supports(AttackType attackType, VerificationTechnique technique) {
        return attackType == AttackType.SSRF && technique == VerificationTechnique.LOCALHOST_PROBE;
    }

    @Override
    public StrategyType getStrategyType() {
        return StrategyType.LOCALHOST_PROBE;
    }

    @Override
    public String getDescription() {
        return "SSRF Localhost Probe → LOCALHOST_PROBE (replace URL with 127.0.0.1/localhost)";
    }
}
