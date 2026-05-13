package com.aiburpcopilot.core.verification.payload;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.model.TestStrategy;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Payload 规则引擎接口。
 * <p>
 * 根据测试策略生成安全的 payload 列表。
 * Payload 来源于 YAML 规则文件，不通过 AI 生成。
 */
public interface IPayloadRuleEngine {

    /**
     * 根据测试策略生成 payload 列表。
     *
     * @param strategy 测试策略
     * @return payload 字符串列表
     */
    List<String> generatePayloads(TestStrategy strategy);

    /**
     * 根据攻击类型和策略类型生成 payload 列表。
     *
     * @param attackType  攻击类型
     * @param strategyType 策略类型
     * @return payload 字符串列表
     */
    List<String> generatePayloads(AttackType attackType, StrategyType strategyType);

    default boolean supportsAttackType(AttackType attackType) {
        return attackType != null && !getSupportedStrategyTypes(attackType).isEmpty();
    }

    default Set<StrategyType> getSupportedStrategyTypes(AttackType attackType) {
        return Set.of();
    }

    default Map<AttackType, Set<StrategyType>> getRuleCapabilities() {
        return Map.of();
    }

    /**
     * 重新加载规则文件（支持热更新）。
     */
    void reload();
}
