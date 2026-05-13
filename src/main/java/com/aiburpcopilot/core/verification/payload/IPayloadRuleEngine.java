package com.aiburpcopilot.core.verification.payload;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.model.TestStrategy;
import com.aiburpcopilot.core.verification.probe.ProbeDefinition;
import com.aiburpcopilot.core.verification.util.RuleKeyUtil;

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
        return supportsAttackType(RuleKeyUtil.attackTypeName(attackType));
    }

    default boolean supportsAttackType(String attackTypeName) {
        return attackTypeName != null && !getSupportedStrategyNames(attackTypeName).isEmpty();
    }

    default Set<StrategyType> getSupportedStrategyTypes(AttackType attackType) {
        return Set.of();
    }

    default Map<AttackType, Set<StrategyType>> getRuleCapabilities() {
        return Map.of();
    }

    default Map<String, Set<String>> getRuleCapabilityNames() {
        return Map.of();
    }

    default Map<String, Set<String>> getAttackTypeAliases() {
        return Map.of();
    }

    default List<ProbeDefinition> getEnabledProbes(AttackType attackType) {
        return getEnabledProbes(RuleKeyUtil.attackTypeName(attackType));
    }

    default List<ProbeDefinition> getEnabledProbes(String attackTypeName) {
        return List.of();
    }

    default RuleWorkflowConfig getWorkflowConfig(AttackType attackType) {
        return getWorkflowConfig(RuleKeyUtil.attackTypeName(attackType));
    }

    default RuleWorkflowConfig getWorkflowConfig(String attackTypeName) {
        return new RuleWorkflowConfig();
    }

    default Set<String> getSupportedStrategyNames(String attackTypeName) {
        return Set.of();
    }

    /**
     * 重新加载规则文件（支持热更新）。
     */
    void reload();
}
