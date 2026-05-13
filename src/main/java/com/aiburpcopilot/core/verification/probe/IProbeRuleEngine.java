package com.aiburpcopilot.core.verification.probe;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.util.RuleKeyUtil;

import java.util.List;
import java.util.Set;

public interface IProbeRuleEngine {

    default List<ProbeDefinition> getProbes(AttackType attackType) {
        return getProbes(RuleKeyUtil.attackTypeName(attackType));
    }

    default List<ProbeDefinition> getProbes(String attackTypeName) {
        return List.of();
    }

    default Set<AttackType> getAttackTypes() {
        return Set.of();
    }

    default Set<String> getAttackTypeNames() {
        return Set.of();
    }

    void reload();
}
