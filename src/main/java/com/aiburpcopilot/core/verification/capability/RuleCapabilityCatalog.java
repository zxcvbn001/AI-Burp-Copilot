package com.aiburpcopilot.core.verification.capability;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.model.WorkflowDefinition;
import com.aiburpcopilot.core.verification.payload.IPayloadRuleEngine;
import com.aiburpcopilot.core.verification.plugins.impl.PluginRegistry;
import com.aiburpcopilot.core.verification.technique.ITechniqueRegistry;
import com.aiburpcopilot.core.verification.technique.TechniqueRule;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;
import com.aiburpcopilot.core.verification.technique.impl.TechniqueRegistry;

import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Deterministic catalog of capabilities that are actually executable locally.
 * AI output is only advisory and must be constrained to this catalog.
 */
public class RuleCapabilityCatalog {

    private final Map<AttackType, WorkflowDefinition> workflows;
    private final Map<AttackType, Set<StrategyType>> payloadStrategies;
    private final Map<AttackType, Map<VerificationTechnique, StrategyType>> techniqueMap;

    public RuleCapabilityCatalog(PluginRegistry pluginRegistry,
                                 IPayloadRuleEngine payloadRuleEngine) {
        this(pluginRegistry, payloadRuleEngine, TechniqueRegistry.createDefault());
    }

    public RuleCapabilityCatalog(PluginRegistry pluginRegistry,
                                 IPayloadRuleEngine payloadRuleEngine,
                                 ITechniqueRegistry techniqueRegistry) {
        this.workflows = loadWorkflows(pluginRegistry);
        this.payloadStrategies = payloadRuleEngine != null
                ? payloadRuleEngine.getRuleCapabilities()
                : Map.of();
        this.techniqueMap = loadTechniqueMap(techniqueRegistry);
    }

    public boolean supportsAttackType(AttackType attackType) {
        return attackType != null
                && workflows.containsKey(attackType)
                && payloadStrategies.containsKey(attackType)
                && !payloadStrategies.get(attackType).isEmpty();
    }

    public boolean supportsTechnique(AttackType attackType, VerificationTechnique technique) {
        if (!supportsAttackType(attackType) || technique == null) {
            return false;
        }
        StrategyType strategyType = Optional.ofNullable(techniqueMap.get(attackType))
                .map(map -> map.get(technique))
                .orElse(null);
        return strategyType != null
                && payloadStrategies.getOrDefault(attackType, Set.of()).contains(strategyType);
    }

    public Set<AttackType> getSupportedAttackTypes() {
        Set<AttackType> result = EnumSet.noneOf(AttackType.class);
        for (AttackType attackType : AttackType.values()) {
            if (supportsAttackType(attackType)) {
                result.add(attackType);
            }
        }
        return Collections.unmodifiableSet(result);
    }

    public Map<VerificationTechnique, StrategyType> getSupportedTechniques(AttackType attackType) {
        if (!supportsAttackType(attackType)) {
            return Map.of();
        }
        Map<VerificationTechnique, StrategyType> result = new LinkedHashMap<>();
        Map<VerificationTechnique, StrategyType> techniques =
                techniqueMap.getOrDefault(attackType, Map.of());
        Set<StrategyType> strategies = payloadStrategies.getOrDefault(attackType, Set.of());
        for (Map.Entry<VerificationTechnique, StrategyType> entry : techniques.entrySet()) {
            if (strategies.contains(entry.getValue())) {
                result.put(entry.getKey(), entry.getValue());
            }
        }
        return Collections.unmodifiableMap(result);
    }

    public String toPromptConstraint() {
        StringBuilder sb = new StringBuilder();
        sb.append("??????????????????????????????????????\n");
        for (AttackType attackType : AttackType.values()) {
            if (!supportsAttackType(attackType)) {
                continue;
            }
            sb.append("- ").append(attackType.name()).append(": ");
            Map<VerificationTechnique, StrategyType> techniques = getSupportedTechniques(attackType);
            sb.append(String.join(", ", techniques.keySet().stream().map(Enum::name).toList()));
            sb.append("\n");
        }
        sb.append("????????????????? possibleVulnerabilities ?? recommendedTechniques?????????\n");
        return sb.toString();
    }

    private Map<AttackType, WorkflowDefinition> loadWorkflows(PluginRegistry pluginRegistry) {
        Map<AttackType, WorkflowDefinition> result = new EnumMap<>(AttackType.class);
        if (pluginRegistry == null) {
            return result;
        }
        for (WorkflowDefinition workflow : pluginRegistry.getAllWorkflows()) {
            if (workflow != null && workflow.getAttackType() != null) {
                result.put(workflow.getAttackType(), workflow);
            }
        }
        return Collections.unmodifiableMap(result);
    }

    private Map<AttackType, Map<VerificationTechnique, StrategyType>> loadTechniqueMap(
            ITechniqueRegistry techniqueRegistry) {
        Map<AttackType, Map<VerificationTechnique, StrategyType>> result =
                new EnumMap<>(AttackType.class);
        if (techniqueRegistry == null) {
            return Collections.unmodifiableMap(result);
        }
        for (AttackType attackType : AttackType.values()) {
            for (VerificationTechnique technique : VerificationTechnique.values()) {
                Optional<TechniqueRule> rule = techniqueRegistry.findRule(attackType, technique);
                rule.ifPresent(techniqueRule ->
                        register(result, attackType, technique, techniqueRule.getStrategyType()));
            }
        }
        return Collections.unmodifiableMap(result);
    }

    private void register(Map<AttackType, Map<VerificationTechnique, StrategyType>> result,
                          AttackType attackType,
                          VerificationTechnique technique,
                          StrategyType strategyType) {
        result.computeIfAbsent(attackType, ignored -> new LinkedHashMap<>())
                .put(technique, strategyType);
    }
}
