package com.aiburpcopilot.core.verification.capability;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.payload.IPayloadRuleEngine;
import com.aiburpcopilot.core.verification.probe.ProbeDefinition;
import com.aiburpcopilot.core.verification.technique.ITechniqueRegistry;
import com.aiburpcopilot.core.verification.technique.TechniqueRule;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;
import com.aiburpcopilot.core.verification.technique.impl.TechniqueRegistry;
import com.aiburpcopilot.core.verification.util.RuleKeyUtil;

import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class RuleCapabilityCatalog {

    private final IPayloadRuleEngine payloadRuleEngine;
    private final Map<String, Set<String>> payloadStrategies;
    private final Map<String, Set<String>> attackTypeAliases;
    private final Map<AttackType, Map<VerificationTechnique, StrategyType>> legacyTechniqueMap;

    public RuleCapabilityCatalog(Object pluginRegistry,
                                 IPayloadRuleEngine payloadRuleEngine) {
        this(pluginRegistry, payloadRuleEngine, TechniqueRegistry.createDefault());
    }

    public RuleCapabilityCatalog(Object pluginRegistry,
                                 IPayloadRuleEngine payloadRuleEngine,
                                 ITechniqueRegistry techniqueRegistry) {
        this.payloadRuleEngine = payloadRuleEngine;
        this.payloadStrategies = payloadRuleEngine != null
                ? payloadRuleEngine.getRuleCapabilityNames()
                : Map.of();
        this.attackTypeAliases = payloadRuleEngine != null
                ? payloadRuleEngine.getAttackTypeAliases()
                : Map.of();
        this.legacyTechniqueMap = loadTechniqueMap(techniqueRegistry);
    }

    public boolean supportsAttackType(AttackType attackType) {
        return supportsAttackType(RuleKeyUtil.attackTypeName(attackType));
    }

    public boolean supportsAttackType(String attackTypeName) {
        String key = resolveAttackTypeName(attackTypeName);
        return key != null
                && payloadStrategies.containsKey(key)
                && !payloadStrategies.get(key).isEmpty();
    }

    public boolean supportsTechnique(AttackType attackType, VerificationTechnique technique) {
        if (!supportsAttackType(attackType) || technique == null) {
            return false;
        }
        StrategyType strategyType = Optional.ofNullable(legacyTechniqueMap.get(attackType))
                .map(map -> map.get(technique))
                .orElse(null);
        return strategyType != null && supportsStrategy(attackType.name(), strategyType.name());
    }

    public boolean supportsTechnique(String attackTypeName, String techniqueOrStrategyName) {
        if (!supportsAttackType(attackTypeName)) {
            return false;
        }
        String technique = RuleKeyUtil.normalize(techniqueOrStrategyName);
        if (technique == null) {
            return true;
        }
        String key = resolveAttackTypeName(attackTypeName);
        for (ProbeDefinition probe : payloadRuleEngine.getEnabledProbes(key)) {
            String probeTechnique = RuleKeyUtil.normalize(probe.getTechnique());
            String probeStrategy = RuleKeyUtil.normalize(probe.getStrategyName());
            if (technique.equals(probeTechnique) || technique.equals(probeStrategy)) {
                return true;
            }
        }
        return false;
    }

    public boolean supportsStrategy(String attackTypeName, String strategyName) {
        String key = resolveAttackTypeName(attackTypeName);
        String strategy = RuleKeyUtil.normalize(strategyName);
        return key != null
                && strategy != null
                && payloadStrategies.getOrDefault(key, Set.of()).contains(strategy);
    }

    public Set<AttackType> getSupportedAttackTypes() {
        Set<AttackType> result = EnumSet.noneOf(AttackType.class);
        for (String attackTypeName : getSupportedAttackTypeNames()) {
            RuleKeyUtil.toAttackType(attackTypeName).ifPresent(result::add);
        }
        return Collections.unmodifiableSet(result);
    }

    public Set<String> getSupportedAttackTypeNames() {
        return Collections.unmodifiableSet(new LinkedHashSet<>(payloadStrategies.keySet()));
    }

    public String resolveAttackTypeName(String value) {
        String normalized = RuleKeyUtil.normalize(value);
        if (normalized == null) {
            return null;
        }
        if (payloadStrategies.containsKey(normalized)) {
            return normalized;
        }
        for (Map.Entry<String, Set<String>> entry : attackTypeAliases.entrySet()) {
            for (String alias : entry.getValue()) {
                if (aliasMatches(normalized, alias)) {
                    return entry.getKey();
                }
            }
        }
        for (Map.Entry<String, Set<String>> entry : attackTypeAliases.entrySet()) {
            String key = entry.getKey();
            if (aliasMatches(normalized, key)) {
                return entry.getKey();
            }
        }
        for (String attackTypeName : payloadStrategies.keySet()) {
            if (normalized.contains(attackTypeName) || attackTypeName.contains(normalized)) {
                return attackTypeName;
            }
        }
        return null;
    }

    private boolean aliasMatches(String value, String alias) {
        if (value == null || alias == null) {
            return false;
        }
        String normalizedAlias = RuleKeyUtil.normalize(alias);
        if (normalizedAlias == null) {
            return false;
        }
        return value.equals(normalizedAlias)
                || value.contains(normalizedAlias)
                || normalizedAlias.contains(value);
    }

    public Map<VerificationTechnique, StrategyType> getSupportedTechniques(AttackType attackType) {
        if (!supportsAttackType(attackType)) {
            return Map.of();
        }
        Map<VerificationTechnique, StrategyType> result = new LinkedHashMap<>();
        Map<VerificationTechnique, StrategyType> techniques =
                legacyTechniqueMap.getOrDefault(attackType, Map.of());
        Set<String> strategies = payloadStrategies.getOrDefault(attackType.name(), Set.of());
        for (Map.Entry<VerificationTechnique, StrategyType> entry : techniques.entrySet()) {
            if (strategies.contains(entry.getValue().name())) {
                result.put(entry.getKey(), entry.getValue());
            }
        }
        return Collections.unmodifiableMap(result);
    }

    public String toPromptConstraint() {
        StringBuilder sb = new StringBuilder();
        sb.append("Capabilities format: attackType -> techniques | probes. Only use listed attackType values.\n");
        for (String attackTypeName : getSupportedAttackTypeNames()) {
            sb.append("- ").append(attackTypeName)
                    .append(" -> ")
                    .append(String.join(",", techniqueNames(attackTypeName)))
                    .append(" | ")
                    .append(summarizeProbes(attackTypeName))
                    .append("\n");
        }
        return sb.toString();
    }

    private Set<String> techniqueNames(String attackTypeName) {
        Set<String> names = new LinkedHashSet<>();
        if (payloadRuleEngine != null) {
            for (ProbeDefinition probe : payloadRuleEngine.getEnabledProbes(attackTypeName)) {
                String technique = RuleKeyUtil.normalize(probe.getTechnique());
                if (technique != null) {
                    names.add(technique);
                }
            }
        }
        if (names.isEmpty()) {
            names.addAll(payloadStrategies.getOrDefault(attackTypeName, Set.of()));
        }
        return names;
    }

    private String summarizeProbes(String attackTypeName) {
        if (payloadRuleEngine == null) {
            return "No probe metadata available";
        }
        var probes = payloadRuleEngine.getEnabledProbes(attackTypeName);
        if (probes.isEmpty()) {
            return "No enabled probes";
        }
        return String.join(",", probes.stream().limit(3).map(ProbeDefinition::getId).toList());
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
                        result.computeIfAbsent(attackType, ignored -> new LinkedHashMap<>())
                                .put(technique, techniqueRule.getStrategyType()));
            }
        }
        return Collections.unmodifiableMap(result);
    }
}
