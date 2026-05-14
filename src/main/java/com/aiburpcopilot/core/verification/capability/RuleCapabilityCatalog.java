package com.aiburpcopilot.core.verification.capability;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.payload.IPayloadRuleEngine;
import com.aiburpcopilot.core.verification.payload.RuleWorkflowConfig;
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
    private final Map<AttackType, Map<VerificationTechnique, StrategyType>> legacyTechniqueMap;

    public RuleCapabilityCatalog(Object pluginRegistry,
                                 IPayloadRuleEngine payloadRuleEngine) {
        this(pluginRegistry, payloadRuleEngine, TechniqueRegistry.createDefault());
    }

    public RuleCapabilityCatalog(Object pluginRegistry,
                                 IPayloadRuleEngine payloadRuleEngine,
                                 ITechniqueRegistry techniqueRegistry) {
        this.payloadRuleEngine = payloadRuleEngine;
        this.legacyTechniqueMap = loadTechniqueMap(techniqueRegistry);
    }

    private Map<String, Set<String>> payloadStrategies() {
        return payloadRuleEngine != null
                ? payloadRuleEngine.getRuleCapabilityNames()
                : Map.of();
    }

    private Map<String, Set<String>> attackTypeAliases() {
        return payloadRuleEngine != null
                ? payloadRuleEngine.getAttackTypeAliases()
                : Map.of();
    }

    public boolean supportsAttackType(AttackType attackType) {
        return supportsAttackType(RuleKeyUtil.attackTypeName(attackType));
    }

    public boolean supportsAttackType(String attackTypeName) {
        String key = resolveAttackTypeName(attackTypeName);
        Map<String, Set<String>> payloadStrategies = payloadStrategies();
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
        Map<String, Set<String>> payloadStrategies = payloadStrategies();
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
        return Collections.unmodifiableSet(new LinkedHashSet<>(payloadStrategies().keySet()));
    }

    public String resolveAttackTypeName(String value) {
        String normalized = RuleKeyUtil.normalize(value);
        if (normalized == null) {
            return null;
        }
        Map<String, Set<String>> payloadStrategies = payloadStrategies();
        Map<String, Set<String>> attackTypeAliases = attackTypeAliases();
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
        if (value.equals(normalizedAlias)) {
            return true;
        }
        return isTokenAlias(normalizedAlias)
                && containsToken(value, normalizedAlias);
    }

    private boolean isTokenAlias(String alias) {
        return alias.length() >= 4 || alias.contains("_");
    }

    private boolean containsToken(String value, String alias) {
        return ("_" + value + "_").contains("_" + alias + "_");
    }

    public Map<VerificationTechnique, StrategyType> getSupportedTechniques(AttackType attackType) {
        if (!supportsAttackType(attackType)) {
            return Map.of();
        }
        Map<VerificationTechnique, StrategyType> result = new LinkedHashMap<>();
        Map<VerificationTechnique, StrategyType> techniques =
                legacyTechniqueMap.getOrDefault(attackType, Map.of());
        Set<String> strategies = payloadStrategies().getOrDefault(attackType.name(), Set.of());
        for (Map.Entry<VerificationTechnique, StrategyType> entry : techniques.entrySet()) {
            if (strategies.contains(entry.getValue().name())) {
                result.put(entry.getKey(), entry.getValue());
            }
        }
        return Collections.unmodifiableMap(result);
    }

    public String toPromptConstraint() {
        StringBuilder sb = new StringBuilder();
        sb.append("AllowedAttackTypes: ");
        sb.append(String.join(", ", getSupportedAttackTypeNames()));
        sb.append("\nUse only these broad attackType keys. Do not output subtypes or technique names.\n");
        for (String attackTypeName : getSupportedAttackTypeNames()) {
            RuleWorkflowConfig workflowConfig = payloadRuleEngine != null
                    ? payloadRuleEngine.getWorkflowConfig(attackTypeName)
                    : null;
            String description = workflowConfig != null ? workflowConfig.getDescription() : null;
            if (description != null && !description.isBlank()) {
                sb.append("- ").append(attackTypeName).append(": ")
                        .append(compact(description, 90))
                        .append("\n");
            }
        }
        return sb.toString();
    }

    private String compact(String value, int maxLength) {
        String compacted = value.replaceAll("\\s+", " ").trim();
        if (compacted.length() <= maxLength) {
            return compacted;
        }
        return compacted.substring(0, Math.max(0, maxLength - 3)) + "...";
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
