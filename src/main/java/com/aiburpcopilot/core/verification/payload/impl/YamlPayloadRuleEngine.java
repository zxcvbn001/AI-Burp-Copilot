package com.aiburpcopilot.core.verification.payload.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.config.ExternalResourcePaths;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.model.TestStrategy;
import com.aiburpcopilot.core.verification.payload.IPayloadRuleEngine;
import com.aiburpcopilot.core.verification.payload.RuleWorkflowConfig;
import com.aiburpcopilot.core.verification.probe.IProbeRuleEngine;
import com.aiburpcopilot.core.verification.probe.OracleDefinition;
import com.aiburpcopilot.core.verification.probe.ProbeDefinition;
import com.aiburpcopilot.core.verification.probe.ProbePayload;
import com.aiburpcopilot.core.verification.probe.ProbePayloadPair;
import com.aiburpcopilot.core.verification.probe.ProbeRole;
import com.aiburpcopilot.core.verification.util.RuleKeyUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * YAML probe rule engine.
 * <p>
 * The new rule format is probe-only:
 * <pre>
 * attackType: SQLI
 * probes:
 *   - id: sqli_quote_error_recovery
 *     strategy: ERROR_BASED
 *     payloads:
 *       - value: "'"
 *         role: TRIGGER
 *     oracle:
 *       type: ERROR_KEYWORD_OR_RECOVERY
 * </pre>
 * Legacy {@code rules:} blocks are intentionally ignored. Compatibility
 * methods from {@link IPayloadRuleEngine} derive payload lists from probes.
 */
public class YamlPayloadRuleEngine implements IPayloadRuleEngine, IProbeRuleEngine {

    private static final Logger log = LoggerFactory.getLogger(YamlPayloadRuleEngine.class);
    private static final String PAYLOADS_DIR = "rules/payloads/";
    private static final String[] PAYLOAD_FILES = {
            "sqli.yaml", "idor.yaml", "ssrf.yaml", "auth.yaml",
            "xss.yaml", "path_traversal.yaml", "open_redirect.yaml", "ssti.yaml",
            "xxe.yaml", "jwt.yaml", "graphql.yaml", "cors.yaml",
            "file_upload.yaml", "command_injection.yaml", "ldap_injection.yaml"
    };
    private final Map<String, List<ProbeDefinition>> probeMap = new LinkedHashMap<>();
    private final Map<String, RuleWorkflowConfig> workflowConfigMap = new LinkedHashMap<>();
    private final Map<String, Set<String>> aliasMap = new LinkedHashMap<>();
    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());

    public YamlPayloadRuleEngine() {
        ExternalResourcePaths.initialize();
        reload();
    }

    @Override
    public List<String> generatePayloads(TestStrategy strategy) {
        if (strategy == null) {
            return List.of();
        }
        StrategyType strategyType = strategy.getStrategies().isEmpty()
                ? strategy.getPrimaryStrategy()
                : strategy.getStrategies().get(0);
        return generatePayloads(strategy.getAttackType(), strategyType);
    }

    @Override
    public List<String> generatePayloads(AttackType attackType, StrategyType strategyType) {
        if (attackType == null || strategyType == null) {
            return List.of();
        }
        List<String> payloads = new ArrayList<>();
        for (ProbeDefinition probe : getProbes(attackType)) {
            if (probe.getStrategy() != strategyType) {
                continue;
            }
            probe.getPayloads().stream()
                    .map(this::displayPayload)
                    .filter(value -> value != null)
                    .forEach(payloads::add);
            probe.getPayloadPairs().forEach(pair -> {
                if (pair.getTrueValue() != null) {
                    payloads.add(pair.getTrueValue());
                }
                if (pair.getFalseValue() != null) {
                    payloads.add(pair.getFalseValue());
                }
            });
        }
        return payloads;
    }

    @Override
    public List<ProbeDefinition> getProbes(AttackType attackType) {
        return getProbes(RuleKeyUtil.attackTypeName(attackType));
    }

    @Override
    public List<ProbeDefinition> getProbes(String attackTypeName) {
        String key = resolveAttackTypeName(attackTypeName);
        return key != null ? new ArrayList<>(probeMap.getOrDefault(key, List.of())) : List.of();
    }

    @Override
    public Set<AttackType> getAttackTypes() {
        Set<AttackType> result = new LinkedHashSet<>();
        for (String attackTypeName : probeMap.keySet()) {
            RuleKeyUtil.toAttackType(attackTypeName).ifPresent(result::add);
        }
        return Collections.unmodifiableSet(result);
    }

    @Override
    public Set<String> getAttackTypeNames() {
        return Collections.unmodifiableSet(new LinkedHashSet<>(probeMap.keySet()));
    }

    @Override
    public List<ProbeDefinition> getEnabledProbes(AttackType attackType) {
        return getEnabledProbes(RuleKeyUtil.attackTypeName(attackType));
    }

    @Override
    public List<ProbeDefinition> getEnabledProbes(String attackTypeName) {
        return getProbes(attackTypeName).stream()
                .filter(ProbeDefinition::isEnabledByDefault)
                .toList();
    }

    @Override
    public RuleWorkflowConfig getWorkflowConfig(AttackType attackType) {
        return getWorkflowConfig(RuleKeyUtil.attackTypeName(attackType));
    }

    @Override
    public RuleWorkflowConfig getWorkflowConfig(String attackTypeName) {
        String key = resolveAttackTypeName(attackTypeName);
        return key != null ? workflowConfigMap.getOrDefault(key, new RuleWorkflowConfig()) : new RuleWorkflowConfig();
    }

    @Override
    public Set<StrategyType> getSupportedStrategyTypes(AttackType attackType) {
        if (attackType == null) {
            return Set.of();
        }
        Set<StrategyType> strategies = new LinkedHashSet<>();
        for (ProbeDefinition probe : getProbes(attackType)) {
            if (probe.getStrategy() != null && probe.isEnabledByDefault()) {
                strategies.add(probe.getStrategy());
            }
        }
        return Collections.unmodifiableSet(strategies);
    }

    @Override
    public Map<AttackType, Set<StrategyType>> getRuleCapabilities() {
        Map<AttackType, Set<StrategyType>> capabilities = new LinkedHashMap<>();
        for (String attackTypeName : probeMap.keySet()) {
            AttackType attackType = RuleKeyUtil.toAttackType(attackTypeName).orElse(null);
            if (attackType == null) {
                continue;
            }
            Set<StrategyType> strategies = getSupportedStrategyTypes(attackType);
            if (!strategies.isEmpty()) capabilities.put(attackType, strategies);
        }
        return Collections.unmodifiableMap(capabilities);
    }

    @Override
    public Map<String, Set<String>> getRuleCapabilityNames() {
        Map<String, Set<String>> capabilities = new LinkedHashMap<>();
        for (String attackTypeName : probeMap.keySet()) {
            Set<String> strategies = getSupportedStrategyNames(attackTypeName);
            if (!strategies.isEmpty()) {
                capabilities.put(attackTypeName, strategies);
            }
        }
        return Collections.unmodifiableMap(capabilities);
    }

    @Override
    public Map<String, Set<String>> getAttackTypeAliases() {
        Map<String, Set<String>> copy = new LinkedHashMap<>();
        aliasMap.forEach((key, value) -> copy.put(key, Collections.unmodifiableSet(new LinkedHashSet<>(value))));
        return Collections.unmodifiableMap(copy);
    }

    @Override
    public Set<String> getSupportedStrategyNames(String attackTypeName) {
        Set<String> strategies = new LinkedHashSet<>();
        for (ProbeDefinition probe : getProbes(attackTypeName)) {
            String strategyName = probe.getStrategyName();
            if (strategyName != null && probe.isEnabledByDefault()) {
                strategies.add(strategyName);
            }
        }
        return Collections.unmodifiableSet(strategies);
    }

    @Override
    public void reload() {
        probeMap.clear();
        workflowConfigMap.clear();
        aliasMap.clear();
        scanExternalPayloads();
        if (probeMap.isEmpty()) {
            for (String fileName : PAYLOAD_FILES) {
                loadPayloadFile(fileName);
            }
        }
        log.info("Probe rules loaded: {} attack types, {} probes, {} payload entries",
                probeMap.size(), countTotalProbes(), countTotalPayloads());
    }

    private void scanExternalPayloads() {
        Path externalPayloadDir = ExternalResourcePaths.payloadRulesDir();
        try {
            if (Files.exists(externalPayloadDir)) {
                try (var stream = Files.list(externalPayloadDir)) {
                    stream.filter(path -> path.toString().endsWith(".yaml")
                                    || path.toString().endsWith(".yml"))
                            .forEach(this::loadPayloadFromPath);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to scan external probe dir: {}", externalPayloadDir, e);
        }
    }

    private void loadPayloadFromPath(Path filePath) {
        try {
            String content = Files.readString(filePath);
            @SuppressWarnings("unchecked")
            Map<String, Object> root = yamlMapper.readValue(content, Map.class);
            loadRoot(filePath.getFileName().toString(), root, true);
        } catch (Exception e) {
            log.error("Failed to load external probe rules: {}", filePath, e);
        }
    }

    @SuppressWarnings("unchecked")
    private void loadPayloadFile(String fileName) {
        String path = PAYLOADS_DIR + fileName;
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(path)) {
            if (in == null) {
                log.warn("Probe rule file not found: {}", path);
                return;
            }
            Map<String, Object> root = yamlMapper.readValue(in, Map.class);
            loadRoot(fileName, root, false);
        } catch (Exception e) {
            log.error("Failed to load probe rule file: {}", fileName, e);
        }
    }

    private void loadRoot(String sourceName, Map<String, Object> root, boolean externalOverride) {
        String attackTypeName = RuleKeyUtil.normalize(stringValue(root.get("attackType"), null));
        if (attackTypeName == null) {
            log.warn("Missing attackType in probe file: {}", sourceName);
            return;
        }

        List<ProbeDefinition> probes = loadProbeRules(attackTypeName, root);
        if (probes.isEmpty()) {
            log.warn("No probes found in probe file: {}", sourceName);
            return;
        }

        if (externalOverride) {
            probeMap.put(attackTypeName, probes);
            workflowConfigMap.put(attackTypeName, parseWorkflowConfig(root));
        } else {
            probeMap.computeIfAbsent(attackTypeName, ignored -> new ArrayList<>()).addAll(probes);
            workflowConfigMap.putIfAbsent(attackTypeName, parseWorkflowConfig(root));
        }
        registerAliases(attackTypeName, root);
        log.debug("Loaded probe file: {} attackType={} probes={}",
                sourceName, attackTypeName, probes.size());
    }

    @SuppressWarnings("unchecked")
    private RuleWorkflowConfig parseWorkflowConfig(Map<String, Object> root) {
        RuleWorkflowConfig config = new RuleWorkflowConfig();
        Object rawWorkflow = root.get("workflow");
        if (rawWorkflow instanceof Map<?, ?> workflowMap) {
            Map<String, Object> map = (Map<String, Object>) workflowMap;
            config.setName(stringValue(map.get("name"), null));
            config.setDescription(stringValue(map.get("description"), null));
            config.setIncludeInfluenceStep(booleanValue(map.get("includeInfluenceStep"), true));
            config.setRequiresInfluenceApproval(booleanValue(map.get("requiresInfluenceApproval"), true));
        }
        return config;
    }

    private void registerAliases(String attackTypeName, Map<String, Object> root) {
        Set<String> aliases = aliasMap.computeIfAbsent(attackTypeName, ignored -> new LinkedHashSet<>());
        aliases.add(attackTypeName);
        addAlias(aliases, stringValue(root.get("displayName"), null));
        addAlias(aliases, stringValue(root.get("name"), null));
        addAlias(aliases, stringValue(root.get("description"), null));
        for (String alias : stringList(root.get("aliases"))) {
            addAlias(aliases, alias);
        }
    }

    private void addAlias(Set<String> aliases, String value) {
        String normalized = RuleKeyUtil.normalize(value);
        if (normalized != null) {
            aliases.add(normalized);
        }
    }

    private String resolveAttackTypeName(String value) {
        String normalized = RuleKeyUtil.normalize(value);
        if (normalized == null) {
            return null;
        }
        if (probeMap.containsKey(normalized)) {
            return normalized;
        }
        for (Map.Entry<String, Set<String>> entry : aliasMap.entrySet()) {
            for (String alias : entry.getValue()) {
                if (aliasMatches(normalized, alias)) {
                    return entry.getKey();
                }
            }
        }
        for (String attackTypeName : probeMap.keySet()) {
            if (aliasMatches(normalized, attackTypeName)) {
                return attackTypeName;
            }
        }
        return normalized;
    }

    private boolean aliasMatches(String value, String alias) {
        String normalizedAlias = RuleKeyUtil.normalize(alias);
        return value != null
                && normalizedAlias != null
                && (value.equals(normalizedAlias)
                || value.contains(normalizedAlias)
                || normalizedAlias.contains(value));
    }

    @SuppressWarnings("unchecked")
    private List<ProbeDefinition> loadProbeRules(String attackTypeName, Map<String, Object> root) {
        Object rawProbes = root.get("probes");
        if (!(rawProbes instanceof List<?> probeList)) {
            if (root.containsKey("rules")) {
                log.warn("Ignoring legacy payload rules for {}. Convert them to probes.", attackTypeName);
            }
            return List.of();
        }

        List<ProbeDefinition> probes = new ArrayList<>();
        for (Object rawProbe : probeList) {
            if (rawProbe instanceof Map<?, ?> probeMap) {
                ProbeDefinition probe = parseProbe(attackTypeName, (Map<String, Object>) probeMap);
                if (probe != null) {
                    probes.add(probe);
                }
            }
        }
        return probes;
    }

    @SuppressWarnings("unchecked")
    private ProbeDefinition parseProbe(String attackTypeName, Map<String, Object> map) {
        ProbeDefinition probe = new ProbeDefinition();
        probe.setAttackTypeName(attackTypeName);
        probe.setId(stringValue(map.get("id"), attackTypeName.toLowerCase() + "_probe"));
        probe.setTechnique(stringValue(map.get("technique"), null));
        probe.setStrategyName(stringValue(map.get("strategy"), null));
        probe.setEnabledByDefault(booleanValue(map.get("enabledByDefault"), true));
        probe.setPriority(intValue(map.get("priority"), 100));
        probe.setStopOnMatch(booleanValue(map.get("stopOnMatch"), true));
        probe.setMaxRequests(intValue(map.get("maxRequests"), 1));
        probe.setMaxPayloadLength(intValue(map.get("maxPayloadLength"), 128));
        probe.setEvidenceWeight(doubleValue(map.get("evidenceWeight"), 0.5));
        probe.setApplicableParamTypes(stringList(map.get("applicableParamTypes")));
        probe.setValueTypes(stringList(map.get("valueTypes")));
        probe.setRequiresLlmReview(booleanValue(map.get("requiresLlmReview"), false));

        Object rawPayloads = map.get("payloads");
        if (rawPayloads instanceof List<?> payloadList) {
            List<ProbePayload> payloads = new ArrayList<>();
            for (Object rawPayload : payloadList) {
                ProbePayload payload = parsePayload(rawPayload);
                if (payload != null) {
                    payloads.add(payload);
                }
            }
            probe.setPayloads(payloads);
        }

        Object rawPairs = map.get("payloadPairs");
        if (rawPairs instanceof List<?> pairList) {
            List<ProbePayloadPair> pairs = new ArrayList<>();
            for (Object rawPair : pairList) {
                if (rawPair instanceof Map<?, ?> pairMap) {
                    Map<String, Object> pairValues = (Map<String, Object>) pairMap;
                    ProbePayloadPair pair = new ProbePayloadPair();
                    pair.setTrueValue(stringValue(pairValues.get("trueValue"), null));
                    pair.setFalseValue(stringValue(pairValues.get("falseValue"), null));
                    pair.setTrueMutation(stringValue(pairValues.get("trueMutation"),
                            stringValue(pairValues.get("mutation"), "REPLACE")));
                    pair.setFalseMutation(stringValue(pairValues.get("falseMutation"),
                            stringValue(pairValues.get("mutation"), "REPLACE")));
                    if (pair.getTrueValue() != null && pair.getFalseValue() != null) {
                        pairs.add(pair);
                    }
                }
            }
            probe.setPayloadPairs(pairs);
        }

        Object rawOracle = map.get("oracle");
        if (rawOracle instanceof Map<?, ?> oracleMap) {
            probe.setOracle(parseOracle((Map<String, Object>) oracleMap));
        }
        return probe;
    }

    @SuppressWarnings("unchecked")
    private ProbePayload parsePayload(Object rawPayload) {
        ProbePayload payload = new ProbePayload();
        if (rawPayload instanceof String value) {
            payload.setValue(value);
            return payload;
        }
        if (!(rawPayload instanceof Map<?, ?> payloadMap)) {
            return null;
        }

        Map<String, Object> map = (Map<String, Object>) payloadMap;
        payload.setValue(stringValue(map.get("value"), null));
        payload.setMutation(stringValue(map.get("mutation"), "REPLACE"));
        String role = stringValue(map.get("role"), "SINGLE");
        try {
            payload.setRole(ProbeRole.valueOf(role.trim().toUpperCase()));
        } catch (IllegalArgumentException ignored) {
            payload.setRole(ProbeRole.SINGLE);
        }

        Object markers = map.get("markers");
        if (markers instanceof List<?> markerList) {
            payload.setMarkers(markerList.stream().map(String::valueOf).toList());
        }
        return payload.getValue() != null ? payload : null;
    }

    private String displayPayload(ProbePayload payload) {
        if (payload == null || payload.getValue() == null) {
            return null;
        }
        String mutation = payload.getMutation();
        if (mutation == null || "REPLACE".equalsIgnoreCase(mutation)) {
            return payload.getValue();
        }
        return mutation + "(" + payload.getValue() + ")";
    }

    private OracleDefinition parseOracle(Map<String, Object> map) {
        OracleDefinition oracle = new OracleDefinition();
        oracle.setType(stringValue(map.get("type"), null));
        oracle.setKeywords(stringList(map.get("keywords")));
        oracle.setErrorKeywords(stringList(map.get("errorKeywords")));
        oracle.setRequireMarkers(stringList(map.get("requireMarkers")));
        oracle.setRequireExactPayload(booleanValue(map.get("requireExactPayload"), false));
        oracle.setRequireUnescaped(booleanValue(map.get("requireUnescaped"), false));
        oracle.setRecoveryPayloadIndex(intValue(map.get("recoveryPayloadIndex"), -1));
        oracle.setMinDelayMs(longValue(map.get("minDelayMs"), 2500));
        oracle.setBaselineMultiplier(doubleValue(map.get("baselineMultiplier"), 2.5));
        oracle.setMinSimilarityTrueBaseline(doubleValue(map.get("minSimilarityTrueBaseline"), 0.90));
        oracle.setMaxSimilarityTrueFalse(doubleValue(map.get("maxSimilarityTrueFalse"), 0.80));
        oracle.setMinConfidence(doubleValue(map.get("minConfidence"), 0.7));
        return oracle;
    }

    private int countTotalProbes() {
        return probeMap.values().stream().mapToInt(List::size).sum();
    }

    private int countTotalPayloads() {
        int count = 0;
        for (List<ProbeDefinition> probes : probeMap.values()) {
            for (ProbeDefinition probe : probes) {
                count += probe.getPayloads().size();
                count += probe.getPayloadPairs().size() * 2;
            }
        }
        return count;
    }

    private String stringValue(Object value, String defaultValue) {
        return value != null ? String.valueOf(value) : defaultValue;
    }

    private boolean booleanValue(Object value, boolean defaultValue) {
        return value != null ? Boolean.parseBoolean(String.valueOf(value)) : defaultValue;
    }

    private int intValue(Object value, int defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(String.valueOf(value));
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private long longValue(Object value, long defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        try {
            return Long.parseLong(String.valueOf(value));
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private double doubleValue(Object value, double defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        try {
            return Double.parseDouble(String.valueOf(value));
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private List<String> stringList(Object value) {
        if (value instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return List.of();
    }
}
