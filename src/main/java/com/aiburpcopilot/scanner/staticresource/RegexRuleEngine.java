package com.aiburpcopilot.scanner.staticresource;

import com.aiburpcopilot.core.config.ExternalResourcePaths;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class RegexRuleEngine {

    private static final Logger log = LoggerFactory.getLogger(RegexRuleEngine.class);
    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());

    private volatile List<CompiledRule> compiledRules = new ArrayList<>();

    public RegexRuleEngine() {
        ExternalResourcePaths.initialize();
        reload();
    }

    public synchronized void reload() {
        List<RuleDefinition> definitions = loadFromYaml();
        if (definitions.isEmpty()) {
            throw new IllegalStateException("No static resource rules loaded from configured directory: "
                    + ExternalResourcePaths.staticRulesFile().toAbsolutePath());
        }
        this.compiledRules = definitions.stream()
                .filter(RuleDefinition::isEnabled)
                .map(this::compile)
                .collect(Collectors.toList());
        log.info("RegexRuleEngine loaded {} rules ({} total definitions)",
                compiledRules.size(), definitions.size());
    }

    public List<StaticScanResult.Finding> matchAll(String content) {
        if (content == null || content.isEmpty()) {
            return Collections.emptyList();
        }

        List<StaticScanResult.Finding> findings = new ArrayList<>();
        String[] lines = content.split("\n", -1);

        for (CompiledRule rule : compiledRules) {
            for (int i = 0; i < lines.length; i++) {
                Matcher matcher = rule.pattern.matcher(lines[i]);
                if (matcher.find()) {
                    String matched = matcher.group();
                    if (matched.length() > 80) {
                        matched = matched.substring(0, 80) + "...";
                    }
                    findings.add(new StaticScanResult.Finding(
                            rule.name, matched, i + 1, rule.severity));
                }
            }
        }

        return findings;
    }

    public int getRuleCount() {
        return compiledRules.size();
    }

    private List<RuleDefinition> loadFromYaml() {
        try {
            var externalPath = ExternalResourcePaths.staticRulesFile();
            if (!Files.exists(externalPath) || !Files.isReadable(externalPath)) {
                return Collections.emptyList();
            }
            String content = Files.readString(externalPath);
            RuleConfig config = YAML_MAPPER.readValue(content, RuleConfig.class);
            if (config == null || config.getRules() == null || config.getRules().isEmpty()) {
                return Collections.emptyList();
            }
            log.info("Loaded {} static rules from {}",
                    config.getRules().size(), externalPath.toAbsolutePath());
            return config.getRules();
        } catch (Exception e) {
            log.warn("Failed to load static rules from {}",
                    ExternalResourcePaths.staticRulesFile(), e);
            return Collections.emptyList();
        }
    }

    private CompiledRule compile(RuleDefinition def) {
        return new CompiledRule(def.getName(), Pattern.compile(def.getRegex()), def.getSeverity());
    }

    private static class RuleConfig {
        private List<RuleDefinition> rules;

        public List<RuleDefinition> getRules() { return rules; }
        public void setRules(List<RuleDefinition> rules) { this.rules = rules; }
    }

    private static class RuleDefinition {
        private String name;
        private String regex;
        private String severity = "MEDIUM";
        private boolean enabled = true;
        private String description = "";

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getRegex() { return regex; }
        public void setRegex(String regex) { this.regex = regex; }
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
    }

    private static class CompiledRule {
        private final String name;
        private final Pattern pattern;
        private final String severity;

        private CompiledRule(String name, Pattern pattern, String severity) {
            this.name = name;
            this.pattern = pattern;
            this.severity = severity;
        }
    }
}
