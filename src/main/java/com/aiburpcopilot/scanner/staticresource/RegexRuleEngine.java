package com.aiburpcopilot.scanner.staticresource;

import com.aiburpcopilot.core.config.ExternalResourcePaths;
import com.aiburpcopilot.utils.Constants;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 正则规则引擎。
 * <p>
 * 从 YAML 配置文件加载静态资源扫描规则，缓存已编译的 Pattern。
 * <p>
 * 规则文件位置：classpath:/rules/static-resource-rules.yaml
 * 支持外部覆盖：~/.ai-burp-copilot/rules/static-resource-rules.yaml
 * <p>
 * 如果 YAML 加载失败或为空，自动降级到内置硬编码规则。
 * <p>
 * Phase 2 扩展点：
 * <ul>
 *   <li>支持热加载（监听文件变更自动重载）</li>
 *   <li>支持按路径/域名配置规则白名单</li>
 *   <li>支持规则分组和优先级</li>
 * </ul>
 */
public class RegexRuleEngine {

    private static final Logger log = LoggerFactory.getLogger(RegexRuleEngine.class);

    /** YAML 规则文件路径（classpath） */
    private static final String RULES_YAML_PATH = "rules/static-resource-rules.yaml";

    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());

    /** 已加载的编译后规则 */
    private volatile List<CompiledRule> compiledRules = new ArrayList<>();

    public RegexRuleEngine() {
        ExternalResourcePaths.initialize();
        reload();
    }

    /**
     * 重新加载规则（支持热更新）。
     */
    public synchronized void reload() {
        List<RuleDefinition> definitions = loadFromYaml();
        if (definitions.isEmpty()) {
            log.warn("No rules loaded from YAML, falling back to built-in defaults");
            definitions = createBuiltinRules();
        }
        this.compiledRules = definitions.stream()
                .filter(RuleDefinition::isEnabled)
                .map(this::compile)
                .collect(Collectors.toList());
        log.info("RegexRuleEngine loaded {} rules ({} total definitions)",
                compiledRules.size(), definitions.size());
    }

    /**
     * 对内容执行所有规则匹配。
     *
     * @param content 待扫描的文本内容
     * @return 匹配到的发现列表
     */
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

    /**
     * 获取当前加载的规则数量。
     */
    public int getRuleCount() {
        return compiledRules.size();
    }

    // ========== YAML Loading ==========

    /**
     * 从 classpath YAML 或外部文件加载规则定义。
     * 外部文件优先，如果外部文件存在则使用外部文件。
     */
    private List<RuleDefinition> loadFromYaml() {
        // 1. 优先检查外部文件
        try {
            java.nio.file.Path externalPath = ExternalResourcePaths.staticRulesFile();
            if (java.nio.file.Files.exists(externalPath) && java.nio.file.Files.isReadable(externalPath)) {
                String content = java.nio.file.Files.readString(externalPath);
                RuleConfig config = YAML_MAPPER.readValue(content, RuleConfig.class);
                if (config != null && config.getRules() != null && !config.getRules().isEmpty()) {
                    log.info("Loaded {} rule definitions from external: {}",
                            config.getRules().size(), externalPath);
                    return config.getRules();
                }
            }
        } catch (Exception e) {
            log.debug("No external rules found at {}: {}",
                    ExternalResourcePaths.staticRulesFile(), e.getMessage());
        }

        // 2. 回退到 classpath
        try {
            InputStream is = getClass().getClassLoader().getResourceAsStream(RULES_YAML_PATH);
            if (is == null) {
                log.warn("Rules YAML not found at: {}", RULES_YAML_PATH);
                return Collections.emptyList();
            }

            RuleConfig config = YAML_MAPPER.readValue(is, RuleConfig.class);
            if (config == null || config.getRules() == null || config.getRules().isEmpty()) {
                log.warn("Rules YAML is empty or malformed");
                return Collections.emptyList();
            }

            log.info("Loaded {} rule definitions from classpath {}", config.getRules().size(), RULES_YAML_PATH);
            return config.getRules();

        } catch (Exception e) {
            log.warn("Failed to load rules YAML: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * 创建内置硬编码规则（降级方案）。
     */
    private List<RuleDefinition> createBuiltinRules() {
        List<RuleDefinition> rules = new ArrayList<>();
        rules.add(new RuleDefinition("AWS Access Key", Constants.REGEX_AWS_KEY, "HIGH", true, ""));
        rules.add(new RuleDefinition("Google API Key", Constants.REGEX_GOOGLE_KEY, "HIGH", true, ""));
        rules.add(new RuleDefinition("Hardcoded Secret", Constants.REGEX_SECRET, "HIGH", true, ""));
        rules.add(new RuleDefinition("Hardcoded Token", Constants.REGEX_TOKEN, "HIGH", true, ""));
        rules.add(new RuleDefinition("Source Mapping URL", Constants.REGEX_SOURCE_MAP, "MEDIUM", true, ""));
        rules.add(new RuleDefinition("Internal IP Address", Constants.REGEX_INTERNAL_IP, "MEDIUM", true, ""));
        rules.add(new RuleDefinition("Internal Domain", Constants.REGEX_INTERNAL_DOMAIN, "MEDIUM", true, ""));
        return rules;
    }

    /**
     * 将规则定义编译为正则 Pattern。
     */
    private CompiledRule compile(RuleDefinition def) {
        return new CompiledRule(def.getName(), Pattern.compile(def.getRegex()), def.getSeverity());
    }

    // ========== YAML Model ==========

    /**
     * YAML 根结构：{ rules: [...] }
     */
    private static class RuleConfig {
        private List<RuleDefinition> rules;

        public List<RuleDefinition> getRules() { return rules; }
        public void setRules(List<RuleDefinition> rules) { this.rules = rules; }
    }

    /**
     * 单条规则定义（对应 YAML 中的一条规则）。
     */
    private static class RuleDefinition {
        private String name;
        private String regex;
        private String severity = "MEDIUM";
        private boolean enabled = true;
        private String description = "";

        public RuleDefinition() {}

        public RuleDefinition(String name, String regex, String severity, boolean enabled, String description) {
            this.name = name;
            this.regex = regex;
            this.severity = severity;
            this.enabled = enabled;
            this.description = description;
        }

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

    // ========== Internal Model ==========

    /**
     * 编译后的规则（含 Pattern 对象）。
     */
    private static class CompiledRule {
        final String name;
        final Pattern pattern;
        final String severity;

        CompiledRule(String name, Pattern pattern, String severity) {
            this.name = name;
            this.pattern = pattern;
            this.severity = severity;
        }
    }
}
