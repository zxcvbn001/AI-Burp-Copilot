package com.aiburpcopilot.core.verification.policy.impl;

import com.aiburpcopilot.core.config.ExternalResourcePaths;
import com.aiburpcopilot.core.verification.model.VerificationPolicy;
import com.aiburpcopilot.core.verification.policy.IPolicyEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * 策略引擎实现。
 * <p>
 * 管理验证策略的加载、更新和查询。
 * 策略配置从 {@code ~/.ai-burp-copilot/verification-policy.yaml} 加载。
 * 如果配置文件不存在，使用内置默认值。
 * <p>
 * 线程安全：使用 volatile 引用确保可见性，更新方法加锁。
 */
public class PolicyEngine implements IPolicyEngine {

    private static final Logger log = LoggerFactory.getLogger(PolicyEngine.class);

    /** 策略配置文件路径 */
    private static final String CONFIG_FILE = "verification-policy.yaml";

    private volatile VerificationPolicy policy;

    public PolicyEngine() {
        ExternalResourcePaths.initialize();
        // 初始化时加载一次
        this.policy = createDefaultPolicy();
        log.info("PolicyEngine initialized, config path: {}", configPath().toAbsolutePath());
    }

    private Path configPath() {
        return ExternalResourcePaths.homeDir().resolve(CONFIG_FILE);
    }

    @Override
    public VerificationPolicy getPolicy() {
        return policy;
    }

    @Override
    public synchronized void updatePolicy(VerificationPolicy policy) {
        if (policy == null) {
            log.warn("Attempted to update policy with null, ignoring");
            return;
        }
        this.policy = policy;
        log.info("Policy updated: {}", policy);
    }

    @Override
    public boolean isTimeBasedAllowed() {
        VerificationPolicy p = policy;
        return p != null && p.isEnabled() && p.isAllowTimeBased();
    }

    @Override
    public boolean isUnionBasedAllowed() {
        VerificationPolicy p = policy;
        return p != null && p.isEnabled() && p.isAllowUnionBased();
    }

    @Override
    public boolean isErrorBasedAllowed() {
        VerificationPolicy p = policy;
        return p != null && p.isEnabled() && p.isAllowErrorBased();
    }

    @Override
    public int getMaxReplayRequests() {
        VerificationPolicy p = policy;
        return p != null ? p.getMaxReplayRequests() : 5;
    }

    @Override
    public int getMaxParameterTests() {
        VerificationPolicy p = policy;
        return p != null ? p.getMaxParameterTests() : 20;
    }

    @Override
    public double getMinInfluenceScore() {
        VerificationPolicy p = policy;
        return p != null ? p.getMinInfluenceScore() : 0.1;
    }

    /**
     * 检查指定 URL 的主机是否在验证白名单中。
     * <p>
     * 规则：
     * <ul>
     *   <li>如果白名单为空，允许所有主机（默认放行）</li>
     *   <li>如果白名单不为空，仅允许匹配白名单条目的主机</li>
     *   <li>匹配规则：主机名完全相等，或白名单条目以点号开头时匹配子域名</li>
     * </ul>
     *
     * @param url 目标 URL 字符串，为 null 或空则返回 true（作为降级安全策略）
     * @return 是否允许对该主机执行验证
     */
    @Override
    public boolean isHostAllowed(String url) {
        VerificationPolicy p = policy;
        if (p == null) {
            return true;
        }

        List<String> whitelist = p.getWhitelist();
        if (whitelist == null || whitelist.isEmpty()) {
            // 白名单为空，允许所有
            return true;
        }

        if (url == null || url.isEmpty()) {
            // 无法解析 URL 时降级为允许（避免阻塞合法请求）
            return true;
        }

        String host = parseHost(url);
        if (host == null) {
            return true;
        }

        for (String entry : whitelist) {
            if (entry == null || entry.isEmpty()) {
                continue;
            }
            // 完全匹配
            if (host.equalsIgnoreCase(entry)) {
                return true;
            }
            // 子域名匹配（如 ".example.com" 匹配 "api.example.com"）
            if (entry.startsWith(".")) {
                if (host.endsWith(entry) || host.equals(entry.substring(1))) {
                    return true;
                }
            }
        }

        log.debug("Host '{}' not in whitelist (entries: {})", host, whitelist);
        return false;
    }

    /**
     * 从 URL 字符串中解析主机名。
     *
     * @param urlStr URL 字符串
     * @return 主机名，解析失败返回 null
     */
    private String parseHost(String urlStr) {
        if (urlStr == null || urlStr.isEmpty()) {
            return null;
        }
        try {
            // 尝试补全协议头以便标准解析
            String normalized = urlStr;
            if (!normalized.contains("://")) {
                normalized = "https://" + normalized;
            }
            return new URL(normalized).getHost();
        } catch (MalformedURLException e) {
            // 退化处理：手动提取 "://" 之后到第一个 "/" 之间的部分
            try {
                String temp = urlStr;
                int schemeEnd = temp.indexOf("://");
                if (schemeEnd >= 0) {
                    temp = temp.substring(schemeEnd + 3);
                } else if (temp.startsWith("//")) {
                    temp = temp.substring(2);
                }
                // 去除路径、查询参数等
                int slash = temp.indexOf('/');
                if (slash >= 0) {
                    temp = temp.substring(0, slash);
                }
                int colon = temp.lastIndexOf(':');
                int atIndex = temp.indexOf('@');
                if (atIndex >= 0) {
                    // 有认证信息（如 user:pass@host）
                    temp = temp.substring(atIndex + 1);
                }
                if (colon >= 0 && colon > (atIndex >= 0 ? 0 : -1)) {
                    temp = temp.substring(0, colon);
                }
                return temp.isEmpty() ? null : temp;
            } catch (Exception ex) {
                log.debug("Failed to parse host from URL: {}", urlStr, ex);
                return null;
            }
        }
    }

    /**
     * 从外部配置文件重新加载策略。
     * <p>
     * 配置文件路径：{@code ~/.ai-burp-copilot/verification-policy.yaml}
     * 如果文件不存在，使用默认值。
     * 如果文件格式错误，保留当前策略不变并记录错误。
     */
    @Override
    public synchronized void reload() {
        try {
            Path configPath = configPath();
            Path parent = configPath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }

            if (Files.exists(configPath)) {
                String content = Files.readString(configPath, StandardCharsets.UTF_8);
                VerificationPolicy loaded = parsePolicyYaml(content);
                if (loaded != null) {
                    this.policy = loaded;
                    log.info("Policy reloaded from: {}", configPath.toAbsolutePath());
                } else {
                    log.warn("Failed to parse policy YAML, keeping current policy");
                }
            } else {
                log.info("Policy config file not found at {}, using defaults", configPath.toAbsolutePath());
                this.policy = createDefaultPolicy();
            }
        } catch (IOException e) {
            log.error("Failed to read policy config file: {}", configPath().toAbsolutePath(), e);
        }
    }

    /**
     * 将 YAML 内容解析为 VerificationPolicy 对象。
     * <p>
     * 使用 SnakeYAML 解析 Map，然后手动填充字段，
     * 以兼容 SnakeYAML 2.x 的类型安全 API。
     *
     * @param yamlContent YAML 字符串
     * @return 解析后的策略对象，解析失败返回 null
     */
    @SuppressWarnings("unchecked")
    private VerificationPolicy parsePolicyYaml(String yamlContent) {
        try {
            Yaml yaml = new Yaml();
            Map<String, Object> data = yaml.load(yamlContent);
            if (data == null) {
                return createDefaultPolicy();
            }

            VerificationPolicy p = new VerificationPolicy();

            if (data.get("enabled") instanceof Boolean) {
                p.setEnabled((Boolean) data.get("enabled"));
            }
            if (data.get("allowTimeBased") instanceof Boolean) {
                p.setAllowTimeBased((Boolean) data.get("allowTimeBased"));
            }
            if (data.get("allowUnionBased") instanceof Boolean) {
                p.setAllowUnionBased((Boolean) data.get("allowUnionBased"));
            }
            if (data.get("allowErrorBased") instanceof Boolean) {
                p.setAllowErrorBased((Boolean) data.get("allowErrorBased"));
            }
            if (data.get("maxReplayRequests") instanceof Integer) {
                p.setMaxReplayRequests((Integer) data.get("maxReplayRequests"));
            } else if (data.get("maxReplayRequests") instanceof Number) {
                p.setMaxReplayRequests(((Number) data.get("maxReplayRequests")).intValue());
            }
            if (data.get("maxParameterTests") instanceof Integer) {
                p.setMaxParameterTests((Integer) data.get("maxParameterTests"));
            } else if (data.get("maxParameterTests") instanceof Number) {
                p.setMaxParameterTests(((Number) data.get("maxParameterTests")).intValue());
            }
            if (data.get("minInfluenceScore") instanceof Double) {
                p.setMinInfluenceScore((Double) data.get("minInfluenceScore"));
            } else if (data.get("minInfluenceScore") instanceof Number) {
                p.setMinInfluenceScore(((Number) data.get("minInfluenceScore")).doubleValue());
            }
            if (data.get("requestTimeoutMs") instanceof Integer) {
                p.setRequestTimeoutMs((Integer) data.get("requestTimeoutMs"));
            } else if (data.get("requestTimeoutMs") instanceof Number) {
                p.setRequestTimeoutMs(((Number) data.get("requestTimeoutMs")).intValue());
            }
            if (data.get("maxPayloadLength") instanceof Integer) {
                p.setMaxPayloadLength((Integer) data.get("maxPayloadLength"));
            } else if (data.get("maxPayloadLength") instanceof Number) {
                p.setMaxPayloadLength(((Number) data.get("maxPayloadLength")).intValue());
            }
            if (data.get("whitelist") instanceof List) {
                List<String> whitelist = (List<String>) data.get("whitelist");
                p.setWhitelist(whitelist);
            }

            return p;
        } catch (Exception e) {
            log.error("Error parsing policy YAML content", e);
            return null;
        }
    }

    /**
     * 创建默认策略配置。
     */
    private VerificationPolicy createDefaultPolicy() {
        VerificationPolicy p = new VerificationPolicy();
        p.setEnabled(true);
        p.setAllowTimeBased(false);
        p.setAllowUnionBased(false);
        p.setAllowErrorBased(true);
        p.setMaxReplayRequests(5);
        p.setMaxParameterTests(20);
        p.setMinInfluenceScore(0.1);
        p.setRequestTimeoutMs(5000);
        p.setMaxPayloadLength(128);
        p.setWhitelist(new java.util.ArrayList<>());
        return p;
    }
}
