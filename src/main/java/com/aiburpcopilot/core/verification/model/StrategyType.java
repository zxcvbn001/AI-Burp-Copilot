package com.aiburpcopilot.core.verification.model;

/**
 * 测试策略类型枚举。
 * <p>
 * 定义验证框架支持的具体测试方法类型。
 * StrategyType 是"执行层"的测试手段，上承 VerificationTechnique（技术层），
 * 下接 Payload YAML（规则层）。
 * <p>
 * 架构修正后的关系链：
 * <pre>
 *   AttackType → VerificationTechnique → StrategyType → Payload
 * </pre>
 *
 * <h3>当前支持的策略类型</h3>
 * <ul>
 *   <li><b>SQLI:</b> BOOLEAN_BASED_MINIMAL, ERROR_BASED, TIME_BASED, UNION_BASED</li>
 *   <li><b>IDOR:</b> NUMERIC_INCREMENT, UUID_SWAP</li>
 *   <li><b>AUTH:</b> REMOVE_TOKEN, ROLE_SWITCH</li>
 *   <li><b>SSRF:</b> LOCALHOST_PROBE</li>
 * </ul>
 */
public enum StrategyType {

    // ---- SQLI ----
    /** 最小化布尔盲注 — 仅使用安全的 true/false payload */
    BOOLEAN_BASED_MINIMAL("Boolean Based (Minimal)"),

    /** 基于错误 — 观察响应差异 */
    ERROR_BASED("Error Based"),

    /** 基于时间 — 观察响应时间差异 */
    TIME_BASED("Time Based"),

    /** 联合查询 — UNION SELECT 探测（默认禁用） */
    UNION_BASED("Union Based"),

    // ---- IDOR ----
    /** 数字递增 — 将 ID 参数值 +1 */
    NUMERIC_INCREMENT("Numeric Increment"),

    /** UUID 替换 — 替换为另一个 UUID */
    UUID_SWAP("UUID Swap"),

    // ---- AUTH ----
    /** 移除 Token — 删除授权头 */
    REMOVE_TOKEN("Remove Token"),

    /** 角色切换 — 替换为低权限 Token */
    ROLE_SWITCH("Role Switch"),

    // ---- SSRF ----
    /** 本地回环探测 — URL 替换为 localhost */
    LOCALHOST_PROBE("Localhost Probe"),

    PATH_TRAVERSAL_PROBE("Path Traversal Probe"),

    OPEN_REDIRECT_PROBE("Open Redirect Probe"),

    TEMPLATE_EXPRESSION("Template Expression");

    private final String displayName;

    StrategyType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * 根据字符串名称查找策略类型（大小写不敏感）。
     *
     * @param name 策略名称，如 "BOOLEAN_BASED_MINIMAL", "numeric increment"
     * @return 匹配的 StrategyType，若未找到返回 null
     */
    public static StrategyType fromString(String name) {
        if (name == null || name.isBlank()) return null;
        String normalized = name.trim().toUpperCase().replace(' ', '_').replace('-', '_');
        for (StrategyType t : values()) {
            if (t.name().equals(normalized)
                    || t.displayName.toUpperCase().replace(' ', '_').equals(normalized)) {
                return t;
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
