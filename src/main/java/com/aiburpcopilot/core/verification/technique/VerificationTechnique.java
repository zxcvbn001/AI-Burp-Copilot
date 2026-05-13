package com.aiburpcopilot.core.verification.technique;

/**
 * 验证技术枚举。
 * <p>
 * 定义验证框架支持的测试技术，按"能力层"而非"漏洞类型"设计。
 * 每种技术描述"如何验证"一种漏洞类型，AttackType 决定"验证什么"，
 * VerificationTechnique 决定"怎么验证"。
 * <p>
 * 三大设计原则：
 * <ol>
 *   <li>技术是 AttackType 无关的抽象概念</li>
 *   <li>新增攻击类型只能新增技术，不能修改引擎</li>
 *   <li>技术枚举值只描述行为，不包含业务逻辑</li>
 * </ol>
 *
 * <h3>当前支持的技术</h3>
 * <ul>
 *   <li><b>SQLI:</b> BOOLEAN_BASED, ERROR_BASED, TIME_BASED, UNION_BASED</li>
 *   <li><b>IDOR:</b> NUMERIC_INCREMENT, UUID_SWAP</li>
 *   <li><b>AUTH:</b> REMOVE_TOKEN, ROLE_SWITCH</li>
 *   <li><b>SSRF:</b> LOCALHOST_PROBE</li>
 * </ul>
 *
 * <h3>未来扩展示例（不修改核心引擎）</h3>
 * <pre>{@code
 *   GRAPHQL_INTROSPECTION,
 *   JWT_ALG_CONFUSION,
 *   WEBSOCKET_REPLAY
 * }</pre>
 */
public enum VerificationTechnique {

    // ---- SQLI ----
    /** 布尔盲注 — true/false payload 对比 */
    BOOLEAN_BASED("Boolean Based", "SQLI"),

    /** 基于错误 — 触发数据库错误信息 */
    ERROR_BASED("Error Based", "SQLI"),

    /** 基于时间 — 观察响应延迟差异 */
    TIME_BASED("Time Based", "SQLI"),

    /** 联合查询 — UNION SELECT 探测列数（Phase 2 默认禁用） */
    UNION_BASED("Union Based", "SQLI"),

    // ---- IDOR ----
    /** 数字递增 — 将 ID 参数值 +1 或替换为相邻值 */
    NUMERIC_INCREMENT("Numeric Increment", "IDOR"),

    /** UUID 替换 — 将用户 UUID 替换为另一个已知 UUID */
    UUID_SWAP("UUID Swap", "IDOR"),

    // ---- AUTH ----
    /** 移除 Token — 完全删除 Authorization Header */
    REMOVE_TOKEN("Remove Token", "AUTH"),

    /** 角色切换 — 将低权限 Token 替换为已知高权限 Token */
    ROLE_SWITCH("Role Switch", "AUTH"),

    // ---- SSRF ----
    /** 本地回环探测 — 将 URL 替换为 localhost/127.0.0.1 */
    LOCALHOST_PROBE("Localhost Probe", "SSRF"),

    // ---- XSS ----
    REFLECTION("Reflection", "XSS"),

    // ---- Path Traversal ----
    PATH_TRAVERSAL_PROBE("Path Traversal Probe", "PATH_TRAVERSAL");

    private final String displayName;

    /** 所属攻击类型范畴（用于文档/UI 分组，不影响逻辑） */
    private final String category;

    VerificationTechnique(String displayName, String category) {
        this.displayName = displayName;
        this.category = category;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getCategory() {
        return category;
    }

    /**
     * 根据字符串名称查找技术（大小写不敏感）。
     *
     * @param name 技术名称，如 "BOOLEAN_BASED", "boolean based"
     * @return 匹配的 VerificationTechnique，若未找到返回 null
     */
    public static VerificationTechnique fromString(String name) {
        if (name == null || name.isBlank()) return null;
        String normalized = name.trim().toUpperCase().replace(' ', '_').replace('-', '_');
        for (VerificationTechnique t : values()) {
            if (t.name().equals(normalized) || t.displayName.toUpperCase().replace(' ', '_').equals(normalized)) {
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
