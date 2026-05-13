package com.aiburpcopilot.core.context;

/**
 * 攻击类型枚举。
 * <p>
 * 定义验证框架支持的安全测试攻击类型。
 * Phase 2 实现 SQLI / IDOR / SSRF / AUTH，
 * 预留 XSS / PATH_TRAVERSAL 供后续扩展。
 * <p>
 * 所有测试均为最小化安全验证，不执行实际攻击。
 */
public enum AttackType {

    /** SQL 注入 — 仅布尔盲注验证 */
    SQLI("SQL Injection"),

    /** 水平越权 / 不安全的直接对象引用 */
    IDOR("IDOR"),

    /** 服务端请求伪造 — 仅本地回环验证 */
    SSRF("SSRF"),

    /** 认证/授权缺陷 */
    AUTH("Auth Bypass"),

    /** 跨站脚本（预留） */
    XSS("XSS"),

    /** 路径遍历（预留） */
    PATH_TRAVERSAL("Path Traversal"),

    OPEN_REDIRECT("Open Redirect"),

    SSTI("Server-Side Template Injection");

    private final String displayName;

    AttackType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
