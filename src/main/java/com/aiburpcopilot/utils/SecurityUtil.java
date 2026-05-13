package com.aiburpcopilot.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 安全工具类。
 * <p>
 * 处理安全相关的数据清洗、截断和注入防护。
 * 所有送往 AI 的用户数据均需经过此工具清洗。
 * <p>
 * 安全措施：
 * <ul>
 *   <li>Prompt Injection 防护 - 移除用户数据中的指令覆盖标记</li>
 *   <li>响应体大小限制 - 截断过大的响应体</li>
 *   <li>Prompt 长度限制 - 确保总 Prompt 不超过 API 限制</li>
 * </ul>
 */
public final class SecurityUtil {

    private static final Logger log = LoggerFactory.getLogger(SecurityUtil.class);

    private SecurityUtil() {}

    /** 默认最大响应体大小（1MB） */
    public static final int MAX_RESPONSE_BODY_SIZE = 1 * 1024 * 1024;

    /** 默认最大 Prompt 长度（UTF-8 字符数） */
    public static final int MAX_PROMPT_LENGTH = 8000;

    /** Prompt Injection 模式 */
    private static final String[] INJECTION_PATTERNS = {
            "ignore previous instructions",
            "ignore all previous",
            "forget previous",
            "disregard previous",
            "new instructions:",
            "system prompt:",
            "system:",
            "you are now",
            "your new role",
            "act as",
            "pretend you are",
            "override",
            "ignore above",
            "dismiss above",
            "do not follow",
    };

    // ========== Prompt Injection 防护 ==========

    /**
     * 清洗用户数据中的潜在 Prompt Injection 模式。
     * <p>
     * 将用户数据中可能包含的指令覆盖语句替换为安全占位符。
     * 不影响正常 HTTP 参数/路径内容。
     *
     * @param text 原始用户数据（URL、路径、body 等）
     * @return 清洗后的文本
     */
    public static String sanitizeForPrompt(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }

        String sanitized = text;
        for (String pattern : INJECTION_PATTERNS) {
            if (containsIgnoreCase(sanitized, pattern)) {
                sanitized = sanitized.replaceAll("(?i)" + java.util.regex.Pattern.quote(pattern), "[REDACTED]");
                log.debug("Prompt injection pattern sanitized: {}", pattern);
            }
        }

        // 如果清洗后变化，说明发现了注入尝试
        if (!sanitized.equals(text)) {
            log.info("Prompt injection patterns detected and sanitized");
        }

        return sanitized;
    }

    /**
     * 包裹用户数据以明确标识其为外部输入。
     * <p>
     * 使用明确的标记将用户数据与 AI Prompt 指令分开，
     * 降低 AI 被用户数据覆盖指令的风险。
     *
     * @param label 数据标签（如 "User Input"、"Request Body"）
     * @param content 用户数据内容
     * @return 带标签的安全包裹文本
     */
    public static String wrapForPrompt(String label, String content) {
        if (content == null || content.isEmpty()) {
            return "[" + label + "]: (empty)\n";
        }

        String sanitized = sanitizeForPrompt(content);
        return "[BEGIN " + label + "]\n"
                + sanitized + "\n"
                + "[END " + label + "]\n";
    }

    // ========== 响应体大小限制 ==========

    /**
     * 截断过大的响应体。
     * <p>
     * 防止超大响应体（如大文件下载）被完整传递到 AI 或内存中。
     *
     * @param body 原始响应体字节
     * @param maxSize 最大允许大小（字节）
     * @return 截断后的字节数组（不超过 maxSize）
     */
    public static byte[] truncateResponseBody(byte[] body, int maxSize) {
        if (body == null) {
            return null;
        }
        if (body.length <= maxSize) {
            return body;
        }

        byte[] truncated = new byte[maxSize];
        System.arraycopy(body, 0, truncated, 0, maxSize);
        log.debug("Response body truncated from {} to {} bytes", body.length, maxSize);
        return truncated;
    }

    /**
     * 截断响应体（使用默认大小限制）。
     */
    public static byte[] truncateResponseBody(byte[] body) {
        return truncateResponseBody(body, MAX_RESPONSE_BODY_SIZE);
    }

    // ========== Prompt 长度限制 ==========

    /**
     * 截断 Prompt 确保不超过最大长度。
     * <p>
     * 优先从末尾截断（保留 Prompt 开头和中间的内容）。
     *
     * @param prompt 原始 Prompt 文本
     * @param maxLength 最大字符数
     * @return 截断后的 Prompt
     */
    public static String truncatePrompt(String prompt, int maxLength) {
        if (prompt == null || prompt.length() <= maxLength) {
            return prompt;
        }

        // 保留前 60% 和后 30%，中间用省略标记
        int keepHead = (int) (maxLength * 0.6);
        int keepTail = (int) (maxLength * 0.3);

        String head = prompt.substring(0, keepHead);
        String tail = prompt.substring(prompt.length() - keepTail);

        String result = head + "\n...(content truncated)...\n" + tail;
        log.debug("Prompt truncated from {} to {} chars", prompt.length(), result.length());
        return result;
    }

    // ========== Private Helpers ==========

    private static boolean containsIgnoreCase(String text, String pattern) {
        return text.toLowerCase().contains(pattern);
    }
}
