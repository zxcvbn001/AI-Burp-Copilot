package com.aiburpcopilot.core.verification.safety;

import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * 危险 Payload 过滤器。
 * <p>
 * 静态工具类，在 payload 注入请求之前过滤掉危险内容。
 * 拦截模式：UNION SELECT、SLEEP、BENCHMARK、xp_cmdshell 等数据库危险操作。
 * <p>
 * 此类不可通过依赖注入绕过 — 始终在 {@link #filter} 中生效。
 */
public final class DangerousPayloadFilter {

    private static final Logger log = LoggerFactory.getLogger(DangerousPayloadFilter.class);
    private static final PluginLogger pluginLog = PluginLogger.getInstance();

    private static final Set<String> DANGEROUS_PATTERNS = Set.of(
            "UNION",
            "SLEEP",
            "BENCHMARK",
            "XP_CMDSHELL",
            "WAITFOR DELAY",
            "PG_SLEEP",
            "EXECUTE IMMEDIATE",
            "EXEC SP_",
            "INTO OUTFILE",
            "INTO DUMPFILE",
            "LOAD_FILE",
            "DROP TABLE",
            "ALTER TABLE",
            "CREATE TABLE",
            "INSERT INTO",
            "DELETE FROM",
            "TRUNCATE",
            "SHUTDOWN",
            "--os-shell",
            "cmd.exe",
            "/bin/bash",
            "/bin/sh",
            "powershell"
    );

    private DangerousPayloadFilter() {
    }

    /**
     * 检查 payload 是否包含危险模式。
     *
     * @param payload payload 字符串
     * @return true 如果包含危险内容
     */
    public static boolean isDangerous(String payload) {
        if (payload == null || payload.isEmpty()) return false;
        String upper = payload.toUpperCase();
        for (String pattern : DANGEROUS_PATTERNS) {
            if (upper.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 过滤 payload 列表，仅返回安全的 payload。
     * 被拦截的 payload 会记录日志。
     *
     * @param payloads 原始 payload 列表
     * @return 安全的 payload 列表
     */
    public static List<String> filter(List<String> payloads) {
        if (payloads == null || payloads.isEmpty()) return List.of();

        List<String> safe = new ArrayList<>();
        for (String payload : payloads) {
            if (isDangerous(payload)) {
                log.warn("Dangerous payload blocked by safety filter: {}", truncate(payload));
                pluginLog.warn(PluginLogger.Category.VERIFICATION,
                        "Safety", "Blocked dangerous payload: " + truncate(payload));
            } else {
                safe.add(payload);
            }
        }

        if (safe.size() < payloads.size()) {
            log.info("Payload filter: {}/{} passed, {} blocked",
                    safe.size(), payloads.size(), payloads.size() - safe.size());
        }

        return safe;
    }

    /**
     * 检查 payload 是否超过长度限制。
     *
     * @param payload   payload 字符串
     * @param maxLength 最大允许长度
     * @return true 如果超过限制
     */
    public static boolean isPayloadTooLong(String payload, int maxLength) {
        return payload != null && payload.length() > maxLength;
    }

    private static String truncate(String s) {
        return s.length() > 80 ? s.substring(0, 80) + "..." : s;
    }
}
