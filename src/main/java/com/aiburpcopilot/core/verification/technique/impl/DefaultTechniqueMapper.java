package com.aiburpcopilot.core.verification.technique.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.model.TestStrategy;
import com.aiburpcopilot.core.verification.technique.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * 默认技术映射器实现。
 * <p>
 * 两条映射路径：
 * <ol>
 *   <li><b>AI 推荐路径：</b> 从 AnalysisResult.recommendedTechniques 读取 →
 *       通过 TechniqueRegistry 查找 TechniqueRule → 生成 TestStrategy</li>
 *   <li><b>规则补充路径：</b> 对 AI 未覆盖的参数，根据参数名/值模式
 *       自动推断适用的技术（如 uid → NUMERIC_INCREMENT）</li>
 * </ol>
 * <p>
 * 此实现独立于 Strategy Engine，可单独测试和替换。
 */
public class DefaultTechniqueMapper implements ITechniqueMapper {

    private static final Logger log = LoggerFactory.getLogger(DefaultTechniqueMapper.class);

    private final ITechniqueRegistry registry;

    /** 默认置信度（当 AI 未提供时） */
    private static final double DEFAULT_CONFIDENCE = 0.70;

    public DefaultTechniqueMapper(ITechniqueRegistry registry) {
        this.registry = registry;
    }

    // ========== AI 推荐路径 ==========

    @Override
    public List<TestStrategy> mapToStrategies(List<TechniqueRecommendation> recommendations) {
        List<TestStrategy> strategies = new ArrayList<>();
        if (recommendations == null || recommendations.isEmpty()) {
            return strategies;
        }

        Set<String> seen = new HashSet<>();

        for (TechniqueRecommendation rec : recommendations) {
            if (!rec.isValid()) {
                log.debug("Skipping invalid TechniqueRecommendation: {}", rec);
                continue;
            }

            String attackTypeName = rec.getAttackTypeName();
            if (attackTypeName == null || rec.getTechnique() == null) {
                log.debug("Skipping TechniqueRecommendation without enum-mappable type/technique: {}", rec);
                continue;
            }

            String dedupKey = rec.getParameterName() + "|" + attackTypeName
                    + "|" + rec.getTechnique().name();
            if (seen.contains(dedupKey)) continue;
            seen.add(dedupKey);

            if (rec.getAttackType() == null) {
                log.debug("Skipping TechniqueRecommendation without AttackType enum mapping: {}", rec);
                continue;
            }
            Optional<TechniqueRule> rule = registry.findRule(rec.getAttackType(), rec.getTechnique());
            if (rule.isEmpty()) {
                log.debug("No TechniqueRule for {}/{}", attackTypeName, rec.getTechniqueName());
                continue;
            }

            StrategyType strategyType = rule.get().getStrategyType();
            TestStrategy strategy = new TestStrategy(
                    rec.getAttackType(),
                    rec.getParameterName(),
                    rec.getTechnique(),
                    List.of(strategyType),
                    rec.getConfidence(),
                    rec.getReasoning()
            );
            strategies.add(strategy);

            log.debug("Mapped: {} {} → {} (conf={:.2f})",
                    rec.getAttackType(), rec.getTechnique(),
                    strategyType, rec.getConfidence());
        }

        return strategies;
    }

    // ========== 规则补充路径 ==========

    @Override
    public List<TestStrategy> supplementStrategies(AttackType attackType,
                                                    String parameterName,
                                                    String parameterValue) {
        List<TestStrategy> supplement = new ArrayList<>();
        if (attackType == null || parameterName == null) return supplement;

        switch (attackType) {
            case IDOR:
                supplement.addAll(supplementIdor(parameterName, parameterValue));
                break;
            case AUTH:
                supplement.addAll(supplementAuth(parameterName, parameterValue));
                break;
            case SSRF:
                supplement.addAll(supplementSsrf(parameterName, parameterValue));
                break;
            default:
                break;
        }

        return supplement;
    }

    // ---------- 各类型补充规则 ----------

    /**
     * IDOR 补充：根据参数名和值推断技术。
     */
    private List<TestStrategy> supplementIdor(String paramName, String paramValue) {
        List<TestStrategy> result = new ArrayList<>();

        // 数字 ID 参数 → NUMERIC_INCREMENT
        if (isNumericParam(paramName) && isNumericValue(paramValue)) {
            result.add(createSupplementStrategy(
                    AttackType.IDOR, paramName,
                    VerificationTechnique.NUMERIC_INCREMENT,
                    StrategyType.NUMERIC_INCREMENT,
                    "IDOR supplement: parameter '" + paramName + "' appears to be a numeric ID"
            ));
        }

        // UUID 参数 → UUID_SWAP
        if (isUuidParam(paramName) && isUuidValue(paramValue)) {
            result.add(createSupplementStrategy(
                    AttackType.IDOR, paramName,
                    VerificationTechnique.UUID_SWAP,
                    StrategyType.UUID_SWAP,
                    "IDOR supplement: parameter '" + paramName + "' appears to be a UUID"
            ));
        }

        return result;
    }

    /**
     * AUTH 补充：根据 Authorization Header 存在性推断技术。
     */
    private List<TestStrategy> supplementAuth(String paramName, String paramValue) {
        // Auth 类型的参数通常不是具体参数名，而是检测 HTTP Header
        // 这里按参数名判断
        if (paramName == null) return List.of();

        String lower = paramName.toLowerCase();
        if (lower.contains("authorization") || lower.contains("auth")
                || lower.contains("token") || lower.contains("jwt")) {
            return List.of(createSupplementStrategy(
                    AttackType.AUTH, paramName,
                    VerificationTechnique.REMOVE_TOKEN,
                    StrategyType.REMOVE_TOKEN,
                    "AUTH supplement: removing token from parameter '" + paramName + "'"
            ));
        }

        return List.of();
    }

    /**
     * SSRF 补充：根据参数名推断技术。
     */
    private List<TestStrategy> supplementSsrf(String paramName, String paramValue) {
        String lower = paramName != null ? paramName.toLowerCase() : "";
        if (lower.contains("url") || lower.contains("callback") || lower.contains("webhook")
                || lower.contains("redirect") || lower.contains("image")
                || lower.contains("link") || lower.contains("uri")) {
            return List.of(createSupplementStrategy(
                    AttackType.SSRF, paramName,
                    VerificationTechnique.LOCALHOST_PROBE,
                    StrategyType.LOCALHOST_PROBE,
                    "SSRF supplement: parameter '" + paramName + "' may accept URLs"
            ));
        }
        return List.of();
    }

    // ---------- Helper Methods ----------

    private TestStrategy createSupplementStrategy(AttackType attackType, String paramName,
                                                   VerificationTechnique technique,
                                                   StrategyType strategyType,
                                                   String reasoning) {
        return new TestStrategy(
                attackType,
                paramName,
                technique,
                List.of(strategyType),
                DEFAULT_CONFIDENCE,
                reasoning
        );
    }

    private static boolean isNumericParam(String paramName) {
        if (paramName == null) return false;
        String lower = paramName.toLowerCase();
        return lower.endsWith("id") || lower.endsWith("uid") || lower.endsWith("no")
                || lower.endsWith("num") || lower.equals("id")
                || lower.contains("id_") || lower.contains("_id");
    }

    private static boolean isNumericValue(String value) {
        if (value == null || value.isEmpty()) return false;
        try {
            Long.parseLong(value.trim());
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static boolean isUuidParam(String paramName) {
        if (paramName == null) return false;
        String lower = paramName.toLowerCase();
        return lower.contains("uuid") || lower.contains("guid")
                || (lower.contains("token") && !lower.contains("access"));
    }

    private static boolean isUuidValue(String value) {
        if (value == null || value.isEmpty()) return false;
        // 简单 UUID 格式检测: 8-4-4-4-12 hex digits
        return value.matches("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    }
}
