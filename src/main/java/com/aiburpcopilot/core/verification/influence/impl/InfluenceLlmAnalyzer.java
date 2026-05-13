package com.aiburpcopilot.core.verification.influence.impl;

import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.influence.IInfluenceLlmAnalyzer;
import com.aiburpcopilot.core.verification.influence.InfluenceLlmDecision;
import com.aiburpcopilot.core.verification.model.DiffResult;
import com.aiburpcopilot.core.verification.model.ParameterProfile;
import com.aiburpcopilot.utils.JsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class InfluenceLlmAnalyzer implements IInfluenceLlmAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(InfluenceLlmAnalyzer.class);
    private static final int TIMEOUT_SECONDS = 45;

    private final IAIProvider aiProvider;

    public InfluenceLlmAnalyzer(IAIProvider aiProvider) {
        this.aiProvider = aiProvider;
    }

    @Override
    public InfluenceLlmDecision analyze(AttackType attackType,
                                        String parameterName,
                                        String mutationValue,
                                        ParameterProfile profile,
                                        DiffResult diffResult,
                                        double deterministicScore) {
        if (aiProvider == null || !aiProvider.isAvailable() || diffResult == null) {
            return InfluenceLlmDecision.unavailable();
        }
        try {
            String response = aiProvider.analyzeDiff(buildPrompt(
                            attackType, parameterName, mutationValue,
                            profile, diffResult, deterministicScore))
                    .get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            return parseDecision(response);
        } catch (Exception e) {
            log.warn("Influence LLM analysis unavailable for param='{}': {}",
                    parameterName, e.getMessage());
            return InfluenceLlmDecision.unavailable();
        }
    }

    private String buildPrompt(AttackType attackType,
                               String parameterName,
                               String mutationValue,
                               ParameterProfile profile,
                               DiffResult diff,
                               double deterministicScore) {
        return "请判断一次参数影响性验证是否说明该参数会影响服务端响应。\n"
                + "你只能基于规则引擎提取出的差异字段、差异摘要和差异片段判断；不要生成 payload，不要建议发包。\n"
                + "如果差异只是时间戳、随机数、token、traceId、广告、统计字段、缓存噪声或无关模板变化，应判定 influential=false。\n"
                + "如果差异体现业务状态、权限结果、数据集合、错误状态、结构字段、查询结果、页面关键内容变化，应判定 influential=true。\n"
                + "返回严格 JSON：{\"influential\":true/false,\"confidence\":0.0-1.0,\"reasoning\":\"中文简短理由\"}\n\n"
                + "attackType: " + attackType + "\n"
                + "parameterName: " + parameterName + "\n"
                + "parameterType: " + (profile != null ? profile.getDetectedType() : "UNKNOWN") + "\n"
                + "mutationValue: " + summarize(mutationValue, 120) + "\n"
                + "deterministicScore: " + String.format("%.3f", deterministicScore) + "\n"
                + "similarity: " + String.format("%.3f", diff.getSimilarity()) + "\n"
                + "statusChanged: " + diff.isStatusChanged() + "\n"
                + "lengthChanged: " + diff.isLengthChanged() + "\n"
                + "structureChanged: " + diff.isStructureChanged() + "\n"
                + "keywordChanged: " + diff.isKeywordChanged() + "\n"
                + "stableChangeCount: " + diff.getStableChangeCount() + "\n"
                + "noiseChangeCount: " + diff.getNoiseChangeCount() + "\n"
                + "changedPaths: " + limitList(diff.getChangedPaths(), 16) + "\n"
                + "noisePaths: " + limitList(diff.getNoisePaths(), 16) + "\n"
                + "diffSummary: " + limitList(diff.getDiffSummary(), 16) + "\n"
                + "diffSnippets: " + limitList(diff.getDiffSnippets(), 10) + "\n";
    }

    @SuppressWarnings("unchecked")
    private InfluenceLlmDecision parseDecision(String raw) {
        if (raw == null || raw.isBlank()) {
            return InfluenceLlmDecision.unavailable();
        }
        Map<String, Object> map = JsonUtil.fromJsonSafe(extractJson(raw), Map.class);
        if (map == null) {
            return InfluenceLlmDecision.unavailable();
        }
        Object influentialValue = map.containsKey("influential")
                ? map.get("influential")
                : map.get("matched");
        boolean influential = influentialValue instanceof Boolean bool
                ? bool
                : Boolean.parseBoolean(String.valueOf(influentialValue));

        double confidence = 0.0;
        Object confidenceValue = map.get("confidence");
        if (confidenceValue instanceof Number number) {
            confidence = number.doubleValue();
        } else if (confidenceValue != null) {
            try {
                confidence = Double.parseDouble(String.valueOf(confidenceValue));
            } catch (NumberFormatException ignored) {
                confidence = 0.0;
            }
        }
        String reasoning = String.valueOf(map.getOrDefault("reasoning", "LLM 未返回明确理由"));
        return new InfluenceLlmDecision(true, influential,
                Math.max(0.0, Math.min(1.0, confidence)), reasoning);
    }

    private String extractJson(String raw) {
        String cleaned = raw.trim();
        int start = cleaned.indexOf('{');
        int end = cleaned.lastIndexOf('}');
        if (start >= 0 && end > start) {
            return cleaned.substring(start, end + 1);
        }
        return cleaned;
    }

    private List<String> limitList(List<String> values, int max) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        return values.stream()
                .limit(max)
                .map(value -> summarize(value, 180))
                .toList();
    }

    private String summarize(String value, int maxLength) {
        if (value == null) {
            return "";
        }
        String normalized = value.replaceAll("\\s+", " ").trim();
        return normalized.length() <= maxLength
                ? normalized
                : normalized.substring(0, Math.max(0, maxLength - 3)) + "...";
    }
}
