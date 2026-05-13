package com.aiburpcopilot.core.verification.influence.impl;

import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.ParameterContext;
import com.aiburpcopilot.core.verification.influence.IParameterRoleAnalyzer;
import com.aiburpcopilot.core.verification.influence.ParameterRole;
import com.aiburpcopilot.core.verification.model.CandidateParameter;
import com.aiburpcopilot.core.verification.model.ParameterProfile;
import com.aiburpcopilot.utils.JsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class ParameterRoleLlmAnalyzer implements IParameterRoleAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(ParameterRoleLlmAnalyzer.class);
    private static final int TIMEOUT_SECONDS = 30;

    private final IAIProvider aiProvider;

    public ParameterRoleLlmAnalyzer(IAIProvider aiProvider) {
        this.aiProvider = aiProvider;
    }

    @Override
    public ParameterRole analyze(HTTPContext context,
                                 CandidateParameter candidate,
                                 ParameterProfile profile) {
        if (aiProvider == null || !aiProvider.isAvailable()) {
            return ParameterRole.unavailable();
        }
        try {
            String response = aiProvider.analyzeDiff(buildPrompt(context, candidate, profile))
                    .get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            return parse(response);
        } catch (Exception e) {
            log.warn("Parameter role LLM analysis unavailable for param='{}': {}",
                    candidate != null ? candidate.getParameterName() : "-", e.getMessage());
            return ParameterRole.unavailable();
        }
    }

    private String buildPrompt(HTTPContext context,
                               CandidateParameter candidate,
                               ParameterProfile profile) {
        String parameterName = candidate != null ? candidate.getParameterName() : "";
        String originalValue = profile != null ? profile.getOriginalValue() : "";
        return "你是参数业务作用分析器。请只分析参数可能在服务端业务中的作用，不判断漏洞是否存在，不生成攻击 payload。\n"
                + "目标：判断这个参数是否可能参与服务端业务语义，并给出最小化影响性探测建议。\n"
                + "可选 role：OBJECT_IDENTIFIER, CREDENTIAL, AUTH_CONTEXT, FILTER_OR_SEARCH, PAGINATION, STATE_OR_FLAG, ROUTING_OR_ACTION, CONTENT, PRESENTATION, TRACKING_OR_NOISE, UNKNOWN。\n"
                + "recommendedMutations 只能从这些安全动作中选择：EMPTY, NULL_LITERAL, INCREMENT, DECREMENT, FLIP_BOOLEAN, APPEND_MARKER, CHANGE_TEXT。\n"
                + "如果参数像账号、密码、验证码、token、id、状态、查询条件、分页、业务动作，即使错误结果相同，也可能是业务相关。\n"
                + "返回严格 JSON：{\"role\":\"...\",\"likelyBusinessRelevant\":true/false,\"confidence\":0.0-1.0,\"recommendedMutations\":[\"...\"],\"reasoning\":\"中文简短理由\"}\n\n"
                + "HTTP summary:\n" + summarizeHttp(context)
                + "\nTarget parameter:\n"
                + "name: " + parameterName + "\n"
                + "sampleValue: " + summarize(originalValue, 120) + "\n"
                + "detectedType: " + (profile != null ? profile.getDetectedType() : "UNKNOWN") + "\n"
                + "candidateAttackType: " + (candidate != null ? candidate.getAttackType() : "UNKNOWN") + "\n";
    }

    private String summarizeHttp(HTTPContext context) {
        if (context == null) {
            return "N/A\n";
        }
        StringBuilder builder = new StringBuilder();
        builder.append("method: ").append(context.getMethod()).append("\n");
        builder.append("path: ").append(context.getPath()).append("\n");
        builder.append("contentType: ").append(context.getContentType()).append("\n");
        builder.append("responseContentType: ").append(context.getResponseContentType()).append("\n");
        if (context.getParameters() != null && !context.getParameters().isEmpty()) {
            builder.append("parameters:\n");
            for (ParameterContext parameter : context.getParameters()) {
                builder.append("- ")
                        .append(parameter.getName())
                        .append(" type=")
                        .append(parameter.getType())
                        .append(" sample=")
                        .append(summarize(parameter.getValue(), 80))
                        .append("\n");
            }
        }
        return builder.toString();
    }

    @SuppressWarnings("unchecked")
    private ParameterRole parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return ParameterRole.unavailable();
        }
        Map<String, Object> map = JsonUtil.fromJsonSafe(extractJson(raw), Map.class);
        if (map == null) {
            return ParameterRole.unavailable();
        }
        String role = String.valueOf(map.getOrDefault("role", "UNKNOWN"));
        boolean relevant = Boolean.parseBoolean(String.valueOf(
                map.getOrDefault("likelyBusinessRelevant", false)));
        double confidence = parseConfidence(map.get("confidence"));
        List<String> mutations = parseMutations(map.get("recommendedMutations"));
        String reasoning = String.valueOf(map.getOrDefault("reasoning", ""));
        return new ParameterRole(true, role, relevant, confidence, mutations, reasoning);
    }

    private double parseConfidence(Object value) {
        if (value instanceof Number number) {
            return Math.max(0.0, Math.min(1.0, number.doubleValue()));
        }
        if (value != null) {
            try {
                return Math.max(0.0, Math.min(1.0, Double.parseDouble(String.valueOf(value))));
            } catch (NumberFormatException ignored) {
                return 0.0;
            }
        }
        return 0.0;
    }

    private List<String> parseMutations(Object value) {
        if (!(value instanceof List<?> list)) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (Object item : list) {
            if (item != null) {
                result.add(String.valueOf(item));
            }
        }
        return result;
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
