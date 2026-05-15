package com.aiburpcopilot.core.verification.review;

import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.core.config.Timeouts;
import com.aiburpcopilot.core.verification.model.DiffResult;
import com.aiburpcopilot.core.verification.model.FinalVerdicts;
import com.aiburpcopilot.core.verification.model.ReviewStatus;
import com.aiburpcopilot.core.verification.model.VerificationResult;
import com.aiburpcopilot.utils.JsonUtil;

import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class FindingReviewService {

    private static final int MAX_TRANSCRIPT_LENGTH = 12000;

    private final IAIProvider aiProvider;
    private final IConfigService configService;

    public FindingReviewService(IAIProvider aiProvider) {
        this(aiProvider, null);
    }

    public FindingReviewService(IAIProvider aiProvider, IConfigService configService) {
        this.aiProvider = aiProvider;
        this.configService = configService;
    }

    public void review(VerificationResult result) {
        if (result == null) {
            return;
        }
        result.setReviewStatus(ReviewStatus.RUNNING);
        if (aiProvider == null || !aiProvider.isAvailable()) {
            result.setReviewStatus(ReviewStatus.LOCAL_ONLY);
            result.setLlmReview(buildLocalReview(result)
                    + "\n\n说明：AI Provider 未配置或不可用，本次仅执行本地二次研判。");
            result.setLlmMatched(null);
            FinalVerdicts.recompute(result);
            return;
        }

        try {
            String raw = aiProvider.analyzeDiff(buildPrompt(result))
                    .get(Timeouts.effectiveFindingReviewWaitMs(configService), TimeUnit.MILLISECONDS);
            applyLlmReview(result, raw);
        } catch (Exception e) {
            result.setReviewStatus(ReviewStatus.FAILED);
            result.setLlmMatched(null);
            result.setLlmReview(buildLocalReview(result)
                    + "\n\nLLM 二次研判执行失败：" + e.getClass().getSimpleName()
                    + " - " + safe(e.getMessage()));
            FinalVerdicts.recompute(result);
        }
    }

    public String statusText(ReviewStatus status) {
        if (status == null) {
            return "未要求";
        }
        return switch (status) {
            case NOT_REQUIRED -> "未要求";
            case PENDING -> "待研判";
            case RUNNING -> "研判中";
            case PASSED -> "证据支持";
            case REJECTED -> "证据不足";
            case FAILED -> "研判失败";
            case LOCAL_ONLY -> "本地研判";
        };
    }

    private void applyLlmReview(VerificationResult result, String raw) {
        Map<String, Object> map = JsonUtil.fromJsonSafe(extractJson(raw), Map.class);
        if (map == null || map.isEmpty()) {
            result.setReviewStatus(ReviewStatus.FAILED);
            result.setLlmMatched(null);
            result.setLlmReview("LLM 二次研判结果：\n" + safe(raw)
                    + "\n\n说明：未解析到结构化 JSON，已降级为本地结论，请人工复核。");
            FinalVerdicts.recompute(result);
            return;
        }

        boolean supported = asBoolean(map.get("supported"));
        double confidence = asDouble(map.get("confidence"), -1.0);
        result.setLlmMatched(supported);
        result.setReviewStatus(supported ? ReviewStatus.PASSED : ReviewStatus.REJECTED);
        if (!supported) {
            result.setConfidence(0.0);
            result.setRiskLevel(com.aiburpcopilot.core.context.RiskLevel.INFO);
            result.setRejectReason("LLM review rejected the finding evidence.");
        } else if (confidence >= 0.0) {
            result.setConfidence(Math.max(result.getConfidence(), confidence));
            result.setRejectReason(null);
        }
        StringBuilder text = new StringBuilder();
        text.append("LLM 漏洞级二次研判：")
                .append(supported ? "证据支持" : "证据不足");
        if (confidence >= 0.0) {
            text.append("，置信度 ").append(String.format("%.2f", confidence));
        }
        text.append("\n\n结论：").append(safe(map.get("conclusion")));
        text.append("\n\n理由：").append(safe(map.get("reasoning")));
        appendList(text, "支持证据", map.get("supportingEvidence"));
        appendList(text, "反证/不足", map.get("counterEvidence"));
        appendList(text, "人工复核点", map.get("manualReviewPoints"));
        text.append("\n\n说明：LLM 仅复核证据是否充分，不直接决定漏洞成立。");
        result.setLlmReview(text.toString());
        FinalVerdicts.recompute(result);
    }

    private String buildPrompt(VerificationResult result) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("你是漏洞验证证据复核助手。请只基于给定请求、响应、Diff、规则证据判断证据是否支持漏洞成立。\n")
                .append("你不能自由发挥，不能假设不存在于证据中的事实，不能直接控制发包。\n")
                .append("普通参数类型校验错误、仅 payload 被原样反射、通用成功/失败提示、状态码变化本身，都不能单独作为漏洞成立依据。\n")
                .append("如果证据不足，请明确指出需要人工复核什么。\n")
                .append("必须返回 JSON，不要 Markdown。格式：\n")
                .append("{\"supported\":true,\"confidence\":0.0,\"conclusion\":\"...\",\"reasoning\":\"...\",")
                .append("\"supportingEvidence\":[\"...\"],\"counterEvidence\":[\"...\"],\"manualReviewPoints\":[\"...\"]}\n\n");
        prompt.append("漏洞类型：").append(value(result.getAttackTypeName() != null ? result.getAttackTypeName() : result.getAttackType())).append("\n")
                .append("参数：").append(value(result.getParameter())).append("\n")
                .append("URL：").append(value(result.getUrl())).append("\n")
                .append("Payload：").append(value(result.getPayload())).append("\n")
                .append("阶段：").append(value(result.getPhase())).append("\n")
                .append("本地置信度：").append(String.format("%.2f", result.getConfidence())).append("\n")
                .append("风险等级：").append(value(result.getRiskLevel())).append("\n\n")
                .append("本地规则推理：\n").append(value(result.getReasoning())).append("\n\n")
                .append("Diff 摘要：\n").append(formatDiff(result.getDiffResult(), result.getResponseTimeMs())).append("\n\n");
        if (result.getExchangeTranscript() != null && !result.getExchangeTranscript().isBlank()) {
            prompt.append("完整验证过程：\n")
                    .append(limit(result.getExchangeTranscript(), MAX_TRANSCRIPT_LENGTH))
                    .append("\n");
        } else {
            prompt.append("完整验证过程：无\n");
        }
        return prompt.toString();
    }

    private String buildLocalReview(VerificationResult result) {
        DiffResult diff = result.getDiffResult();
        StringBuilder text = new StringBuilder();
        text.append("本地二次研判：");
        if (result.getConfidence() >= 0.7) {
            text.append("本地验证置信度较高，但仍建议人工复核请求/响应证据后确认。");
        } else if (result.getConfidence() >= 0.4) {
            text.append("存在一定证据，但需要结合业务语义人工确认。");
        } else {
            text.append("证据偏弱，不建议直接作为有效漏洞。");
        }
        if (diff != null) {
            text.append("\n稳定差异=").append(diff.getStableChangeCount())
                    .append("，噪声差异=").append(diff.getNoiseChangeCount())
                    .append("，显著=").append(diff.isSignificant() ? "是" : "否");
        }
        return text.toString();
    }

    private String formatDiff(DiffResult diff, long responseTimeMs) {
        if (diff == null) {
            return "未执行差异分析。可能是请求超时、重放失败，或没有捕获到原始响应。";
        }
        StringBuilder text = new StringBuilder();
        text.append("状态码：").append(diff.getOriginalStatus()).append(" -> ").append(diff.getMutatedStatus())
                .append(diff.isStatusChanged() ? " [变化]" : " [未变化]").append("\n");
        text.append("响应长度：").append(diff.getOriginalLength()).append(" -> ")
                .append(diff.getMutatedLength()).append(" bytes")
                .append(diff.isLengthChanged() ? " [变化]" : " [未变化]").append("\n");
        if (responseTimeMs > 0) {
            text.append("响应耗时：").append(responseTimeMs).append(" ms\n");
        }
        text.append("关键词变化：")
                .append(diff.isKeywordChanged() ? diff.getMatchedKeywords() : "未发现明显关键词变化").append("\n");
        text.append("稳定差异数：").append(diff.getStableChangeCount()).append("\n");
        if (!diff.getChangedPaths().isEmpty()) {
            text.append("稳定变化字段：").append(diff.getChangedPaths()).append("\n");
        }
        text.append("动态噪声数：").append(diff.getNoiseChangeCount()).append("\n");
        if (!diff.getDiffSnippets().isEmpty()) {
            text.append("不同内容片段：").append(diff.getDiffSnippets()).append("\n");
        }
        text.append("相似度：").append(String.format("%.2f", diff.getSimilarity())).append("\n");
        text.append("显著差异：").append(diff.isSignificant() ? "是" : "否");
        return text.toString();
    }

    private void appendList(StringBuilder text, String title, Object value) {
        text.append("\n\n").append(title).append("：");
        if (value instanceof List<?> list && !list.isEmpty()) {
            for (Object item : list) {
                text.append("\n- ").append(safe(item));
            }
        } else {
            text.append("-");
        }
    }

    private String extractJson(String raw) {
        if (raw == null) {
            return "";
        }
        int start = raw.indexOf('{');
        int end = raw.lastIndexOf('}');
        if (start >= 0 && end > start) {
            return raw.substring(start, end + 1);
        }
        return raw;
    }

    private boolean asBoolean(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        return value != null && Boolean.parseBoolean(String.valueOf(value));
    }

    private double asDouble(Object value, double defaultValue) {
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        try {
            return value != null ? Double.parseDouble(String.valueOf(value)) : defaultValue;
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private String limit(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength) + "\n...内容过长，已截断...";
    }

    private String value(Object value) {
        return value != null ? String.valueOf(value) : "-";
    }

    private String safe(Object value) {
        return value != null ? String.valueOf(value) : "-";
    }
}
