package com.aiburpcopilot.burp.ui;

import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.core.verification.model.DiffResult;
import com.aiburpcopilot.core.verification.model.VerificationResult;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class VerificationUiSupport {

    static final String PHASE_INFLUENCE = "Influence Gate";
    static final String PHASE_PAYLOAD = "Payload Verification";

    private VerificationUiSupport() {
    }

    static List<ResultRow> collectRows(IHistoryService historyService) {
        Map<String, ResultRow> dedup = new LinkedHashMap<>();
        for (HistoryEntry entry : historyService.getAll()) {
            if (entry.getVerificationResults() == null) {
                continue;
            }
            for (VerificationResult result : entry.getVerificationResults()) {
                if (result.getUrl() == null && entry.getUrl() != null) {
                    result.setUrl(entry.getUrl());
                }
                dedup.put(rowKey(entry, result), new ResultRow(entry, result));
            }
        }
        return new ArrayList<>(dedup.values());
    }

    static String rowKey(HistoryEntry entry, VerificationResult result) {
        return nullToDash(entry.getRequestId())
                + "|" + nullToDash(result.getPhase())
                + "|" + nullToDash(result.getAttackType() != null ? result.getAttackType().name() : null)
                + "|" + nullToDash(result.getParameter())
                + "|" + nullToDash(result.getStrategyType() != null ? result.getStrategyType().name() : null)
                + "|" + nullToDash(result.getPayload());
    }

    static boolean isInfluence(VerificationResult result) {
        return result != null && PHASE_INFLUENCE.equalsIgnoreCase(result.getPhase());
    }

    static boolean isPayloadVerification(VerificationResult result) {
        return result != null && !isInfluence(result);
    }

    static String formatDiffChinese(DiffResult diff, long responseTimeMs) {
        if (diff == null) {
            return "未执行差异分析。\n可能是请求超时、重放失败，或没有捕获到原始响应。";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("=== 差异分析摘要 ===\n\n");
        sb.append("状态码：").append(diff.getOriginalStatus())
                .append(" -> ").append(diff.getMutatedStatus())
                .append(diff.isStatusChanged() ? "  [已变化]" : "  [未变化]").append("\n");
        sb.append("响应长度：").append(diff.getOriginalLength())
                .append(" -> ").append(diff.getMutatedLength()).append(" bytes")
                .append(diff.isLengthChanged() ? "  [已变化]" : "  [未变化]").append("\n");
        if (responseTimeMs > 0) {
            sb.append("响应耗时：").append(responseTimeMs).append(" ms\n");
        }
        sb.append("关键字：")
                .append(diff.isKeywordChanged() ? "发现 " + diff.getMatchedKeywords() : "未发现明显关键字变化")
                .append("\n");
        sb.append("结构变化：").append(diff.isStructureChanged() ? "有" : "无").append("\n");
        sb.append("稳定差异数：").append(diff.getStableChangeCount()).append("\n");
        if (!diff.getChangedPaths().isEmpty()) {
            sb.append("稳定变化字段：\n");
            for (String path : diff.getChangedPaths()) {
                sb.append("  - ").append(path).append("\n");
            }
        }
        sb.append("动态噪声数：").append(diff.getNoiseChangeCount()).append("\n");
        if (!diff.getNoisePaths().isEmpty()) {
            sb.append("疑似动态噪声字段：\n");
            for (String path : diff.getNoisePaths()) {
                sb.append("  - ").append(path).append("\n");
            }
        }
        if (!diff.getDiffSnippets().isEmpty()) {
            sb.append("\n不同内容片段：\n");
            for (String snippet : diff.getDiffSnippets()) {
                sb.append("  - ").append(snippet).append("\n");
            }
        }
        if (!diff.getDiffSummary().isEmpty()) {
            sb.append("\n可供二次研判的确定性差异：\n");
            for (String line : diff.getDiffSummary()) {
                sb.append("  - ").append(toChineseLine(line)).append("\n");
            }
        }
        sb.append("相似度：").append(String.format("%.2f", diff.getSimilarity())).append("\n");
        sb.append("是否显著：").append(diff.isSignificant() ? "是" : "否");
        return sb.toString();
    }

    static String buildLocalReview(VerificationResult result) {
        if (result == null) {
            return "无结果可研判。";
        }
        DiffResult diff = result.getDiffResult();
        StringBuilder sb = new StringBuilder();
        sb.append("本地二次研判：");
        if (result.getConfidence() >= 0.7) {
            sb.append("置信度较高，建议人工复核请求/响应证据后确认。");
        } else if (result.getConfidence() >= 0.4) {
            sb.append("存在一定证据，但建议结合业务语义人工确认。");
        } else {
            sb.append("证据较弱，不建议直接标记为有效漏洞。");
        }
        if (diff != null) {
            sb.append("\n稳定差异=").append(diff.getStableChangeCount())
                    .append("，噪声差异=").append(diff.getNoiseChangeCount())
                    .append("，显著=").append(diff.isSignificant() ? "是" : "否");
        }
        return sb.toString();
    }

    static String buildFindingReviewPrompt(VerificationResult result) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("你是漏洞验证复核助手。请根据本地验证证据、请求响应过程、Diff 摘要和规则推理，判断证据是否足以支持漏洞成立。\n")
                .append("注意：你不能自由发挥，只能基于给定证据。普通参数校验错误、仅反射 payload、通用成功/失败提示都不能直接判定为漏洞。\n")
                .append("请用中文输出：结论、置信度、支持证据、反证/不足、建议人工复核点。\n\n");
        if (result == null) {
            return prompt.append("没有验证结果。").toString();
        }
        prompt.append("漏洞类型：").append(nullToDash(result.getAttackType() != null ? result.getAttackType().name() : null)).append("\n")
                .append("参数：").append(nullToDash(result.getParameter())).append("\n")
                .append("URL：").append(nullToDash(result.getUrl())).append("\n")
                .append("Payload：").append(nullToDash(result.getPayload())).append("\n")
                .append("阶段：").append(nullToDash(result.getPhase())).append("\n")
                .append("本地置信度：").append(String.format("%.2f", result.getConfidence())).append("\n")
                .append("风险等级：").append(nullToDash(result.getRiskLevel())).append("\n\n")
                .append("本地规则推理：\n").append(nullToDash(result.getReasoning())).append("\n\n")
                .append("Diff 摘要：\n").append(formatDiffChinese(result.getDiffResult(), result.getResponseTimeMs())).append("\n\n");
        if (result.getExchangeTranscript() != null && !result.getExchangeTranscript().isBlank()) {
            prompt.append("完整验证过程：\n")
                    .append(limit(result.getExchangeTranscript(), 12000))
                    .append("\n");
        } else {
            prompt.append("完整验证过程：无。\n");
        }
        return prompt.toString();
    }

    private static String toChineseLine(String line) {
        return line.replace("HTTP status changed", "HTTP 状态码变化")
                .replace("Body length changed", "响应体长度变化")
                .replace("Keyword changes", "关键字变化")
                .replace("Response time changed", "响应耗时变化")
                .replace("One response is missing", "其中一个响应缺失");
    }

    private static String limit(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength) + "\n...内容过长，已截断...";
    }

    private static String nullToDash(Object value) {
        return value != null ? String.valueOf(value) : "-";
    }

    record ResultRow(HistoryEntry entry, VerificationResult result) {
    }
}
