package com.aiburpcopilot.burp.ui;

import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.core.verification.model.DiffResult;
import com.aiburpcopilot.core.verification.model.FinalVerdicts;
import com.aiburpcopilot.core.verification.model.VerificationResult;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class VerificationUiSupport {

    static final String PHASE_INFLUENCE = "Influence Gate";
    static final String PHASE_PAYLOAD = "Payload Verification";
    static final String PHASE_FINDING = "Finding";

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
        if (result != null && result.getDedupKey() != null && !result.getDedupKey().isBlank()) {
            return nullToDash(entry.getRequestId()) + "|" + result.getPhase() + "|" + result.getDedupKey();
        }
        return nullToDash(entry.getRequestId())
                + "|" + nullToDash(result.getPhase())
                + "|" + nullToDash(result.getAttackTypeName())
                + "|" + nullToDash(result.getParameter())
                + "|" + nullToDash(result.getStrategyName())
                + "|" + nullToDash(result.getPayload());
    }

    static String workflowKey(HistoryEntry entry, VerificationResult result) {
        if (result != null && result.getTraceId() != null && !result.getTraceId().isBlank()) {
            return nullToDash(entry.getRequestId()) + "|" + result.getTraceId();
        }
        if (result != null && result.getCandidateId() != null && !result.getCandidateId().isBlank()) {
            return nullToDash(entry.getRequestId()) + "|" + result.getCandidateId();
        }
        return nullToDash(entry.getRequestId())
                + "|" + nullToDash(result.getAttackTypeName())
                + "|" + nullToDash(result.getParameter());
    }

    static boolean isInfluence(VerificationResult result) {
        return result != null && PHASE_INFLUENCE.equalsIgnoreCase(result.getPhase());
    }

    static boolean isPayloadVerification(VerificationResult result) {
        return result != null && !isInfluence(result);
    }

    static boolean isAggregatedFinding(VerificationResult result) {
        return result != null && PHASE_FINDING.equalsIgnoreCase(result.getPhase());
    }

    static boolean isEffectiveFinding(VerificationResult result) {
        return result != null
                && isPayloadVerification(result)
                && (isAggregatedFinding(result) || result.getManualConfirmedOverride() != null)
                && FinalVerdicts.isEffective(result);
    }

    static boolean isBetterWorkflowRepresentative(VerificationResult candidate, VerificationResult current) {
        if (candidate == null) {
            return false;
        }
        if (current == null) {
            return true;
        }
        boolean candidateFinding = isAggregatedFinding(candidate);
        boolean currentFinding = isAggregatedFinding(current);
        if (candidateFinding != currentFinding) {
            return candidateFinding;
        }
        boolean candidateEffective = FinalVerdicts.isEffective(candidate);
        boolean currentEffective = FinalVerdicts.isEffective(current);
        if (candidateEffective != currentEffective) {
            return candidateEffective;
        }
        int candidateEvidence = candidate.getEvidences() != null ? candidate.getEvidences().size() : 0;
        int currentEvidence = current.getEvidences() != null ? current.getEvidences().size() : 0;
        if (candidateEvidence != currentEvidence) {
            return candidateEvidence > currentEvidence;
        }
        int candidateRecords = candidate.getExchangeRecords() != null ? candidate.getExchangeRecords().size() : 0;
        int currentRecords = current.getExchangeRecords() != null ? current.getExchangeRecords().size() : 0;
        if (candidateRecords != currentRecords) {
            return candidateRecords > currentRecords;
        }
        return candidate.getConfidence() > current.getConfidence();
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

    private static String toChineseLine(String line) {
        return line.replace("HTTP status changed", "HTTP 状态码变化")
                .replace("Body length changed", "响应体长度变化")
                .replace("Keyword changes", "关键字变化")
                .replace("Response time changed", "响应耗时变化")
                .replace("One response is missing", "其中一个响应缺失");
    }

    private static String nullToDash(Object value) {
        return value != null ? String.valueOf(value) : "-";
    }

    record ResultRow(HistoryEntry entry, VerificationResult result) {
    }
}
