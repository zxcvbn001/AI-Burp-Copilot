package com.aiburpcopilot.core.verification.probe;

import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.influence.IInfluenceDiffEngine;
import com.aiburpcopilot.core.verification.model.DiffResult;
import com.aiburpcopilot.core.verification.model.Evidence;
import com.aiburpcopilot.utils.JsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class ProbeOracleEngine {

    private static final Logger log = LoggerFactory.getLogger(ProbeOracleEngine.class);
    private static final int LLM_DIFF_TIMEOUT_SECONDS = 20;

    private final IInfluenceDiffEngine diffEngine;
    private final IAIProvider aiProvider;

    public ProbeOracleEngine(IInfluenceDiffEngine diffEngine) {
        this(diffEngine, null);
    }

    public ProbeOracleEngine(IInfluenceDiffEngine diffEngine, IAIProvider aiProvider) {
        this.diffEngine = diffEngine;
        this.aiProvider = aiProvider;
    }

    public OracleResult evaluate(ProbeDefinition probe,
                                 byte[] baselineResponse,
                                 long baselineDurationMs,
                                 List<ProbeExecution> executions) {
        String type = probe.getOracle() != null ? probe.getOracle().getType() : null;
        if (type == null || type.isBlank()) {
            type = "REFLECTION";
        }
        return switch (type.trim().toUpperCase()) {
            case "ERROR_KEYWORD", "ERROR_KEYWORD_OR_RECOVERY", "ERROR_RECOVERY" ->
                    evaluateErrorKeyword(probe, baselineResponse, executions);
            case "PAIR_DIFF" -> evaluatePairDiff(probe, baselineResponse, executions);
            case "TIME_DELAY" -> evaluateTimeDelay(probe, baselineDurationMs, executions);
            case "KEYWORD" -> evaluateKeyword(probe, baselineResponse, executions);
            case "REDIRECT_LOCATION" -> evaluateRedirectLocation(probe, baselineResponse, executions);
            case "EXPRESSION_EVALUATION" -> evaluateExpressionEvaluation(probe, baselineResponse, executions);
            case "BASELINE_DIFF" -> evaluateBaselineDiff(probe, baselineResponse, executions);
            case "BASELINE_SIMILAR" -> evaluateBaselineSimilar(probe, baselineResponse, executions);
            case "HTML_REFLECTION", "REFLECTION" ->
                    evaluateReflection(probe, baselineResponse, baselineDurationMs, executions);
            default -> evaluateReflection(probe, baselineResponse, baselineDurationMs, executions);
        };
    }

    private OracleResult evaluateReflection(ProbeDefinition probe,
                                            byte[] baselineResponse,
                                            long baselineDurationMs,
                                            List<ProbeExecution> executions) {
        OracleResult result = new OracleResult();
        OracleDefinition oracle = probe.getOracle();
        for (ProbeExecution execution : executions) {
            DiffResult diff = diff(baselineResponse, execution.getResponseBytes(),
                    baselineDurationMs, execution.getDurationMs());
            if (result.getDiffResult() == null) {
                result.setDiffResult(diff);
            }
            String responseText = text(execution.getResponseBytes());
            if (responseText.isEmpty()) {
                continue;
            }

            List<String> requiredMarkers = new ArrayList<>(oracle.getRequireMarkers());
            for (ProbePayload payload : probe.getPayloads()) {
                if (payload.getValue() != null && payload.getValue().equals(execution.getValue())) {
                    requiredMarkers.addAll(payload.getMarkers());
                    if (requiredMarkers.isEmpty() || oracle.isRequireExactPayload()) {
                        requiredMarkers.add(payload.getValue());
                    }
                    break;
                }
            }
            if (requiredMarkers.isEmpty()) {
                requiredMarkers.add(execution.getValue());
            }

            List<String> matchedMarkers = requiredMarkers.stream()
                    .filter(marker -> marker != null && !marker.isBlank())
                    .filter(responseText::contains)
                    .toList();
            if (!matchedMarkers.isEmpty()) {
                boolean unescapedOk = !oracle.isRequireUnescaped()
                        || containsLikelyHtmlReflection(responseText, execution.getValue());
                if (!unescapedOk) {
                    continue;
                }
                double confidence = oracle.getMinConfidence();
                if (matchedMarkers.contains(execution.getValue())) {
                    confidence = Math.min(0.95, confidence + 0.08);
                }
                result.setMatched(true);
                result.setConfidence(Math.max(result.getConfidence(), confidence));
                result.setDiffResult(diff);
                result.setReasoning("响应中反射了探测标记：" + matchedMarkers);
                Evidence evidence = Evidence.general(
                        "响应中反射了探测标记：" + matchedMarkers,
                        "REFLECTION",
                        confidence);
                evidence.setMutatedRequest(execution.getRequestBytes());
                evidence.setOriginalResponse(baselineResponse);
                evidence.setMutatedResponse(execution.getResponseBytes());
                result.addEvidence(evidence);
            }
        }
        if (result.getReasoning() == null) {
            result.setReasoning("未发现稳定反射证据");
        }
        if (probe.isRequiresLlmReview() && result.getDiffResult() != null) {
            boolean localMatched = result.isMatched();
            LlmDiffDecision llmDecision = judgeDiffWithLlm(
                    probe, "HTML_REFLECTION", result.getDiffResult(), executions,
                    localMatched, result.getReasoning());
            result.setLlmReview(llmDecision.review);
            result.setLlmAvailable(llmDecision.available);
            if (llmDecision.available) {
                result.setMatched(localMatched && llmDecision.matched);
                result.setConfidence(result.isMatched()
                        ? Math.min(result.getConfidence(), llmDecision.confidence)
                        : 0.0);
                result.setReasoning("LLM 反射差异研判"
                        + (result.isMatched() ? "确认：" : "未确认：")
                        + llmDecision.reasoning);
            }
        }
        return result;
    }

    private OracleResult evaluateErrorKeyword(ProbeDefinition probe,
                                              byte[] baselineResponse,
                                              List<ProbeExecution> executions) {
        OracleResult result = new OracleResult();
        OracleDefinition oracle = probe.getOracle();
        String baselineText = text(baselineResponse).toLowerCase();
        List<String> keywords = !oracle.getErrorKeywords().isEmpty()
                ? oracle.getErrorKeywords()
                : oracle.getKeywords();

        ProbeExecution trigger = executions.stream()
                .filter(e -> e.getRole() == ProbeRole.TRIGGER || e.getRole() == ProbeRole.SINGLE)
                .findFirst()
                .orElse(null);
        if (trigger == null) {
            result.setReasoning("未执行错误触发 payload");
            return result;
        }

        String triggerText = text(trigger.getResponseBytes()).toLowerCase();
        List<String> matched = keywords.stream()
                .filter(keyword -> keyword != null && !keyword.isBlank())
                .filter(keyword -> triggerText.contains(keyword.toLowerCase())
                        && !baselineText.contains(keyword.toLowerCase()))
                .toList();

        if (!matched.isEmpty()) {
            double confidence = oracle.getMinConfidence();
            ProbeExecution recovery = executions.stream()
                    .filter(e -> e.getRole() == ProbeRole.RECOVERY)
                    .findFirst()
                    .orElse(null);
            if (recovery != null && !containsAny(text(recovery.getResponseBytes()).toLowerCase(), matched)) {
                confidence = Math.min(0.95, confidence + 0.10);
            }
            result.setMatched(true);
            result.setConfidence(confidence);
            result.setReasoning("响应中出现新增错误关键词：" + matched);
            Evidence evidence = Evidence.general(result.getReasoning(), "ERROR_KEYWORD", confidence);
            evidence.setMutatedRequest(trigger.getRequestBytes());
            evidence.setMutatedResponse(trigger.getResponseBytes());
            result.addEvidence(evidence);
        } else {
            result.setReasoning("未发现新增错误关键词");
        }
        return result;
    }

    private OracleResult evaluateKeyword(ProbeDefinition probe,
                                         byte[] baselineResponse,
                                         List<ProbeExecution> executions) {
        OracleResult result = new OracleResult();
        OracleDefinition oracle = probe.getOracle();
        String baselineText = text(baselineResponse).toLowerCase();
        for (ProbeExecution execution : executions) {
            String responseText = text(execution.getResponseBytes()).toLowerCase();
            List<String> matched = oracle.getKeywords().stream()
                    .filter(keyword -> keyword != null && !keyword.isBlank())
                    .filter(keyword -> responseText.contains(keyword.toLowerCase())
                            && !baselineText.contains(keyword.toLowerCase()))
                    .toList();
            if (!matched.isEmpty()) {
                double confidence = oracle.getMinConfidence();
                result.setMatched(true);
                result.setConfidence(Math.max(result.getConfidence(), confidence));
                result.setReasoning("响应中出现新增关键词：" + matched);
                Evidence evidence = Evidence.general(result.getReasoning(), "KEYWORD", confidence);
                evidence.setMutatedRequest(execution.getRequestBytes());
                evidence.setMutatedResponse(execution.getResponseBytes());
                result.addEvidence(evidence);
            }
        }
        if (result.getReasoning() == null) {
            result.setReasoning("未发现新增关键词证据");
        }
        return result;
    }

    private OracleResult evaluateRedirectLocation(ProbeDefinition probe,
                                                  byte[] baselineResponse,
                                                  List<ProbeExecution> executions) {
        OracleResult result = new OracleResult();
        OracleDefinition oracle = probe.getOracle();
        String baselineLocation = extractHeader(text(baselineResponse), "location").toLowerCase();
        for (ProbeExecution execution : executions) {
            String responseText = text(execution.getResponseBytes());
            int statusCode = parseStatusCode(responseText);
            String location = extractHeader(responseText, "location");
            if (location == null || location.isBlank()) {
                continue;
            }
            String locationLower = location.toLowerCase();
            boolean statusLooksRedirect = statusCode >= 300 && statusCode < 400;
            List<String> markers = new ArrayList<>(oracle.getRequireMarkers());
            if (markers.isEmpty()) {
                markers.add(execution.getValue());
            }
            List<String> matchedMarkers = markers.stream()
                    .filter(marker -> marker != null && !marker.isBlank())
                    .filter(marker -> locationLower.contains(marker.toLowerCase()))
                    .toList();
            if (statusLooksRedirect && !matchedMarkers.isEmpty()
                    && !baselineLocation.equalsIgnoreCase(location)) {
                double confidence = Math.min(0.95, oracle.getMinConfidence() + 0.05);
                result.setMatched(true);
                result.setConfidence(Math.max(result.getConfidence(), confidence));
                result.setReasoning("Location 响应头跳转到可控标记：" + location);
                Evidence evidence = Evidence.general(result.getReasoning(), "REDIRECT_LOCATION", confidence);
                evidence.setMutatedRequest(execution.getRequestBytes());
                evidence.setOriginalResponse(baselineResponse);
                evidence.setMutatedResponse(execution.getResponseBytes());
                result.addEvidence(evidence);
            }
        }
        if (result.getReasoning() == null) {
            result.setReasoning("未发现可控 Location 重定向证据");
        }
        return result;
    }

    private OracleResult evaluateExpressionEvaluation(ProbeDefinition probe,
                                                      byte[] baselineResponse,
                                                      List<ProbeExecution> executions) {
        OracleResult result = new OracleResult();
        String baselineText = text(baselineResponse);
        for (ProbeExecution execution : executions) {
            String responseText = text(execution.getResponseBytes());
            if (responseText.isBlank()) {
                continue;
            }
            List<String> markers = markersForExecution(probe, execution);
            List<String> matchedMarkers = markers.stream()
                    .filter(marker -> marker != null && !marker.isBlank())
                    .filter(marker -> responseText.contains(marker) && !baselineText.contains(marker))
                    .toList();
            boolean rawExpressionReflected = execution.getValue() != null
                    && !execution.getValue().isBlank()
                    && responseText.contains(execution.getValue());
            if (!matchedMarkers.isEmpty() && !rawExpressionReflected) {
                double confidence = probe.getOracle().getMinConfidence();
                result.setMatched(true);
                result.setConfidence(Math.max(result.getConfidence(), confidence));
                result.setReasoning("模板表达式疑似被服务端求值，出现结果标记：" + matchedMarkers);
                Evidence evidence = Evidence.general(result.getReasoning(), "EXPRESSION_EVALUATION", confidence);
                evidence.setMutatedRequest(execution.getRequestBytes());
                evidence.setOriginalResponse(baselineResponse);
                evidence.setMutatedResponse(execution.getResponseBytes());
                result.addEvidence(evidence);
            }
        }
        if (result.getReasoning() == null) {
            result.setReasoning("未发现模板表达式求值证据");
        }
        return result;
    }

    private OracleResult evaluatePairDiff(ProbeDefinition probe,
                                          byte[] baselineResponse,
                                          List<ProbeExecution> executions) {
        OracleResult result = new OracleResult();
        ProbeExecution trueCase = executions.stream()
                .filter(e -> e.getRole() == ProbeRole.TRUE_CASE)
                .findFirst()
                .orElse(null);
        ProbeExecution falseCase = executions.stream()
                .filter(e -> e.getRole() == ProbeRole.FALSE_CASE)
                .findFirst()
                .orElse(null);
        if (trueCase == null || falseCase == null) {
            result.setReasoning("缺少 true/false 成对 payload 响应");
            return result;
        }

        double trueBaselineSimilarity = similarity(baselineResponse, trueCase.getResponseBytes());
        double trueFalseSimilarity = similarity(trueCase.getResponseBytes(), falseCase.getResponseBytes());
        DiffResult diff = diff(baselineResponse, falseCase.getResponseBytes(), 0, falseCase.getDurationMs());
        result.setDiffResult(diff);

        boolean deterministicMatched = trueBaselineSimilarity >= probe.getOracle().getMinSimilarityTrueBaseline()
                && trueFalseSimilarity <= probe.getOracle().getMaxSimilarityTrueFalse();
        String deterministicReasoning = "true/false 响应差异：true~baseline="
                + String.format("%.2f", trueBaselineSimilarity)
                + "，true~false=" + String.format("%.2f", trueFalseSimilarity);
            LlmDiffDecision llmDecision = judgeDiffWithLlm(
                    probe, "PAIR_DIFF", diff, executions, deterministicMatched, deterministicReasoning);
            result.setLlmReview(llmDecision.review);
            result.setLlmAvailable(llmDecision.available);
        boolean hasNegativeEvidence = !negativeEvidenceSignals(probe, executions).isEmpty();
        boolean matched = llmDecision.available ? llmDecision.matched : deterministicMatched;
        if (!llmDecision.available && hasNegativeEvidence) {
            matched = false;
        }
        if (matched) {
            double confidence = llmDecision.available
                    ? llmDecision.confidence
                    : probe.getOracle().getMinConfidence();
            if (!llmDecision.available && hasNegativeEvidence) {
                confidence = Math.min(confidence, 0.45);
            }
            result.setMatched(true);
            result.setConfidence(confidence);
            result.setReasoning((llmDecision.available ? "LLM 差异研判确认：" : "")
                    + (llmDecision.available ? llmDecision.reasoning : deterministicReasoning));
            Evidence evidence = Evidence.general(result.getReasoning(), "PAIR_DIFF", confidence);
            evidence.setMutatedRequest(falseCase.getRequestBytes());
            evidence.setOriginalResponse(trueCase.getResponseBytes());
            evidence.setMutatedResponse(falseCase.getResponseBytes());
            result.addEvidence(evidence);
        } else {
            result.setReasoning((llmDecision.available ? "LLM 差异研判未确认：" : "")
                    + (llmDecision.available ? llmDecision.reasoning : deterministicReasoning));
        }
        return result;
    }

    private OracleResult evaluateBaselineDiff(ProbeDefinition probe,
                                              byte[] baselineResponse,
                                              List<ProbeExecution> executions) {
        OracleResult result = new OracleResult();
        for (ProbeExecution execution : executions) {
            DiffResult diff = diff(baselineResponse, execution.getResponseBytes(), 0, execution.getDurationMs());
            result.setDiffResult(diff);
            double similarity = diff.getSimilarity();
            boolean deterministicMatched = similarity <= probe.getOracle().getMaxSimilarityTrueFalse();
            String deterministicReasoning = "变异响应与 baseline 差异：similarity="
                    + String.format("%.2f", similarity);
            LlmDiffDecision llmDecision = judgeDiffWithLlm(
                    probe, "BASELINE_DIFF", diff, List.of(execution),
                    deterministicMatched, deterministicReasoning);
            result.setLlmReview(llmDecision.review);
            result.setLlmAvailable(llmDecision.available);
            boolean hasNegativeEvidence = !negativeEvidenceSignals(probe, List.of(execution)).isEmpty();
            boolean matched = llmDecision.available ? llmDecision.matched : deterministicMatched;
            if (!llmDecision.available && hasNegativeEvidence) {
                matched = false;
            }
            if (matched) {
                double confidence = llmDecision.available
                        ? llmDecision.confidence
                        : probe.getOracle().getMinConfidence();
                if (!llmDecision.available && hasNegativeEvidence) {
                    confidence = Math.min(confidence, 0.45);
                }
                result.setMatched(true);
                result.setConfidence(Math.max(result.getConfidence(), confidence));
                result.setReasoning((llmDecision.available ? "LLM 差异研判确认：" : "")
                        + (llmDecision.available ? llmDecision.reasoning : deterministicReasoning));
                Evidence evidence = Evidence.general(result.getReasoning(), "BASELINE_DIFF", confidence);
                evidence.setMutatedRequest(execution.getRequestBytes());
                evidence.setOriginalResponse(baselineResponse);
                evidence.setMutatedResponse(execution.getResponseBytes());
                result.addEvidence(evidence);
                break;
            }
        }
        if (result.getReasoning() == null) {
            result.setReasoning("变异响应与 baseline 的差异不足以确认");
        }
        return result;
    }

    private OracleResult evaluateBaselineSimilar(ProbeDefinition probe,
                                                 byte[] baselineResponse,
                                                 List<ProbeExecution> executions) {
        OracleResult result = new OracleResult();
        for (ProbeExecution execution : executions) {
            DiffResult diff = diff(baselineResponse, execution.getResponseBytes(), 0, execution.getDurationMs());
            result.setDiffResult(diff);
            double similarity = diff.getSimilarity();
            boolean deterministicMatched = similarity >= probe.getOracle().getMinSimilarityTrueBaseline();
            String deterministicReasoning = "变异响应与 baseline 仍然接近：similarity="
                    + String.format("%.2f", similarity);
            LlmDiffDecision llmDecision = judgeDiffWithLlm(
                    probe, "BASELINE_SIMILAR", diff, List.of(execution),
                    deterministicMatched, deterministicReasoning);
            result.setLlmReview(llmDecision.review);
            result.setLlmAvailable(llmDecision.available);
            boolean matched = llmDecision.available ? llmDecision.matched : deterministicMatched;
            if (matched) {
                double confidence = llmDecision.available
                        ? llmDecision.confidence
                        : probe.getOracle().getMinConfidence();
                result.setMatched(true);
                result.setConfidence(Math.max(result.getConfidence(), confidence));
                result.setReasoning((llmDecision.available ? "LLM 差异研判确认：" : "")
                        + (llmDecision.available ? llmDecision.reasoning : deterministicReasoning));
                Evidence evidence = Evidence.general(result.getReasoning(), "BASELINE_SIMILAR", confidence);
                evidence.setMutatedRequest(execution.getRequestBytes());
                evidence.setOriginalResponse(baselineResponse);
                evidence.setMutatedResponse(execution.getResponseBytes());
                result.addEvidence(evidence);
                break;
            }
        }
        if (result.getReasoning() == null) {
            result.setReasoning("变异响应与 baseline 不够接近");
        }
        return result;
    }

    private OracleResult evaluateTimeDelay(ProbeDefinition probe,
                                           long baselineDurationMs,
                                           List<ProbeExecution> executions) {
        OracleResult result = new OracleResult();
        for (ProbeExecution execution : executions) {
            boolean delayed = execution.getDurationMs() >= probe.getOracle().getMinDelayMs()
                    && (baselineDurationMs <= 0
                    || execution.getDurationMs() >= baselineDurationMs * probe.getOracle().getBaselineMultiplier());
            if (delayed) {
                double confidence = probe.getOracle().getMinConfidence();
                result.setMatched(true);
                result.setConfidence(Math.max(result.getConfidence(), confidence));
                result.setReasoning("响应耗时达到延时阈值：" + execution.getDurationMs() + "ms");
                Evidence evidence = Evidence.general(result.getReasoning(), "TIME_DELAY", confidence);
                evidence.setMutatedRequest(execution.getRequestBytes());
                evidence.setMutatedResponse(execution.getResponseBytes());
                result.addEvidence(evidence);
            }
        }
        if (result.getReasoning() == null) {
            result.setReasoning("未发现稳定延时证据");
        }
        return result;
    }

    private List<String> negativeEvidenceSignals(ProbeDefinition probe, List<ProbeExecution> executions) {
        List<String> signals = new ArrayList<>();
        if (executions == null || executions.isEmpty()) {
            signals.add("No replay response was available for review.");
            return signals;
        }
        if (allExecutionsLookLikeClientValidationErrors(executions)) {
            signals.add("All mutated responses look like client-side request validation/parsing failures.");
        }
        if (probe != null && probe.getAttackType() == AttackType.SQLI
                && trueFalseOnlyReflectDifferentPayloads(executions)) {
            signals.add("SQLI true/false cases appear to return the same validation error pattern with only reflected input changed.");
        }
        return signals;
    }

    private List<String> positiveEvidenceSignals(ProbeDefinition probe,
                                                 String mode,
                                                 DiffResult diff,
                                                 boolean deterministicMatched,
                                                 String deterministicReasoning) {
        List<String> signals = new ArrayList<>();
        if (deterministicMatched) {
            signals.add("Local oracle matched: " + deterministicReasoning);
        }
        if (diff != null) {
            if (diff.isStatusChanged()) {
                signals.add("HTTP status changed: " + diff.getOriginalStatus() + " -> " + diff.getMutatedStatus());
            }
            if (diff.isStructureChanged()) {
                signals.add("Response structure changed.");
            }
            if (diff.isKeywordChanged()) {
                signals.add("Security keyword changed: " + diff.getMatchedKeywords());
            }
            if (diff.getStableChangeCount() > 0) {
                signals.add("Stable fields changed: " + limitList(diff.getChangedPaths(), 8));
            }
        }
        if (probe != null) {
            signals.add("Probe strategy: " + probe.getStrategy() + ", oracle=" + mode);
        }
        return signals;
    }

    private boolean allExecutionsLookLikeClientValidationErrors(List<ProbeExecution> executions) {
        for (ProbeExecution execution : executions) {
            String responseText = text(execution.getResponseBytes());
            if (!looksLikeClientValidationError(responseText)) {
                return false;
            }
        }
        return true;
    }

    private boolean trueFalseOnlyReflectDifferentPayloads(List<ProbeExecution> executions) {
        ProbeExecution trueCase = executions.stream()
                .filter(execution -> execution.getRole() == ProbeRole.TRUE_CASE)
                .findFirst()
                .orElse(null);
        ProbeExecution falseCase = executions.stream()
                .filter(execution -> execution.getRole() == ProbeRole.FALSE_CASE)
                .findFirst()
                .orElse(null);
        if (trueCase == null || falseCase == null) {
            return false;
        }
        String normalizedTrue = normalizeResponseForReview(text(trueCase.getResponseBytes()), trueCase.getValue());
        String normalizedFalse = normalizeResponseForReview(text(falseCase.getResponseBytes()), falseCase.getValue());
        return !normalizedTrue.isBlank() && normalizedTrue.equals(normalizedFalse);
    }

    private boolean looksLikeClientValidationError(String responseText) {
        if (responseText == null || responseText.isBlank()) {
            return false;
        }
        String lower = responseText.toLowerCase();
        int status = parseStatusCode(responseText);
        boolean validationStatus = status == 400 || status == 422;
        boolean validationLanguage = lower.contains("valid")
                || lower.contains("invalid")
                || lower.contains("parse")
                || lower.contains("parsing")
                || lower.contains("type")
                || lower.contains("schema")
                || lower.contains("deserialize")
                || lower.contains("malformed")
                || lower.contains("required")
                || lower.contains("format")
                || lower.contains("convert");
        boolean validationShape = lower.contains("\"detail\"")
                || lower.contains("\"errors\"")
                || lower.contains("\"loc\"")
                || lower.contains("\"input\"");
        return validationStatus && (validationLanguage || validationShape);
    }

    private String normalizeResponseForReview(String responseText, String payloadValue) {
        if (responseText == null) {
            return "";
        }
        String normalized = responseText.replaceAll("(?i)date:.*?(\\r?\\n)", "date:<normalized>$1")
                .replaceAll("\"input\"\\s*:\\s*\"[^\"]*\"", "\"input\":\"<payload>\"")
                .replaceAll("\"value\"\\s*:\\s*\"[^\"]*\"", "\"value\":\"<payload>\"");
        if (payloadValue != null && !payloadValue.isBlank()) {
            normalized = normalized.replace(payloadValue, "<payload>");
        }
        return normalized.replaceAll("\\s+", " ").trim();
    }

    private int parseStatusCode(String responseText) {
        try {
            if (responseText.startsWith("HTTP/")) {
                String[] parts = responseText.split("\\s+", 3);
                if (parts.length > 1) {
                    return Integer.parseInt(parts[1]);
                }
            }
        } catch (Exception ignored) {
        }
        return 0;
    }

    private LlmDiffDecision judgeDiffWithLlm(ProbeDefinition probe,
                                             String mode,
                                             DiffResult diff,
                                             List<ProbeExecution> executions,
                                             boolean deterministicMatched,
                                             String deterministicReasoning) {
        if (aiProvider == null || !aiProvider.isAvailable()) {
            return LlmDiffDecision.unavailable("LLM 二次研判未执行：AI Provider 未配置或不可用。");
        }
        try {
            String response = aiProvider.analyzeDiff(buildDiffJudgePrompt(
                            probe, mode, diff, executions,
                            deterministicMatched, deterministicReasoning))
                    .get(LLM_DIFF_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            LlmDiffDecision decision = parseLlmDecision(response);
            if (decision.available) {
                return decision;
            }
            return LlmDiffDecision.unavailable("LLM 二次研判执行失败：返回内容不是可解析 JSON。原始返回："
                    + summarize(response, 300));
        } catch (Exception e) {
            log.warn("LLM diff judgment unavailable: {}", e.getMessage());
            return LlmDiffDecision.unavailable("LLM 二次研判执行失败：" + e.getClass().getSimpleName()
                    + ": " + e.getMessage());
        }
    }

    private String buildDiffJudgePrompt(ProbeDefinition probe,
                                        String mode,
                                        DiffResult diff,
                                        List<ProbeExecution> executions,
                                        boolean deterministicMatched,
                                        String deterministicReasoning) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("你是 HTTP PoC 证据复核助手。\n")
                .append("请只判断这些响应差异是否能支持 claimedAttackType，不要因为普通参数校验错误而确认漏洞。\n")
                .append("只返回 JSON：{\"matched\":true/false,\"confidence\":0.0-1.0,\"reasoning\":\"中文理由\"}\n\n")
                .append("claimedAttackType: ").append(probe.getAttackType()).append("\n")
                .append("probeId: ").append(probe.getId()).append("\n")
                .append("strategy: ").append(probe.getStrategy()).append("\n")
                .append("oracle: ").append(mode).append("\n")
                .append("localOracleMatched: ").append(deterministicMatched).append("\n")
                .append("localOracleReasoning: ").append(deterministicReasoning).append("\n\n")
                .append("positiveEvidence:\n");
        for (String signal : positiveEvidenceSignals(probe, mode, diff, deterministicMatched, deterministicReasoning)) {
            prompt.append("- ").append(signal).append("\n");
        }
        prompt.append("\nnegativeEvidence:\n");
        List<String> negatives = negativeEvidenceSignals(probe, executions);
        if (negatives.isEmpty()) {
            prompt.append("- none detected by local pre-review\n");
        } else {
            for (String signal : negatives) {
                prompt.append("- ").append(signal).append("\n");
            }
        }
        prompt.append("\ndiffFeatures:\n")
                .append("- similarity: ").append(String.format("%.3f", diff.getSimilarity())).append("\n")
                .append("- statusChanged: ").append(diff.isStatusChanged()).append(" ")
                .append(diff.getOriginalStatus()).append(" -> ").append(diff.getMutatedStatus()).append("\n")
                .append("- lengthChanged: ").append(diff.isLengthChanged()).append(" ")
                .append(diff.getOriginalLength()).append(" -> ").append(diff.getMutatedLength()).append("\n")
                .append("- structureChanged: ").append(diff.isStructureChanged()).append("\n")
                .append("- keywordChanged: ").append(diff.isKeywordChanged()).append("\n")
                .append("- changedPaths: ").append(limitList(diff.getChangedPaths(), 12)).append("\n")
                .append("- diffSummary: ").append(limitList(diff.getDiffSummary(), 12)).append("\n")
                .append("- diffSnippets: ").append(limitList(diff.getDiffSnippets(), 8)).append("\n\n")
                .append("executions:\n");
        for (ProbeExecution execution : executions) {
            String requestText = text(execution.getRequestBytes());
            String responseText = text(execution.getResponseBytes());
            prompt.append("- role=").append(execution.getRole())
                    .append(", value=").append(summarize(execution.getValue(), 120))
                    .append(", durationMs=").append(execution.getDurationMs())
                    .append("\n  request: ").append(summarize(firstLine(requestText), 240))
                    .append("\n  responseStatus: ").append(parseStatusCode(responseText))
                    .append("\n  responseSnippet: ").append(summarize(extractBodySnippet(responseText), 500))
                    .append("\n");
        }
        return prompt.toString();
    }

    @SuppressWarnings("unchecked")
    private LlmDiffDecision parseLlmDecision(String raw) {
        if (raw == null || raw.isBlank()) {
            return LlmDiffDecision.unavailable("LLM 未返回内容。");
        }
        Map<String, Object> map = JsonUtil.fromJsonSafe(extractJson(raw), Map.class);
        if (map == null) {
            return LlmDiffDecision.unavailable("LLM 返回内容无法解析为 JSON：" + summarize(raw, 300));
        }
        Object matchedValue = map.get("matched");
        Object confidenceValue = map.get("confidence");
        boolean matched = matchedValue instanceof Boolean bool
                ? bool
                : Boolean.parseBoolean(String.valueOf(matchedValue));
        double confidence = 0.0;
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
        String review = "LLM 二次研判：matched=" + matched
                + "，confidence=" + String.format("%.2f", Math.max(0.0, Math.min(1.0, confidence)))
                + "，reasoning=" + reasoning;
        return new LlmDiffDecision(true, matched,
                Math.max(0.0, Math.min(1.0, confidence)), reasoning, review);
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

    private String firstLine(String text) {
        if (text == null || text.isBlank()) {
            return "";
        }
        int lineEnd = text.indexOf('\n');
        return lineEnd >= 0 ? text.substring(0, lineEnd).trim() : text.trim();
    }

    private String extractBodySnippet(String responseText) {
        if (responseText == null || responseText.isBlank()) {
            return "";
        }
        int separator = responseText.indexOf("\r\n\r\n");
        int offset = 4;
        if (separator < 0) {
            separator = responseText.indexOf("\n\n");
            offset = 2;
        }
        String body = separator >= 0 && separator + offset < responseText.length()
                ? responseText.substring(separator + offset)
                : responseText;
        return body;
    }

    private String extractHeader(String responseText, String headerName) {
        if (responseText == null || responseText.isBlank()
                || headerName == null || headerName.isBlank()) {
            return "";
        }
        String normalizedName = headerName.trim().toLowerCase();
        String[] lines = responseText.split("\\r?\\n");
        for (String line : lines) {
            if (line.isBlank()) {
                break;
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            String name = line.substring(0, colon).trim().toLowerCase();
            if (normalizedName.equals(name)) {
                return line.substring(colon + 1).trim();
            }
        }
        return "";
    }

    private List<String> markersForExecution(ProbeDefinition probe, ProbeExecution execution) {
        List<String> markers = new ArrayList<>(probe.getOracle().getRequireMarkers());
        for (ProbePayload payload : probe.getPayloads()) {
            if (payload.getValue() != null && payload.getValue().equals(execution.getValue())) {
                markers.addAll(payload.getMarkers());
                if (markers.isEmpty() || probe.getOracle().isRequireExactPayload()) {
                    markers.add(payload.getValue());
                }
                break;
            }
        }
        if (markers.isEmpty()) {
            markers.add(execution.getValue());
        }
        return markers;
    }

    private DiffResult diff(byte[] original, byte[] mutated, long originalDurationMs, long mutatedDurationMs) {
        if (diffEngine != null) {
            return diffEngine.analyze(original, mutated, originalDurationMs, mutatedDurationMs);
        }
        DiffResult diff = new DiffResult();
        diff.setOriginalLength(original != null ? original.length : 0);
        diff.setMutatedLength(mutated != null ? mutated.length : 0);
        diff.setLengthChanged(diff.getOriginalLength() != diff.getMutatedLength());
        diff.setSimilarity(similarity(original, mutated));
        return diff;
    }

    private boolean containsLikelyHtmlReflection(String responseText, String payload) {
        if (payload == null) {
            return false;
        }
        return responseText.contains(payload)
                || (payload.contains("<") && responseText.contains("<") && responseText.contains(">"));
    }

    private boolean containsAny(String text, List<String> keywords) {
        for (String keyword : keywords) {
            if (text.contains(keyword.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private String text(byte[] bytes) {
        return bytes == null || bytes.length == 0 ? "" : new String(bytes, StandardCharsets.UTF_8);
    }

    private double similarity(byte[] left, byte[] right) {
        if (left == null && right == null) {
            return 1.0;
        }
        if (left == null || right == null) {
            return 0.0;
        }
        int maxLen = Math.max(left.length, right.length);
        if (maxLen == 0) {
            return 1.0;
        }
        int minLen = Math.min(left.length, right.length);
        int sampleLen = Math.min(minLen, 10000);
        int diffCount = Math.abs(left.length - right.length);
        for (int index = 0; index < sampleLen; index++) {
            if (left[index] != right[index]) {
                diffCount++;
            }
        }
        return Math.max(0.0, Math.min(1.0, 1.0 - (diffCount / (double) maxLen)));
    }

    private record LlmDiffDecision(boolean available,
                                   boolean matched,
                                   double confidence,
                                   String reasoning,
                                   String review) {
        static LlmDiffDecision unavailable(String review) {
            return new LlmDiffDecision(false, false, 0.0, "", review);
        }
    }
}
