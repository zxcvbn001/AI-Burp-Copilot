package com.aiburpcopilot.core.verification.influence.impl;

import com.aiburpcopilot.core.verification.influence.IInfluenceDiffEngine;
import com.aiburpcopilot.core.verification.model.DiffResult;
import com.aiburpcopilot.utils.JsonUtil;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Generic response diff engine for influence validation.
 * It extracts stable response features first, filters dynamic noise, then scores
 * deterministic structural changes. LLM may consume diffSummary later, but it
 * must not decide whether a parameter is influential.
 */
public class InfluenceDiffEngine implements IInfluenceDiffEngine {

    private static final double LENGTH_CHANGE_THRESHOLD = 0.20;
    private static final double TIME_RATIO_THRESHOLD = 2.5;

    private static final Set<String> STRUCTURAL_KEYWORDS = Set.of(
            "error", "success", "unauthorized", "forbidden", "not found",
            "bad request", "access denied", "invalid", "failed", "ok"
    );

    private static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern ISO_TIME_PATTERN = Pattern.compile(
            "^\\d{4}-\\d{2}-\\d{2}[T ][0-9:.+-]+Z?$");
    private static final Pattern LONG_NUMBER_PATTERN = Pattern.compile("^\\d{10,}$");
    private static final Pattern HEX_TOKEN_PATTERN = Pattern.compile("^[0-9a-fA-F]{16,}$");
    private static final Pattern UUID_TOKEN_PATTERN = Pattern.compile(
            "\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b");
    private static final Pattern ISO_TIME_TOKEN_PATTERN = Pattern.compile(
            "\\b\\d{4}-\\d{2}-\\d{2}[T ][0-9:.+-]+Z?\\b");
    private static final Pattern LONG_NUMBER_TOKEN_PATTERN = Pattern.compile("\\b\\d{10,}\\b");
    private static final Pattern HEX_TOKEN_VALUE_PATTERN = Pattern.compile("\\b[0-9a-fA-F]{16,}\\b");

    @Override
    public DiffResult analyze(byte[] originalResponse, byte[] mutatedResponse,
                              long originalDurationMs, long mutatedDurationMs) {
        DiffResult result = new DiffResult();
        if (originalResponse == null || mutatedResponse == null) {
            result.setSimilarity(0.0);
            result.setStatusChanged(originalResponse != mutatedResponse);
            result.getDiffSummary().add("One response is missing");
            return result;
        }

        ParsedResponse original = parseResponse(originalResponse);
        ParsedResponse mutated = parseResponse(mutatedResponse);

        result.setOriginalStatus(original.statusCode);
        result.setMutatedStatus(mutated.statusCode);
        result.setOriginalLength(original.bodyBytes.length);
        result.setMutatedLength(mutated.bodyBytes.length);

        result.setStatusChanged(!original.statusCode.equals(mutated.statusCode));
        if (result.isStatusChanged()) {
            result.getChangedPaths().add("$status");
            result.getDiffSummary().add("HTTP status changed: "
                    + original.statusCode + " -> " + mutated.statusCode);
        }

        analyzeBody(original, mutated, result);
        extractTextDifferenceSnippets(original.bodyText, mutated.bodyText, result);
        analyzeKeywords(original.bodyText, mutated.bodyText, result);
        analyzeLength(original.bodyBytes.length, mutated.bodyBytes.length, result);
        analyzeTiming(originalDurationMs, mutatedDurationMs, result);

        result.setSimilarity(calculateSimilarity(result));
        return result;
    }

    private void analyzeBody(ParsedResponse original, ParsedResponse mutated, DiffResult result) {
        Map<String, String> originalFeatures = extractFeatures(original);
        Map<String, String> mutatedFeatures = extractFeatures(mutated);
        Set<String> paths = new LinkedHashSet<>();
        paths.addAll(originalFeatures.keySet());
        paths.addAll(mutatedFeatures.keySet());

        for (String path : paths) {
            String originalValue = originalFeatures.get(path);
            String mutatedValue = mutatedFeatures.get(path);
            if (safeEquals(originalValue, mutatedValue)) {
                continue;
            }
            if (isNoise(path, originalValue, mutatedValue)) {
                result.getNoisePaths().add(path);
                continue;
            }
            result.getChangedPaths().add(path);
            result.getDiffSummary().add(path + ": "
                    + summarizeValue(originalValue) + " -> " + summarizeValue(mutatedValue));
        }

        result.setStableChangeCount(result.getChangedPaths().size());
        result.setNoiseChangeCount(result.getNoisePaths().size());
        result.setStructureChanged(hasStructuralChange(originalFeatures, mutatedFeatures, result));
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> extractFeatures(ParsedResponse response) {
        String body = response.bodyText != null ? response.bodyText.trim() : "";
        if (body.isEmpty()) {
            return Map.of();
        }
        if (isJson(response)) {
            try {
                Object root = JsonUtil.getMapper().readValue(body, Object.class);
                Map<String, String> features = new LinkedHashMap<>();
                flattenJson("$", root, features);
                return features;
            } catch (Exception ignored) {
                return extractTextFeatures(body);
            }
        }
        return extractTextFeatures(body);
    }

    @SuppressWarnings("unchecked")
    private void flattenJson(String path, Object value, Map<String, String> features) {
        if (value instanceof Map<?, ?> map) {
            features.put(path + "#type", "object");
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                flattenJson(path + "." + entry.getKey(), entry.getValue(), features);
            }
        } else if (value instanceof List<?> list) {
            features.put(path + "#type", "array");
            features.put(path + "#size", String.valueOf(list.size()));
            int limit = Math.min(list.size(), 10);
            for (int index = 0; index < limit; index++) {
                flattenJson(path + "[" + index + "]", list.get(index), features);
            }
        } else {
            features.put(path, normalizeScalar(value));
        }
    }

    private Map<String, String> extractTextFeatures(String body) {
        Map<String, String> features = new LinkedHashMap<>();
        String normalized = normalizeDynamicText(body).replaceAll("\\s+", " ").trim();
        features.put("$text.hash", Integer.toHexString(normalized.hashCode()));
        features.put("$text.length", String.valueOf(normalized.length()));
        features.put("$text.prefix", normalized.substring(0, Math.min(160, normalized.length())));
        return features;
    }

    private boolean hasStructuralChange(Map<String, String> original,
                                        Map<String, String> mutated,
                                        DiffResult result) {
        for (String path : result.getChangedPaths()) {
            if ("$status".equals(path)) {
                continue;
            }
            if (path.endsWith("#type")
                    || path.endsWith("#size")
                    || !original.containsKey(path)
                    || !mutated.containsKey(path)) {
                return true;
            }
        }
        return false;
    }

    private void analyzeLength(int originalLength, int mutatedLength, DiffResult result) {
        if (originalLength == 0 && mutatedLength > 0) {
            result.setLengthChanged(true);
        } else if (originalLength > 0) {
            double ratio = Math.abs(mutatedLength - originalLength) / (double) originalLength;
            result.setLengthChanged(ratio > LENGTH_CHANGE_THRESHOLD && result.getStableChangeCount() > 0);
        }
        if (result.isLengthChanged()) {
            result.getDiffSummary().add("Body length changed: "
                    + originalLength + " -> " + mutatedLength);
        }
    }

    private void analyzeKeywords(String originalBody, String mutatedBody, DiffResult result) {
        String original = originalBody != null ? originalBody.toLowerCase() : "";
        String mutated = mutatedBody != null ? mutatedBody.toLowerCase() : "";
        for (String keyword : STRUCTURAL_KEYWORDS) {
            if (original.contains(keyword) != mutated.contains(keyword)) {
                result.setKeywordChanged(true);
                result.getMatchedKeywords().add(keyword);
            }
        }
        if (result.isKeywordChanged()) {
            result.getDiffSummary().add("Keyword changes: " + result.getMatchedKeywords());
        }
    }

    private void analyzeTiming(long originalDurationMs, long mutatedDurationMs, DiffResult result) {
        if (originalDurationMs <= 0 || mutatedDurationMs <= 0) {
            return;
        }
        long diff = mutatedDurationMs - originalDurationMs;
        if (diff > 500 && mutatedDurationMs / (double) originalDurationMs > TIME_RATIO_THRESHOLD) {
            result.setResponseTimeDiff(diff);
            result.getDiffSummary().add("Response time changed: "
                    + originalDurationMs + "ms -> " + mutatedDurationMs + "ms");
        }
    }

    private void extractTextDifferenceSnippets(String originalBody,
                                               String mutatedBody,
                                               DiffResult result) {
        if (originalBody == null || mutatedBody == null || originalBody.equals(mutatedBody)) {
            return;
        }
        int prefix = commonPrefixLength(originalBody, mutatedBody);
        int suffix = commonSuffixLength(originalBody, mutatedBody, prefix);
        int originalEnd = Math.max(prefix, originalBody.length() - suffix);
        int mutatedEnd = Math.max(prefix, mutatedBody.length() - suffix);
        String originalDiff = originalBody.substring(prefix, originalEnd);
        String mutatedDiff = mutatedBody.substring(prefix, mutatedEnd);
        if (originalDiff.isBlank() && mutatedDiff.isBlank()) {
            return;
        }
        int contextStart = Math.max(0, prefix - 60);
        int originalContextEnd = Math.min(originalBody.length(), originalEnd + 60);
        int mutatedContextEnd = Math.min(mutatedBody.length(), mutatedEnd + 60);
        result.getDiffSnippets().add("原始片段: "
                + summarizeValue(originalBody.substring(contextStart, originalContextEnd)));
        result.getDiffSnippets().add("变异片段: "
                + summarizeValue(mutatedBody.substring(contextStart, mutatedContextEnd)));
    }

    private int commonPrefixLength(String left, String right) {
        int max = Math.min(left.length(), right.length());
        int index = 0;
        while (index < max && left.charAt(index) == right.charAt(index)) {
            index++;
        }
        return index;
    }

    private int commonSuffixLength(String left, String right, int prefixLength) {
        int leftIndex = left.length() - 1;
        int rightIndex = right.length() - 1;
        int count = 0;
        while (leftIndex >= prefixLength
                && rightIndex >= prefixLength
                && left.charAt(leftIndex) == right.charAt(rightIndex)) {
            leftIndex--;
            rightIndex--;
            count++;
        }
        return count;
    }

    private boolean isNoise(String path, String original, String mutated) {
        String lowerPath = path.toLowerCase();
        if (lowerPath.contains("timestamp")
                || lowerPath.contains("time")
                || lowerPath.contains("date")
                || lowerPath.contains("nonce")
                || lowerPath.contains("csrf")
                || lowerPath.contains("token")
                || lowerPath.contains("trace")
                || lowerPath.contains("requestid")
                || lowerPath.contains("request_id")
                || lowerPath.contains("uuid")) {
            return true;
        }
        return isDynamicScalar(original) && isDynamicScalar(mutated);
    }

    private boolean isDynamicScalar(String value) {
        if (value == null) {
            return false;
        }
        String trimmed = value.trim();
        return UUID_PATTERN.matcher(trimmed).matches()
                || ISO_TIME_PATTERN.matcher(trimmed).matches()
                || LONG_NUMBER_PATTERN.matcher(trimmed).matches()
                || HEX_TOKEN_PATTERN.matcher(trimmed).matches();
    }

    private String normalizeScalar(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof Number || value instanceof Boolean) {
            return String.valueOf(value);
        }
        return String.valueOf(value).replaceAll("\\s+", " ").trim();
    }

    private String normalizeDynamicText(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        String normalized = UUID_TOKEN_PATTERN.matcher(value).replaceAll("<uuid>");
        normalized = ISO_TIME_TOKEN_PATTERN.matcher(normalized).replaceAll("<time>");
        normalized = LONG_NUMBER_TOKEN_PATTERN.matcher(normalized).replaceAll("<number>");
        normalized = HEX_TOKEN_VALUE_PATTERN.matcher(normalized).replaceAll("<token>");
        return normalized;
    }

    private String summarizeValue(String value) {
        if (value == null) {
            return "<missing>";
        }
        String normalized = value.replaceAll("\\s+", " ");
        return normalized.length() <= 80 ? normalized : normalized.substring(0, 77) + "...";
    }

    private double calculateSimilarity(DiffResult result) {
        double similarity = 1.0;
        if (result.isStatusChanged()) similarity -= 0.25;
        if (result.isStructureChanged()) similarity -= 0.25;
        if (result.isKeywordChanged()) similarity -= 0.15;
        if (result.isLengthChanged()) similarity -= 0.10;
        similarity -= Math.min(0.20, result.getStableChangeCount() * 0.04);
        similarity += Math.min(0.10, result.getNoiseChangeCount() * 0.01);
        if (result.getResponseTimeDiff() > 0) similarity -= 0.05;
        return Math.max(0.0, Math.min(1.0, similarity));
    }

    private boolean isJson(ParsedResponse response) {
        String contentType = header(response.headers, "content-type");
        if (contentType != null && contentType.toLowerCase().contains("json")) {
            return true;
        }
        String body = response.bodyText != null ? response.bodyText.trim() : "";
        return body.startsWith("{") || body.startsWith("[");
    }

    private String header(Map<String, String> headers, String name) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private ParsedResponse parseResponse(byte[] bytes) {
        ParsedResponse response = new ParsedResponse();
        if (bytes == null || bytes.length == 0) {
            return response;
        }

        String raw = new String(bytes, StandardCharsets.UTF_8);
        int separator = raw.indexOf("\r\n\r\n");
        if (separator < 0) separator = raw.indexOf("\n\n");

        String headerPart = separator >= 0 ? raw.substring(0, separator) : raw;
        int bodyOffset = 0;
        if (separator >= 0) {
            String separatorText = raw.startsWith("\r\n\r\n", separator) ? "\r\n\r\n" : "\n\n";
            bodyOffset = headerPart.getBytes(StandardCharsets.UTF_8).length
                    + separatorText.getBytes(StandardCharsets.UTF_8).length;
        }
        if (bodyOffset > 0 && bodyOffset <= bytes.length) {
            response.bodyBytes = new byte[bytes.length - bodyOffset];
            System.arraycopy(bytes, bodyOffset, response.bodyBytes, 0, response.bodyBytes.length);
        } else {
            response.bodyBytes = new byte[0];
        }
        response.bodyText = new String(response.bodyBytes, StandardCharsets.UTF_8);

        String[] lines = headerPart.split("\r\n|\n", -1);
        if (lines.length > 0) {
            String[] statusParts = lines[0].split(" ", 3);
            response.statusCode = statusParts.length > 1 ? statusParts[1] : "0";
        }
        for (int i = 1; i < lines.length; i++) {
            int colonIndex = lines[i].indexOf(':');
            if (colonIndex > 0) {
                response.headers.put(lines[i].substring(0, colonIndex).trim(),
                        lines[i].substring(colonIndex + 1).trim());
            }
        }
        return response;
    }

    private boolean safeEquals(String left, String right) {
        return left == null ? right == null : left.equals(right);
    }

    private static class ParsedResponse {
        String statusCode = "0";
        Map<String, String> headers = new LinkedHashMap<>();
        byte[] bodyBytes = new byte[0];
        String bodyText = "";
    }
}
