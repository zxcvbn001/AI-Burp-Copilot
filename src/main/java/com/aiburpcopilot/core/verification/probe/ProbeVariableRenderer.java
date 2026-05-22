package com.aiburpcopilot.core.verification.probe;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ProbeVariableRenderer {

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{\\s*([A-Za-z][A-Za-z0-9_]*)(?::([^{}\\s:]+))?(?::(\\d{1,3}))?\\s*}}");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int DEFAULT_LENGTH = 8;
    private static final int MAX_LENGTH = 64;
    private static final char[] LOWER = "abcdefghijklmnopqrstuvwxyz".toCharArray();
    private static final char[] ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
    private static final char[] ALPHANUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();
    private static final char[] NUMERIC = "0123456789".toCharArray();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private final Map<String, String> values = new LinkedHashMap<>();

    public String render(String value) {
        if (value == null || value.isBlank() || !value.contains("{{")) {
            return value;
        }
        Matcher matcher = PLACEHOLDER.matcher(value);
        StringBuffer rendered = new StringBuffer();
        while (matcher.find()) {
            String replacement = valueFor(matcher.group(0), matcher.group(1), matcher.group(2), matcher.group(3));
            matcher.appendReplacement(rendered, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(rendered);
        return rendered.toString();
    }

    public List<String> renderList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return new ArrayList<>();
        }
        return values.stream()
                .map(this::render)
                .toList();
    }

    public ProbeDefinition renderProbe(ProbeDefinition source) {
        if (source == null) {
            return null;
        }
        ProbeDefinition rendered = new ProbeDefinition();
        rendered.setAttackType(source.getAttackType());
        rendered.setAttackTypeName(source.getAttackTypeName());
        rendered.setId(source.getId());
        rendered.setTechnique(source.getTechnique());
        rendered.setStrategyName(source.getStrategyName());
        rendered.setEnabledByDefault(source.isEnabledByDefault());
        rendered.setPriority(source.getPriority());
        rendered.setStopOnMatch(source.isStopOnMatch());
        rendered.setMaxRequests(source.getMaxRequests());
        rendered.setMaxPayloadLength(source.getMaxPayloadLength());
        rendered.setEvidenceWeight(source.getEvidenceWeight());
        rendered.setStrength(source.getStrength());
        rendered.setApplicableParamTypes(source.getApplicableParamTypes());
        rendered.setValueTypes(source.getValueTypes());
        rendered.setHttpMethods(source.getHttpMethods());
        rendered.setRequiresLlmReview(source.isRequiresLlmReview());

        List<ProbePayload> payloads = new ArrayList<>();
        for (ProbePayload payload : source.getPayloads()) {
            if (payload == null) {
                continue;
            }
            ProbePayload renderedPayload = new ProbePayload();
            renderedPayload.setValue(render(payload.getValue()));
            renderedPayload.setRole(payload.getRole());
            renderedPayload.setMutation(payload.getMutation());
            renderedPayload.setMarkers(renderList(payload.getMarkers()));
            payloads.add(renderedPayload);
        }
        rendered.setPayloads(payloads);

        List<ProbePayloadPair> payloadPairs = new ArrayList<>();
        for (ProbePayloadPair pair : source.getPayloadPairs()) {
            if (pair == null) {
                continue;
            }
            ProbePayloadPair renderedPair = new ProbePayloadPair();
            renderedPair.setTrueValue(render(pair.getTrueValue()));
            renderedPair.setFalseValue(render(pair.getFalseValue()));
            renderedPair.setTrueMutation(pair.getTrueMutation());
            renderedPair.setFalseMutation(pair.getFalseMutation());
            payloadPairs.add(renderedPair);
        }
        rendered.setPayloadPairs(payloadPairs);
        rendered.setOracle(renderOracle(source.getOracle()));
        return rendered;
    }

    private OracleDefinition renderOracle(OracleDefinition source) {
        OracleDefinition rendered = new OracleDefinition();
        if (source == null) {
            return rendered;
        }
        rendered.setType(source.getType());
        rendered.setKeywords(renderList(source.getKeywords()));
        rendered.setErrorKeywords(renderList(source.getErrorKeywords()));
        rendered.setRequireMarkers(renderList(source.getRequireMarkers()));
        rendered.setRequireExactPayload(source.isRequireExactPayload());
        rendered.setRequireUnescaped(source.isRequireUnescaped());
        rendered.setRecoveryPayloadIndex(source.getRecoveryPayloadIndex());
        rendered.setMinDelayMs(source.getMinDelayMs());
        rendered.setBaselineMultiplier(source.getBaselineMultiplier());
        rendered.setMinSimilarityTrueBaseline(source.getMinSimilarityTrueBaseline());
        rendered.setMaxSimilarityTrueFalse(source.getMaxSimilarityTrueFalse());
        rendered.setMinConfidence(source.getMinConfidence());
        return rendered;
    }

    private String valueFor(String token, String type, String name, String lengthValue) {
        String normalizedType = type != null ? type.trim().toLowerCase() : "rand";
        String effectiveLength = lengthValue;
        String normalizedName = name != null && !name.isBlank() ? name.trim() : null;
        if (effectiveLength == null && normalizedName != null && normalizedName.matches("\\d{1,3}")) {
            effectiveLength = normalizedName;
            normalizedName = null;
        }
        String key = normalizedName != null
                ? normalizedType + ":" + normalizedName
                : token;
        String finalEffectiveLength = effectiveLength;
        if ("arithleft".equals(normalizedType)) {
            return arithmeticValue(normalizedType, token, key, 0);
        }
        if ("arithright".equals(normalizedType)) {
            return arithmeticValue(normalizedType, token, key, 1);
        }
        if ("arithresult".equals(normalizedType)) {
            return arithmeticResult(normalizedType, token, key);
        }
        return values.computeIfAbsent(key, variableKey ->
                generate(token, variableKey, normalizedType, parseLength(finalEffectiveLength)));
    }

    private String generate(String token, String variableKey, String type, int length) {
        return switch (type) {
            case "uuid" -> UUID.randomUUID().toString();
            case "timestamp", "epoch" -> String.valueOf(Instant.now().toEpochMilli());
            case "randlower", "lower" -> randomChars(LOWER, length);
            case "randalpha", "alpha" -> randomChars(ALPHA, length);
            case "randnum", "num", "numeric", "number" -> randomChars(NUMERIC, length);
            case "randhex", "hex" -> randomChars(HEX, length);
            case "rand", "random", "randalnum", "alnum" -> randomChars(ALPHANUM, length);
            default -> token;
        };
    }

    private String arithmeticValue(String type, String token, String variableKey, int index) {
        String baseKey = arithmeticBaseKey(type, token, variableKey);
        String key = baseKey + ":value:" + index;
        return values.computeIfAbsent(key, ignored -> String.valueOf(2 + RANDOM.nextInt(7)));
    }

    private String arithmeticResult(String type, String token, String variableKey) {
        String baseKey = arithmeticBaseKey(type, token, variableKey);
        String key = baseKey + ":result";
        return values.computeIfAbsent(key, ignored -> {
            int left = Integer.parseInt(values.computeIfAbsent(baseKey + ":value:0",
                    valueKey -> String.valueOf(2 + RANDOM.nextInt(7))));
            int right = Integer.parseInt(values.computeIfAbsent(baseKey + ":value:1",
                    valueKey -> String.valueOf(2 + RANDOM.nextInt(7))));
            return String.valueOf(left * right);
        });
    }

    private String arithmeticBaseKey(String type, String token, String variableKey) {
        String prefix = variableKey != null ? variableKey : "";
        for (String suffix : List.of("arithleft", "arithright", "arithresult")) {
            if (prefix.startsWith(suffix + ":")) {
                return "arith:" + prefix.substring(suffix.length() + 1);
            }
        }
        return "arith:" + token;
    }

    private int parseLength(String lengthValue) {
        if (lengthValue == null || lengthValue.isBlank()) {
            return DEFAULT_LENGTH;
        }
        try {
            int parsed = Integer.parseInt(lengthValue.trim());
            return Math.max(1, Math.min(MAX_LENGTH, parsed));
        } catch (NumberFormatException ignored) {
            return DEFAULT_LENGTH;
        }
    }

    private String randomChars(char[] alphabet, int length) {
        StringBuilder value = new StringBuilder(length);
        for (int index = 0; index < length; index++) {
            value.append(alphabet[RANDOM.nextInt(alphabet.length)]);
        }
        return value.toString();
    }
}
