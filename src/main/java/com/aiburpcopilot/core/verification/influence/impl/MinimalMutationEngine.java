package com.aiburpcopilot.core.verification.influence.impl;

import com.aiburpcopilot.core.verification.influence.IMinimalMutationEngine;
import com.aiburpcopilot.core.verification.model.ParameterProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * 最小变异引擎实现。
 * 只产生最小的参数变化，禁止生成漏洞 payload。
 */
public class MinimalMutationEngine implements IMinimalMutationEngine {

    private static final Logger log = LoggerFactory.getLogger(MinimalMutationEngine.class);

    @Override
    public List<String> generateMutations(ParameterProfile profile) {
        List<String> mutations = new ArrayList<>();
        if (profile == null || profile.getDetectedType() == null) return mutations;

        String value = profile.getOriginalValue();

        switch (profile.getDetectedType()) {
            case ParameterProfile.TYPE_NUMERIC -> {
                if (value != null) {
                    try {
                        long num = Long.parseLong(value.trim());
                        mutations.add(String.valueOf(num + 1));
                        mutations.add(String.valueOf(num - 1));
                        if (num != 0) mutations.add("0");
                    } catch (NumberFormatException e) {
                        mutations.add("0");
                        mutations.add("1");
                    }
                }
            }
            case ParameterProfile.TYPE_BOOLEAN -> {
                if ("true".equalsIgnoreCase(value)) {
                    mutations.add("false");
                    mutations.add("0");
                } else if ("false".equalsIgnoreCase(value)) {
                    mutations.add("true");
                    mutations.add("1");
                }
            }
            case ParameterProfile.TYPE_UUID -> {
                if (value != null && value.length() >= 36) {
                    String changed = value.substring(0, value.length() - 1) +
                            (value.charAt(value.length() - 1) == '0' ? '1' : '0');
                    mutations.add(changed);
                }
                mutations.add("00000000-0000-0000-0000-000000000000");
            }
            case ParameterProfile.TYPE_BASE64 -> {
                if (value != null && value.length() > 1) {
                    mutations.add(value.substring(0, value.length() - 1) + "A");
                }
            }
            case ParameterProfile.TYPE_EMAIL -> {
                if (value != null && value.contains("@")) {
                    String before = value.substring(0, value.indexOf('@'));
                    String after = value.substring(value.indexOf('@'));
                    mutations.add(before + "X" + after);
                    mutations.add("test@example.com");
                }
            }
            case ParameterProfile.TYPE_URL -> {
                if (value != null) {
                    mutations.add(value.replaceFirst("https?://[^/]+", "http://127.0.0.1"));
                    mutations.add(value.replaceFirst("https?://", "http://"));
                }
            }
            case ParameterProfile.TYPE_JSON -> {
                mutations.add("{}");
                mutations.add("[]");
            }
            case ParameterProfile.TYPE_STRING -> {
                if (value != null) {
                    mutations.add(value + "X");
                    mutations.add("");
                    mutations.add("0");
                }
            }
            case ParameterProfile.TYPE_JWT -> {
                // JWT is not mutable, return empty
            }
        }

        // Always add empty string and null-like values for testing
        if (!mutations.contains("")) {
            mutations.add("");
        }

        log.debug("Generated {} minimal mutations for param '{}' (type={})",
                mutations.size(), profile.getParameterName(), profile.getDetectedType());
        return mutations;
    }

    @Override
    public String generateMutation(ParameterProfile profile, String mutationType) {
        if (profile == null || mutationType == null) return "";

        String value = profile.getOriginalValue();
        String type = mutationType.toUpperCase();

        return switch (type) {
            case "INCREMENT" -> {
                if (value != null && profile.getDetectedType().equals(ParameterProfile.TYPE_NUMERIC)) {
                    try { yield String.valueOf(Long.parseLong(value.trim()) + 1); }
                    catch (NumberFormatException e) { yield value + "1"; }
                }
                yield value != null ? value + "1" : "1";
            }
            case "DECREMENT" -> {
                if (value != null && profile.getDetectedType().equals(ParameterProfile.TYPE_NUMERIC)) {
                    try { yield String.valueOf(Long.parseLong(value.trim()) - 1); }
                    catch (NumberFormatException e) { yield value; }
                }
                yield value != null ? value : "";
            }
            case "NULL" -> "0";
            case "EMPTY" -> "";
            case "FLIP" -> {
                if ("true".equalsIgnoreCase(value)) yield "false";
                if ("false".equalsIgnoreCase(value)) yield "true";
                if ("1".equals(value)) yield "0";
                yield "1";
            }
            default -> value != null ? value : "";
        };
    }
}
