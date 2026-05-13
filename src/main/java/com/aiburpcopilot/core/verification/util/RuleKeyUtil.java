package com.aiburpcopilot.core.verification.util;

import com.aiburpcopilot.core.context.AttackType;

import java.util.Optional;

public final class RuleKeyUtil {

    private RuleKeyUtil() {
    }

    public static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim()
                .replace('-', '_')
                .replace(' ', '_')
                .replace('/', '_')
                .toUpperCase()
                .replaceAll("_+", "_")
                .replaceAll("^_|_$", "");
        return normalized.isBlank() ? null : normalized;
    }

    public static Optional<AttackType> toAttackType(String value) {
        String normalized = normalize(value);
        if (normalized == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(AttackType.valueOf(normalized));
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
    }

    public static String attackTypeName(AttackType attackType) {
        return attackType != null ? attackType.name() : null;
    }
}
