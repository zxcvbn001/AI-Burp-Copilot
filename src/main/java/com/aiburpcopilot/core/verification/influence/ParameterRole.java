package com.aiburpcopilot.core.verification.influence;

import java.util.List;

public record ParameterRole(
        boolean available,
        String role,
        boolean likelyBusinessRelevant,
        double confidence,
        List<String> recommendedMutations,
        String reasoning) {

    public static ParameterRole unavailable() {
        return new ParameterRole(false, "UNKNOWN", false, 0.0, List.of(), "Parameter role analysis unavailable");
    }

    public boolean strongBusinessSignal() {
        return available && likelyBusinessRelevant && confidence >= 0.60;
    }
}
