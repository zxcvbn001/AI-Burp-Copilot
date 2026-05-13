package com.aiburpcopilot.core.verification.influence;

public record InfluenceLlmDecision(boolean available,
                                   boolean influential,
                                   double confidence,
                                   String reasoning) {

    public static InfluenceLlmDecision unavailable() {
        return new InfluenceLlmDecision(false, false, 0.0, "");
    }
}
