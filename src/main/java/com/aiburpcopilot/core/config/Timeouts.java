package com.aiburpcopilot.core.config;

import com.aiburpcopilot.core.verification.safety.VerificationGuard;

public final class Timeouts {

    private static final long LLM_WAIT_PADDING_MS = 5000L;

    private Timeouts() {
    }

    public static long effectiveLlmWaitMs(IConfigService configService) {
        if (configService == null || configService.getConfig() == null) {
            return 65000L;
        }
        AppConfig config = configService.getConfig();
        long configured = Math.max(1000L, config.getAi().getTimeoutMs());
        long networkBound = Math.max(1000L, config.getLlm().getConnectTimeoutMs())
                + Math.max(1000L, config.getLlm().getReadTimeoutMs())
                + LLM_WAIT_PADDING_MS;
        return Math.max(configured, networkBound);
    }

    public static long effectiveStaticReviewWaitMs(IConfigService configService) {
        return Math.max(effectiveLlmWaitMs(configService), 20000L);
    }

    public static long effectiveVerificationRequestTimeoutMs(VerificationGuard guard) {
        int seconds = guard != null ? guard.getRequestTimeoutSeconds() : 5;
        return Math.max(1000L, seconds * 1000L);
    }

    public static long effectiveFindingReviewWaitMs(IConfigService configService) {
        return Math.max(effectiveLlmWaitMs(configService), 90000L);
    }

    public static long effectiveInfluenceReviewWaitMs(IConfigService configService) {
        return Math.max(effectiveLlmWaitMs(configService), 45000L);
    }

    public static long effectiveParameterRoleWaitMs(IConfigService configService) {
        return Math.max(effectiveLlmWaitMs(configService), 30000L);
    }

    public static long effectiveProbeDiffReviewWaitMs(IConfigService configService) {
        return Math.max(effectiveLlmWaitMs(configService), 20000L);
    }
}
