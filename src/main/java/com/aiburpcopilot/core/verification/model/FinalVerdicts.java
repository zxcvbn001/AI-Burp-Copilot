package com.aiburpcopilot.core.verification.model;

public final class FinalVerdicts {

    public static final String CONFIRMED = "CONFIRMED";
    public static final String LOCAL_CONFIRMED = "LOCAL_CONFIRMED";
    public static final String MANUAL_CONFIRMED = "MANUAL_CONFIRMED";
    public static final String MANUAL_REJECTED = "MANUAL_REJECTED";
    public static final String REJECTED = "REJECTED";
    public static final String NO_EVIDENCE = "NO_EVIDENCE";
    public static final String BELOW_THRESHOLD = "BELOW_THRESHOLD";
    public static final String NO_MATCH = "NO_MATCH";
    public static final String ERROR = "ERROR";
    public static final String PENDING_REVIEW = "PENDING_REVIEW";

    private static final double DEFAULT_THRESHOLD = 0.55;
    private static final double EPSILON = 0.001;

    private FinalVerdicts() {
    }

    public static void recompute(VerificationResult result) {
        if (result == null) {
            return;
        }
        String decision = derive(result);
        result.setFinalDecision(decision);
        result.setConfirmedVulnerability(isEffectiveDecision(decision));
    }

    public static String derive(VerificationResult result) {
        if (result == null) {
            return NO_MATCH;
        }
        String existing = normalize(result.getFinalDecision());
        if (Boolean.TRUE.equals(result.getManualConfirmedOverride())) {
            return MANUAL_CONFIRMED;
        }
        if (Boolean.FALSE.equals(result.getManualConfirmedOverride())) {
            return MANUAL_REJECTED;
        }
        if (ERROR.equals(existing)) {
            return ERROR;
        }
        if (result.getReviewStatus() == ReviewStatus.REJECTED) {
            return REJECTED;
        }
        if (Boolean.FALSE.equals(result.getLlmMatched()) && isFindingScope(result)) {
            return REJECTED;
        }
        if (isFindingScope(result)) {
            if (!hasLocalEvidence(result)) {
                return NO_EVIDENCE;
            }
            if (!thresholdPassed(result)) {
                return BELOW_THRESHOLD;
            }
            if (result.getReviewStatus() == ReviewStatus.PASSED || Boolean.TRUE.equals(result.getLlmMatched())) {
                return CONFIRMED;
            }
            if (result.getReviewStatus() == ReviewStatus.RUNNING || result.getReviewStatus() == ReviewStatus.PENDING) {
                return LOCAL_CONFIRMED;
            }
            if (result.getReviewStatus() == ReviewStatus.LOCAL_ONLY
                    || result.getReviewStatus() == ReviewStatus.FAILED
                    || result.getReviewStatus() == ReviewStatus.NOT_REQUIRED
                    || result.getReviewStatus() == null) {
                return LOCAL_CONFIRMED;
            }
            return LOCAL_CONFIRMED;
        }
        if (existing != null) {
            return existing;
        }
        if (result.getRejectReason() != null && !result.getRejectReason().isBlank()) {
            return REJECTED;
        }
        return NO_MATCH;
    }

    public static boolean isEffective(VerificationResult result) {
        return result != null && isEffectiveDecision(derive(result));
    }

    public static boolean isEffectiveDecision(String decision) {
        String normalized = normalize(decision);
        return CONFIRMED.equals(normalized)
                || LOCAL_CONFIRMED.equals(normalized)
                || MANUAL_CONFIRMED.equals(normalized);
    }

    public static String normalize(String decision) {
        if (decision == null || decision.isBlank()) {
            return null;
        }
        return decision.trim().toUpperCase();
    }

    private static boolean thresholdPassed(VerificationResult result) {
        if (!isFindingScope(result)) {
            return false;
        }
        double threshold = result.getFindingThreshold() > 0 ? result.getFindingThreshold() : DEFAULT_THRESHOLD;
        return result.getFindingConfidenceRaw() + EPSILON >= threshold;
    }

    private static boolean hasLocalEvidence(VerificationResult result) {
        if (result.isLocalMatched()) {
            return true;
        }
        return result.getEvidences() != null && !result.getEvidences().isEmpty();
    }

    private static boolean isFindingScope(VerificationResult result) {
        if (result == null) {
            return false;
        }
        if (result.isFindingGenerated()) {
            return true;
        }
        if (result.getFindingConfidenceRaw() > 0 || result.getFindingThreshold() > 0) {
            return true;
        }
        return "Finding".equalsIgnoreCase(result.getPhase());
    }
}
