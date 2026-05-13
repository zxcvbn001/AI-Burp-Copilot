package com.aiburpcopilot.core.verification.probe;

import java.util.ArrayList;
import java.util.List;

public class OracleDefinition {

    private String type;
    private List<String> keywords = new ArrayList<>();
    private List<String> errorKeywords = new ArrayList<>();
    private List<String> requireMarkers = new ArrayList<>();
    private boolean requireExactPayload;
    private boolean requireUnescaped;
    private int recoveryPayloadIndex = -1;
    private long minDelayMs = 2500;
    private double baselineMultiplier = 2.5;
    private double minSimilarityTrueBaseline = 0.90;
    private double maxSimilarityTrueFalse = 0.80;
    private double minConfidence = 0.7;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public List<String> getKeywords() {
        return keywords;
    }

    public void setKeywords(List<String> keywords) {
        this.keywords = keywords != null ? keywords : new ArrayList<>();
    }

    public List<String> getErrorKeywords() {
        return errorKeywords;
    }

    public void setErrorKeywords(List<String> errorKeywords) {
        this.errorKeywords = errorKeywords != null ? errorKeywords : new ArrayList<>();
    }

    public List<String> getRequireMarkers() {
        return requireMarkers;
    }

    public void setRequireMarkers(List<String> requireMarkers) {
        this.requireMarkers = requireMarkers != null ? requireMarkers : new ArrayList<>();
    }

    public boolean isRequireExactPayload() {
        return requireExactPayload;
    }

    public void setRequireExactPayload(boolean requireExactPayload) {
        this.requireExactPayload = requireExactPayload;
    }

    public boolean isRequireUnescaped() {
        return requireUnescaped;
    }

    public void setRequireUnescaped(boolean requireUnescaped) {
        this.requireUnescaped = requireUnescaped;
    }

    public int getRecoveryPayloadIndex() {
        return recoveryPayloadIndex;
    }

    public void setRecoveryPayloadIndex(int recoveryPayloadIndex) {
        this.recoveryPayloadIndex = recoveryPayloadIndex;
    }

    public long getMinDelayMs() {
        return minDelayMs;
    }

    public void setMinDelayMs(long minDelayMs) {
        this.minDelayMs = minDelayMs;
    }

    public double getBaselineMultiplier() {
        return baselineMultiplier;
    }

    public void setBaselineMultiplier(double baselineMultiplier) {
        this.baselineMultiplier = baselineMultiplier;
    }

    public double getMinSimilarityTrueBaseline() {
        return minSimilarityTrueBaseline;
    }

    public void setMinSimilarityTrueBaseline(double minSimilarityTrueBaseline) {
        this.minSimilarityTrueBaseline = minSimilarityTrueBaseline;
    }

    public double getMaxSimilarityTrueFalse() {
        return maxSimilarityTrueFalse;
    }

    public void setMaxSimilarityTrueFalse(double maxSimilarityTrueFalse) {
        this.maxSimilarityTrueFalse = maxSimilarityTrueFalse;
    }

    public double getMinConfidence() {
        return minConfidence;
    }

    public void setMinConfidence(double minConfidence) {
        this.minConfidence = Math.max(0.0, Math.min(1.0, minConfidence));
    }
}
