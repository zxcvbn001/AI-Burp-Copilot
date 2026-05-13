package com.aiburpcopilot.core.verification.influence.impl;

import com.aiburpcopilot.core.verification.influence.IInfluenceScorer;
import com.aiburpcopilot.core.verification.model.DiffResult;

public class InfluenceScorer implements IInfluenceScorer {

    private static final double W_STATUS = 0.30;
    private static final double W_LENGTH = 0.05;
    private static final double W_STRUCTURE = 0.25;
    private static final double W_STABLE_PATHS = 0.25;
    private static final double W_KEYWORD = 0.10;
    private static final double W_TIMING = 0.05;

    @Override
    public double score(DiffResult diffResult) {
        if (diffResult == null) return 0.0;

        boolean hasStableSignal = diffResult.isStatusChanged()
                || diffResult.isStructureChanged()
                || diffResult.isKeywordChanged()
                || diffResult.getStableChangeCount() > 0;
        if (!hasStableSignal) {
            return 0.0;
        }

        double score = 0.0;
        if (diffResult.isStatusChanged()) score += W_STATUS;
        if (diffResult.isStructureChanged()) score += W_STRUCTURE;
        if (diffResult.getStableChangeCount() > 0) {
            score += Math.min(W_STABLE_PATHS, diffResult.getStableChangeCount() * 0.06);
        }
        if (diffResult.isLengthChanged()) score += W_LENGTH;
        if (diffResult.isKeywordChanged()) score += W_KEYWORD;
        if (diffResult.getResponseTimeDiff() > 0) score += W_TIMING * 0.5;
        if (diffResult.getResponseTimeDiff() > 500) score += W_TIMING * 0.5;
        return Math.min(1.0, score);
    }

    @Override
    public double scoreMultiple(DiffResult... diffResults) {
        if (diffResults == null || diffResults.length == 0) return 0.0;
        double sum = 0.0;
        for (DiffResult dr : diffResults) sum += score(dr);
        return sum / diffResults.length;
    }

    @Override
    public String scoreDetails(DiffResult diffResult) {
        if (diffResult == null) return "No diff result";
        StringBuilder sb = new StringBuilder();
        sb.append("Influence Score Breakdown:\n");
        sb.append(String.format("  Status (%.0f%%):  %s\n", W_STATUS * 100, diffResult.isStatusChanged() ? "CHANGED" : "same"));
        sb.append(String.format("  Length (%.0f%%):  %s\n", W_LENGTH * 100, diffResult.isLengthChanged() ? "CHANGED" : "same"));
        sb.append(String.format("  Structure (%.0f%%): %s\n", W_STRUCTURE * 100, diffResult.isStructureChanged() ? "CHANGED" : "same"));
        sb.append(String.format("  Stable Paths (%.0f%%): %d %s\n",
                W_STABLE_PATHS * 100,
                diffResult.getStableChangeCount(),
                diffResult.getChangedPaths()));
        sb.append("  Noise Paths: ").append(diffResult.getNoiseChangeCount())
                .append(" ").append(diffResult.getNoisePaths()).append("\n");
        sb.append(String.format("  Keyword (%.0f%%): %s\n", W_KEYWORD * 100, diffResult.isKeywordChanged() ? "CHANGED" : "same"));
        sb.append(String.format("  Timing (%.0f%%):  %dms\n", W_TIMING * 100, diffResult.getResponseTimeDiff()));
        sb.append(String.format("  Total Score: %.3f", score(diffResult)));
        return sb.toString();
    }
}
