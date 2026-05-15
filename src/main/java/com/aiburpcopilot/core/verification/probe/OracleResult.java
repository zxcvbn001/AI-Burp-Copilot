package com.aiburpcopilot.core.verification.probe;

import com.aiburpcopilot.core.verification.model.DiffResult;
import com.aiburpcopilot.core.verification.model.Evidence;

import java.util.ArrayList;
import java.util.List;

public class OracleResult {

    private boolean matched;
    private boolean localMatched;
    private Boolean llmMatched;
    private double confidence;
    private String reasoning;
    private String llmReview;
    private boolean llmAvailable;
    private DiffResult diffResult;
    private final List<Evidence> evidences = new ArrayList<>();

    public boolean isMatched() {
        return matched;
    }

    public void setMatched(boolean matched) {
        this.matched = matched;
    }

    public boolean isLocalMatched() {
        return localMatched;
    }

    public void setLocalMatched(boolean localMatched) {
        this.localMatched = localMatched;
    }

    public Boolean getLlmMatched() {
        return llmMatched;
    }

    public void setLlmMatched(Boolean llmMatched) {
        this.llmMatched = llmMatched;
    }

    public double getConfidence() {
        return confidence;
    }

    public void setConfidence(double confidence) {
        this.confidence = Math.max(0.0, Math.min(1.0, confidence));
    }

    public String getReasoning() {
        return reasoning;
    }

    public void setReasoning(String reasoning) {
        this.reasoning = reasoning;
    }

    public String getLlmReview() {
        return llmReview;
    }

    public void setLlmReview(String llmReview) {
        this.llmReview = llmReview;
    }

    public boolean isLlmAvailable() {
        return llmAvailable;
    }

    public void setLlmAvailable(boolean llmAvailable) {
        this.llmAvailable = llmAvailable;
    }

    public DiffResult getDiffResult() {
        return diffResult;
    }

    public void setDiffResult(DiffResult diffResult) {
        this.diffResult = diffResult;
    }

    public List<Evidence> getEvidences() {
        return evidences;
    }

    public void addEvidence(Evidence evidence) {
        if (evidence != null) {
            evidences.add(evidence);
        }
    }
}
