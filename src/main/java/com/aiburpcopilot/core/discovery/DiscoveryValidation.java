package com.aiburpcopilot.core.discovery;

import java.util.ArrayList;
import java.util.List;

public class DiscoveryValidation {

    private DiscoveryValidationStatus status = DiscoveryValidationStatus.NOT_RUN;
    private DiscoveryJudgment judgment = DiscoveryJudgment.UNVALIDATED;
    private String reasoning;
    private int finalStatusCode;
    private String contentType;
    private long validatedAt;
    private List<DiscoveryAttempt> attempts = new ArrayList<>();

    public DiscoveryValidationStatus getStatus() {
        return status;
    }

    public void setStatus(DiscoveryValidationStatus status) {
        this.status = status;
    }

    public DiscoveryJudgment getJudgment() {
        return judgment;
    }

    public void setJudgment(DiscoveryJudgment judgment) {
        this.judgment = judgment;
    }

    public String getReasoning() {
        return reasoning;
    }

    public void setReasoning(String reasoning) {
        this.reasoning = reasoning;
    }

    public int getFinalStatusCode() {
        return finalStatusCode;
    }

    public void setFinalStatusCode(int finalStatusCode) {
        this.finalStatusCode = finalStatusCode;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public long getValidatedAt() {
        return validatedAt;
    }

    public void setValidatedAt(long validatedAt) {
        this.validatedAt = validatedAt;
    }

    public List<DiscoveryAttempt> getAttempts() {
        return attempts;
    }

    public void setAttempts(List<DiscoveryAttempt> attempts) {
        this.attempts = attempts != null ? attempts : new ArrayList<>();
    }

    public DiscoveryValidation copy() {
        DiscoveryValidation copy = new DiscoveryValidation();
        copy.setStatus(status);
        copy.setJudgment(judgment);
        copy.setReasoning(reasoning);
        copy.setFinalStatusCode(finalStatusCode);
        copy.setContentType(contentType);
        copy.setValidatedAt(validatedAt);
        List<DiscoveryAttempt> copiedAttempts = new ArrayList<>();
        for (DiscoveryAttempt attempt : attempts) {
            copiedAttempts.add(attempt != null ? attempt.copy() : null);
        }
        copy.setAttempts(copiedAttempts);
        return copy;
    }
}
