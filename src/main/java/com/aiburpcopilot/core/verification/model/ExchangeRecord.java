package com.aiburpcopilot.core.verification.model;

import com.aiburpcopilot.core.verification.probe.ProbeRole;

public class ExchangeRecord {

    private String exchangeKey;
    private String sourceStep;
    private String probeId;
    private ProbeRole role;
    private String payload;
    private boolean matched;
    private String evidenceType;
    private double confidence;
    private String description;
    private String diffDescription;
    private byte[] requestBytes;
    private byte[] responseBytes;
    private byte[] baselineRequestBytes;
    private byte[] baselineResponseBytes;

    public String getExchangeKey() { return exchangeKey; }
    public void setExchangeKey(String exchangeKey) { this.exchangeKey = exchangeKey; }

    public String getSourceStep() { return sourceStep; }
    public void setSourceStep(String sourceStep) { this.sourceStep = sourceStep; }

    public String getProbeId() { return probeId; }
    public void setProbeId(String probeId) { this.probeId = probeId; }

    public ProbeRole getRole() { return role; }
    public void setRole(ProbeRole role) { this.role = role; }

    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }

    public boolean isMatched() { return matched; }
    public void setMatched(boolean matched) { this.matched = matched; }

    public String getEvidenceType() { return evidenceType; }
    public void setEvidenceType(String evidenceType) { this.evidenceType = evidenceType; }

    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getDiffDescription() { return diffDescription; }
    public void setDiffDescription(String diffDescription) { this.diffDescription = diffDescription; }

    public byte[] getRequestBytes() { return requestBytes; }
    public void setRequestBytes(byte[] requestBytes) { this.requestBytes = requestBytes; }

    public byte[] getResponseBytes() { return responseBytes; }
    public void setResponseBytes(byte[] responseBytes) { this.responseBytes = responseBytes; }

    public byte[] getBaselineRequestBytes() { return baselineRequestBytes; }
    public void setBaselineRequestBytes(byte[] baselineRequestBytes) { this.baselineRequestBytes = baselineRequestBytes; }

    public byte[] getBaselineResponseBytes() { return baselineResponseBytes; }
    public void setBaselineResponseBytes(byte[] baselineResponseBytes) { this.baselineResponseBytes = baselineResponseBytes; }
}
