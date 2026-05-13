package com.aiburpcopilot.core.verification.model;

/**
 * 验证证据。
 * <p>
 * 保存一次验证操作的关键证据，包括请求/响应快照、Diff 摘要等。
 * 证据是不可变的，创建后不可修改。
 */
public class Evidence {

    /** 证据描述 */
    private String description;

    /** 原始请求字节（快照） */
    private byte[] request;

    /** 变异后请求字节（快照） */
    private byte[] mutatedRequest;

    /** 原始响应字节（快照） */
    private byte[] originalResponse;

    /** 变异后响应字节（快照） */
    private byte[] mutatedResponse;

    /** Diff 差异描述 */
    private String diffDescription;

    /** 证据置信度 */
    private double confidence;

    /** 证据类型 */
    private String evidenceType;

    /** 收集时间戳 */
    private long timestamp;

    /** 关联的步骤名 */
    private String sourceStep;

    public Evidence() {
        this.timestamp = System.currentTimeMillis();
        this.confidence = 0.0;
    }

    public Evidence(String description, String evidenceType, double confidence) {
        this();
        this.description = description;
        this.evidenceType = evidenceType;
        this.confidence = confidence;
    }

    /**
     * 创建状态码差异证据。
     */
    public static Evidence statusChanged(String original, String mutated) {
        Evidence e = new Evidence(
                "Status changed: " + original + " -> " + mutated,
                "STATUS_CHANGE", 0.9);
        e.diffDescription = "HTTP status code changed from " + original + " to " + mutated;
        return e;
    }

    /**
     * 创建长度差异证据。
     */
    public static Evidence lengthChanged(int originalLen, int mutatedLen) {
        Evidence e = new Evidence(
                "Response length changed: " + originalLen + " -> " + mutatedLen + " bytes",
                "LENGTH_CHANGE", 0.7);
        e.diffDescription = "Response body length changed by "
                + Math.abs(mutatedLen - originalLen) + " bytes";
        return e;
    }

    /**
     * 创建结构差异证据。
     */
    public static Evidence structureChanged(String detail) {
        Evidence e = new Evidence(
                "JSON structure changed: " + detail,
                "STRUCTURE_CHANGE", 0.75);
        e.diffDescription = detail;
        return e;
    }

    /**
     * 创建关键词匹配证据。
     */
    public static Evidence keywordMatched(String keyword, String context) {
        Evidence e = new Evidence(
                "Keyword matched: '" + keyword + "' in " + context,
                "KEYWORD_MATCH", 0.8);
        e.diffDescription = "Found '" + keyword + "' in " + context;
        return e;
    }

    /**
     * 创建时间差异证据。
     */
    public static Evidence timingChanged(long diffMs) {
        Evidence e = new Evidence(
                "Response time: " + diffMs + "ms",
                "TIMING_CHANGE", 0.5);
        e.diffDescription = "Response time difference: " + diffMs + "ms";
        return e;
    }

    /**
     * 创建通用验证证据。
     */
    public static Evidence general(String description, String type, double confidence) {
        return new Evidence(description, type, confidence);
    }

    // ---------- Getters & Setters ----------

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public byte[] getRequest() { return request; }
    public void setRequest(byte[] request) { this.request = request; }

    public byte[] getMutatedRequest() { return mutatedRequest; }
    public void setMutatedRequest(byte[] mutatedRequest) { this.mutatedRequest = mutatedRequest; }

    public byte[] getOriginalResponse() { return originalResponse; }
    public void setOriginalResponse(byte[] originalResponse) { this.originalResponse = originalResponse; }

    public byte[] getMutatedResponse() { return mutatedResponse; }
    public void setMutatedResponse(byte[] mutatedResponse) { this.mutatedResponse = mutatedResponse; }

    public String getDiffDescription() { return diffDescription; }
    public void setDiffDescription(String diffDescription) { this.diffDescription = diffDescription; }

    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = Math.max(0.0, Math.min(1.0, confidence)); }

    public String getEvidenceType() { return evidenceType; }
    public void setEvidenceType(String evidenceType) { this.evidenceType = evidenceType; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    public String getSourceStep() { return sourceStep; }
    public void setSourceStep(String sourceStep) { this.sourceStep = sourceStep; }

    @Override
    public String toString() {
        return "Evidence{" +
                "type='" + evidenceType + '\'' +
                ", confidence=" + confidence +
                ", description='" + description + '\'' +
                '}';
    }
}
